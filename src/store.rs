//! The storage seam: one `ChartStore` trait, two honest backends.
//!
//! A FHIR resource is kept as its whole JSON payload, keyed by
//! `(resource_type, id)`, alongside an integer `version` that bumps on every
//! write. `InMemoryStore` is the zero-dependency backend for tests and demos;
//! `SqliteStore` is the real single-box persistent backend (bundled SQLite, so
//! no system library is required).
//!
//! `InMemoryStore`, `list`, and `open_in_memory` are exercised by the test
//! suite rather than the binary's happy path, so the dead-code lint is silenced
//! for this module — they're real API surface, not dead code.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use rusqlite::Connection;
use serde_json::Value;

/// Anything that can go wrong talking to a store.
#[derive(Debug)]
pub enum StoreError {
    Db(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Db(m) => write!(f, "store error: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

/// A store of FHIR resources. One trait, many backends.
pub trait ChartStore: Send + Sync {
    /// Store a resource, bumping its version. Returns the new version number
    /// (1 on first write of this id, then 2, 3, ...).
    fn put(&self, resource_type: &str, id: &str, resource: &Value) -> Result<i64, StoreError>;

    /// Fetch a resource by type + id, if present.
    fn get(&self, resource_type: &str, id: &str) -> Result<Option<Value>, StoreError>;

    /// List every stored resource of a given type. Used to inspect the
    /// append-only audit/provenance records (which get a fresh uuid per write);
    /// a type-level list is the seam a search endpoint will later build on.
    fn list(&self, resource_type: &str) -> Result<Vec<Value>, StoreError>;
}

// ---------------------------------------------------------------------------

/// In-memory backend: everything in a map. No persistence. For tests and demos.
#[derive(Default)]
pub struct InMemoryStore {
    // key: "ResourceType/id" -> (version, FHIR resource JSON)
    data: Mutex<HashMap<String, (i64, Value)>>,
}

impl ChartStore for InMemoryStore {
    fn put(&self, resource_type: &str, id: &str, resource: &Value) -> Result<i64, StoreError> {
        let mut data = self.data.lock().unwrap();
        let key = format!("{resource_type}/{id}");
        let version = data.get(&key).map(|(v, _)| v + 1).unwrap_or(1);
        data.insert(key, (version, resource.clone()));
        Ok(version)
    }

    fn get(&self, resource_type: &str, id: &str) -> Result<Option<Value>, StoreError> {
        Ok(self
            .data
            .lock()
            .unwrap()
            .get(&format!("{resource_type}/{id}"))
            .map(|(_, v)| v.clone()))
    }

    fn list(&self, resource_type: &str) -> Result<Vec<Value>, StoreError> {
        let prefix = format!("{resource_type}/");
        Ok(self
            .data
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, (_, v))| v.clone())
            .collect())
    }
}

// ---------------------------------------------------------------------------

/// SQLite backend. The real single-box persistent store.
pub struct SqliteStore {
    // ponytail: global connection lock, move to a pool if write throughput matters
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (or create) a file-backed database and ensure the schema exists.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database — used by the test suite.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    fn init(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS resources (
                 resource_type TEXT NOT NULL,
                 id            TEXT NOT NULL,
                 version       INTEGER NOT NULL,
                 payload       TEXT NOT NULL,
                 PRIMARY KEY (resource_type, id)
             );",
        )?;
        Ok(())
    }
}

impl ChartStore for SqliteStore {
    fn put(&self, resource_type: &str, id: &str, resource: &Value) -> Result<i64, StoreError> {
        let conn = self.conn.lock().unwrap();
        // One atomic upsert; RETURNING hands back the post-bump version.
        let version: i64 = conn.query_row(
            "INSERT INTO resources (resource_type, id, version, payload)
             VALUES (?1, ?2, 1, ?3)
             ON CONFLICT(resource_type, id)
             DO UPDATE SET version = version + 1, payload = excluded.payload
             RETURNING version",
            rusqlite::params![resource_type, id, resource.to_string()],
            |row| row.get(0),
        )?;
        Ok(version)
    }

    fn get(&self, resource_type: &str, id: &str) -> Result<Option<Value>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let payload: Option<String> = conn
            .query_row(
                "SELECT payload FROM resources WHERE resource_type = ?1 AND id = ?2",
                rusqlite::params![resource_type, id],
                |row| row.get(0),
            )
            .ok();
        match payload {
            Some(s) => Ok(Some(
                serde_json::from_str(&s).map_err(|e| StoreError::Db(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    fn list(&self, resource_type: &str) -> Result<Vec<Value>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT payload FROM resources WHERE resource_type = ?1")?;
        let rows = stmt.query_map(rusqlite::params![resource_type], |row| {
            row.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for r in rows {
            let s = r?;
            out.push(serde_json::from_str(&s).map_err(|e| StoreError::Db(e.to_string()))?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// InMemoryStore stays a first-class backend: same trait, same behavior.
    #[test]
    fn in_memory_put_get_list_and_version() {
        let store = InMemoryStore::default();
        assert_eq!(
            store
                .put("Patient", "p1", &json!({"resourceType": "Patient"}))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .put("Patient", "p1", &json!({"resourceType": "Patient"}))
                .unwrap(),
            2
        );
        assert_eq!(store.get("Patient", "p1").unwrap().unwrap()["resourceType"], "Patient");
        assert!(store.get("Patient", "nope").unwrap().is_none());
        assert_eq!(store.list("Patient").unwrap().len(), 1);
    }

    #[test]
    fn sqlite_put_get_list_and_version() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(
            store
                .put("Condition", "c1", &json!({"resourceType": "Condition"}))
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .put("Condition", "c1", &json!({"resourceType": "Condition"}))
                .unwrap(),
            2
        );
        assert!(store.get("Condition", "c1").unwrap().is_some());
        assert_eq!(store.list("Condition").unwrap().len(), 1);
        assert!(store.get("Condition", "nope").unwrap().is_none());
    }
}
