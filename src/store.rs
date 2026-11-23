//! The storage seam: one `ChartStore` trait, two honest backends.
//!
//! A FHIR resource is kept as its whole JSON payload, keyed by
//! `(resource_type, id)`. Writes are APPEND-ONLY: each write inserts a new row
//! at `version = prev_max + 1` and flips the prior row's `is_current` flag —
//! the old payload is never overwritten, so every version is retained. One
//! `commit(&[WriteOp])` is the single write path for both backends, so
//! version-bumping, `is_current` flipping, `patient_ref` promotion, and audit
//! hash-chaining each live in exactly one place. `put` is just a one-op commit.
//!
//! The governance mechanism lives here, not in the handlers: a clinical write +
//! its Provenance + its AuditEvent go through ONE `commit` (all-or-nothing), and
//! every `AuditEvent` written is linked into a tamper-evident SHA-256 hash chain
//! that `verify_audit_chain` can recompute head-to-tail.
//!
//! `InMemoryStore` is the zero-dependency backend for tests and demos;
//! `SqliteStore` is the real single-box persistent backend (bundled SQLite).
//!
//! `InMemoryStore`, `list`, `history`, and `open_in_memory` are exercised by the
//! test suite rather than the binary's happy path, so the dead-code lint is
//! silenced for this module — they're real API surface, not dead code.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};

// ponytail: ONE global audit hash chain, not per-patient. Every AuditEvent in
// the store links into a single sequence. Good enough to prove no event was
// altered or dropped mid-chain. Ceiling: (1) a per-patient chain would localize
// tamper-evidence and scale better, and (2) TAIL TRUNCATION is undetectable —
// lopping the last N links off `audit_chain` plus their events still verifies
// clean, because there is no stored, external head/anchor to compare against.
// A signed or externally-published chain head would close that gap; deferred.

/// Genesis hash the first audit-chain link chains from. A fixed constant so the
/// chain has a well-known root; recomputation starts here.
pub const AUDIT_GENESIS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Anything that can go wrong talking to a store.
#[derive(Debug)]
pub enum StoreError {
    Db(String),
    /// A write would create a second version of an insert-only governance record
    /// (AuditEvent / Provenance). These are immutable by invariant, not allowlist.
    ImmutableResource(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Db(m) => write!(f, "store error: {m}"),
            StoreError::ImmutableResource(m) => write!(f, "immutable resource: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

/// One resource write, composable into an all-or-nothing batch. The handler
/// builds a `Vec<WriteOp>` (resource + Provenance + AuditEvent) and hands it to
/// `commit`; nothing persists unless all of them do.
#[derive(Debug, Clone)]
pub struct WriteOp {
    pub resource_type: String,
    pub id: String,
    pub payload: Value,
}

impl WriteOp {
    pub fn new(resource_type: &str, id: &str, payload: Value) -> Self {
        WriteOp {
            resource_type: resource_type.to_string(),
            id: id.to_string(),
            payload,
        }
    }
}

/// Promote the patient reference off a resource, matching the existing
/// `references_patient` convention: `subject.reference` wins, else
/// `patient.reference`. Returns the full reference string (e.g. "Patient/abc").
// ponytail: subject wins if both fields are present. In US Core a resource
// carries one or the other, so a both-present clash is theoretical.
fn patient_ref_of(payload: &Value) -> Option<String> {
    payload["subject"]["reference"]
        .as_str()
        .or_else(|| payload["patient"]["reference"].as_str())
        .map(str::to_string)
}

/// Governance records that are insert-only: every write is version 1 at a fresh
/// id, never a second version. The immutability invariant lives in the `commit`
/// mechanism (B1), not in a `SUPPORTED_TYPES` allowlist omission. `AuditEvent` is
/// the hash-chain's backing store; `Provenance` is the authorship record — both
/// must be append-only for the audit trail to mean anything.
fn is_immutable_governance(resource_type: &str) -> bool {
    matches!(resource_type, "AuditEvent" | "Provenance")
}

/// SHA-256 of `prev_hash_hex || canonical_json_of_event`, hex-encoded. The event
/// JSON is serialized with serde_json's default (sorted-key) Map, so `to_string`
/// is already canonical — no `preserve_order` feature is enabled.
fn chain_hash(prev_hash: &str, event: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(event.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// A store of FHIR resources. One trait, many backends.
pub trait ChartStore: Send + Sync {
    /// Apply a batch of writes in ONE transaction — all-or-nothing. On any
    /// failure (bad op, DB fault) NONE of the batch persists. Returns the new
    /// version per op, in order. This is the single write path; `put` is sugar.
    ///
    /// Each write is append-only: it inserts a new row at `version = prev_max+1`
    /// with `is_current = 1` and flips the previous current row to `0`. Any op
    /// whose `resource_type == "AuditEvent"` is also linked into the audit hash
    /// chain inside the same transaction.
    fn commit(&self, ops: &[WriteOp]) -> Result<Vec<i64>, StoreError>;

    /// Store a single resource, bumping its version. Sugar over a one-op commit.
    /// Returns the new version number (1 on first write of this id, then 2, ...).
    fn put(&self, resource_type: &str, id: &str, resource: &Value) -> Result<i64, StoreError> {
        let v = self.commit(&[WriteOp::new(resource_type, id, resource.clone())])?;
        Ok(v[0])
    }

    /// Fetch the CURRENT version of a resource by type + id, if present.
    fn get(&self, resource_type: &str, id: &str) -> Result<Option<Value>, StoreError>;

    /// List the CURRENT version of every stored resource of a given type.
    fn list(&self, resource_type: &str) -> Result<Vec<Value>, StoreError>;

    /// Every retained version of one resource, oldest→newest. Proves the record
    /// is append-only: a PUT adds a version here, it never overwrites one.
    fn history(&self, resource_type: &str, id: &str) -> Result<Vec<Value>, StoreError>;

    /// Current resources of `resource_type` that reference `Patient/<patient_ref>`,
    /// via the promoted+indexed `patient_ref` column — not a full-scan filter.
    /// The argument is the Patient id; an EMPTY id returns nothing by an explicit
    /// guard (B3), enforcing the empty-filter PHI contract rather than leaving it
    /// to depend on no resource happening to carry a `Patient/` reference.
    fn find_by_patient(
        &self,
        resource_type: &str,
        patient_id: &str,
    ) -> Result<Vec<Value>, StoreError>;

    /// Recompute the audit hash chain head-to-tail. `false` if any link is broken
    /// — an event payload was altered, or a link's stored hash doesn't match.
    fn verify_audit_chain(&self) -> Result<bool, StoreError>;
}

// ---------------------------------------------------------------------------

/// One retained version of a resource in the in-memory backend.
struct MemVersion {
    version: i64,
    payload: Value,
    patient_ref: Option<String>,
    is_current: bool,
}

/// One link of the in-memory audit hash chain.
struct MemChainLink {
    event_id: String,
    prev_hash: String,
    hash: String,
}

#[derive(Default)]
struct MemState {
    // key: "ResourceType/id" -> append-only vec of versions (oldest→newest)
    data: HashMap<String, Vec<MemVersion>>,
    // audit hash chain, in append order
    chain: Vec<MemChainLink>,
}

/// In-memory backend: everything in a map. No persistence. For tests and demos.
#[derive(Default)]
pub struct InMemoryStore {
    state: Mutex<MemState>,
}

impl ChartStore for InMemoryStore {
    fn commit(&self, ops: &[WriteOp]) -> Result<Vec<i64>, StoreError> {
        // Validate the whole batch FIRST so a bad op aborts before any mutation —
        // all-or-nothing without needing to unwind.
        for op in ops {
            if op.resource_type.is_empty() || op.id.is_empty() {
                return Err(StoreError::Db(format!(
                    "invalid WriteOp: empty resource_type or id ({}/{})",
                    op.resource_type, op.id
                )));
            }
        }

        let mut state = self.state.lock().unwrap();

        // B1: governance records (AuditEvent / Provenance) are insert-only — always
        // version 1, fresh id. Reject any op that would create version > 1. Unlike
        // SQLite (whose per-op `next` catches this for free), the in-memory loop
        // mutates incrementally with no rollback, so this guard must run in the
        // pre-mutation pass WITH the lock held, and must also catch an intra-batch
        // duplicate id that the store doesn't yet know about.
        // Keyed on the full `type/id` (matching SQLite's per-(type,id) `next`), so
        // a batch with both AuditEvent/x and Provenance/x is NOT falsely rejected.
        let mut seen_in_batch: std::collections::HashSet<String> = std::collections::HashSet::new();
        for op in ops {
            if is_immutable_governance(&op.resource_type) {
                let key = format!("{}/{}", op.resource_type, op.id);
                if state.data.contains_key(&key) || !seen_in_batch.insert(key.clone()) {
                    return Err(StoreError::ImmutableResource(format!(
                        "{} is insert-only; cannot create a second version of {key}",
                        op.resource_type
                    )));
                }
            }
        }

        let mut versions = Vec::with_capacity(ops.len());
        for op in ops {
            let key = format!("{}/{}", op.resource_type, op.id);
            let entry = state.data.entry(key).or_default();
            let next = entry.last().map(|v| v.version + 1).unwrap_or(1);
            for v in entry.iter_mut() {
                v.is_current = false;
            }
            entry.push(MemVersion {
                version: next,
                payload: op.payload.clone(),
                patient_ref: patient_ref_of(&op.payload),
                is_current: true,
            });
            versions.push(next);

            if op.resource_type == "AuditEvent" {
                let prev = state
                    .chain
                    .last()
                    .map(|l| l.hash.clone())
                    .unwrap_or_else(|| AUDIT_GENESIS.to_string());
                let hash = chain_hash(&prev, &op.payload);
                state.chain.push(MemChainLink {
                    event_id: op.id.clone(),
                    prev_hash: prev,
                    hash,
                });
            }
        }
        Ok(versions)
    }

    fn get(&self, resource_type: &str, id: &str) -> Result<Option<Value>, StoreError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .data
            .get(&format!("{resource_type}/{id}"))
            .and_then(|vs| vs.iter().find(|v| v.is_current))
            .map(|v| v.payload.clone()))
    }

    fn list(&self, resource_type: &str) -> Result<Vec<Value>, StoreError> {
        let prefix = format!("{resource_type}/");
        let state = self.state.lock().unwrap();
        Ok(state
            .data
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(_, vs)| vs.iter().find(|v| v.is_current))
            .map(|v| v.payload.clone())
            .collect())
    }

    fn history(&self, resource_type: &str, id: &str) -> Result<Vec<Value>, StoreError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .data
            .get(&format!("{resource_type}/{id}"))
            .map(|vs| vs.iter().map(|v| v.payload.clone()).collect())
            .unwrap_or_default())
    }

    fn find_by_patient(
        &self,
        resource_type: &str,
        patient_id: &str,
    ) -> Result<Vec<Value>, StoreError> {
        // B3: an empty patient id returns nothing, explicitly — never every
        // patient's data. The PHI boundary is enforced here, not left incidental.
        if patient_id.is_empty() {
            return Ok(vec![]);
        }
        let prefix = format!("{resource_type}/");
        let target = format!("Patient/{patient_id}");
        let state = self.state.lock().unwrap();
        Ok(state
            .data
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(_, vs)| vs.iter().find(|v| v.is_current))
            .filter(|v| v.patient_ref.as_deref() == Some(target.as_str()))
            .map(|v| v.payload.clone())
            .collect())
    }

    fn verify_audit_chain(&self) -> Result<bool, StoreError> {
        let state = self.state.lock().unwrap();
        let mut prev = AUDIT_GENESIS.to_string();
        for link in &state.chain {
            if link.prev_hash != prev {
                return Ok(false);
            }
            // Fetch the current event payload and recompute.
            let payload = state
                .data
                .get(&format!("AuditEvent/{}", link.event_id))
                .and_then(|vs| vs.iter().find(|v| v.is_current))
                .map(|v| &v.payload);
            let payload = match payload {
                Some(p) => p,
                None => return Ok(false), // event removed under us
            };
            if chain_hash(&prev, payload) != link.hash {
                return Ok(false);
            }
            prev = link.hash.clone();
        }
        Ok(true)
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
    ///
    /// ponytail: pre-release, no migration path. The versioned schema below is
    /// NOT compatible with the old single-row `resources` table — delete any
    /// existing `chartcraft.db` before upgrading. `init` only CREATEs IF NOT
    /// EXISTS, so an old DB would fail LOUDLY at the first `commit` (missing
    /// `is_current`/`patient_ref` columns), not silently corrupt.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        // N5: the clinical store and the auth store share `chartcraft.db`. Wait up
        // to 5 s for a concurrent writer's lock instead of surfacing SQLITE_BUSY as
        // a 500 the instant the two connections contend.
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
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
                 resource_type TEXT    NOT NULL,
                 id            TEXT    NOT NULL,
                 version       INTEGER NOT NULL,
                 payload       TEXT    NOT NULL,
                 recorded      TEXT    NOT NULL,
                 is_current    INTEGER NOT NULL,
                 patient_ref   TEXT,
                 PRIMARY KEY (resource_type, id, version)
             );
             CREATE INDEX IF NOT EXISTS idx_resources_patient
                 ON resources (resource_type, patient_ref);
             CREATE TABLE IF NOT EXISTS audit_chain (
                 seq       INTEGER PRIMARY KEY,
                 event_id  TEXT NOT NULL,
                 prev_hash TEXT NOT NULL,
                 hash      TEXT NOT NULL
             );",
        )?;
        Ok(())
    }
}

impl ChartStore for SqliteStore {
    fn commit(&self, ops: &[WriteOp]) -> Result<Vec<i64>, StoreError> {
        // Validate the batch before touching the DB.
        for op in ops {
            if op.resource_type.is_empty() || op.id.is_empty() {
                return Err(StoreError::Db(format!(
                    "invalid WriteOp: empty resource_type or id ({}/{})",
                    op.resource_type, op.id
                )));
            }
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = crate::fhir::now_iso8601();
        let mut versions = Vec::with_capacity(ops.len());

        for op in ops {
            // Next version = prev max + 1 for this (type, id).
            let next: i64 = tx.query_row(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM resources
                 WHERE resource_type = ?1 AND id = ?2",
                rusqlite::params![op.resource_type, op.id],
                |row| row.get(0),
            )?;
            // B1: governance records are insert-only — version 1, fresh id. A
            // `next > 1` here means this id already has a version, so reject before
            // mutating. Returning early drops `tx`, which rolls the whole batch back
            // (an intra-batch dup also hits this: the first op inserts, the second
            // sees MAX=1 → next=2 → Err), so a violating batch persists nothing.
            if is_immutable_governance(&op.resource_type) && next > 1 {
                return Err(StoreError::ImmutableResource(format!(
                    "{} is insert-only; cannot create version {next} of {}/{}",
                    op.resource_type, op.resource_type, op.id
                )));
            }
            // Demote the previous current row (if any) — never an UPDATE of payload.
            tx.execute(
                "UPDATE resources SET is_current = 0
                 WHERE resource_type = ?1 AND id = ?2 AND is_current = 1",
                rusqlite::params![op.resource_type, op.id],
            )?;
            // Append the new version as current.
            tx.execute(
                "INSERT INTO resources
                   (resource_type, id, version, payload, recorded, is_current, patient_ref)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                rusqlite::params![
                    op.resource_type,
                    op.id,
                    next,
                    op.payload.to_string(),
                    now,
                    patient_ref_of(&op.payload),
                ],
            )?;
            versions.push(next);

            if op.resource_type == "AuditEvent" {
                use rusqlite::OptionalExtension;
                // `.optional()?` maps "empty chain" to genesis but PROPAGATES a
                // real DB fault — a swallowed error here would silently fork the
                // chain (a bogus prev_hash), making verify report false tampering.
                let prev: String = tx
                    .query_row(
                        "SELECT hash FROM audit_chain ORDER BY seq DESC LIMIT 1",
                        [],
                        |row| row.get(0),
                    )
                    .optional()?
                    .unwrap_or_else(|| AUDIT_GENESIS.to_string());
                let hash = chain_hash(&prev, &op.payload);
                tx.execute(
                    "INSERT INTO audit_chain (event_id, prev_hash, hash) VALUES (?1, ?2, ?3)",
                    rusqlite::params![op.id, prev, hash],
                )?;
            }
        }

        tx.commit()?;
        Ok(versions)
    }

    fn get(&self, resource_type: &str, id: &str) -> Result<Option<Value>, StoreError> {
        use rusqlite::OptionalExtension;
        let conn = self.conn.lock().unwrap();
        // `.optional()?` maps "no such row" to None but PROPAGATES a real DB fault
        // as Err — a database error must never read back as "patient not found".
        let payload: Option<String> = conn
            .query_row(
                "SELECT payload FROM resources
                 WHERE resource_type = ?1 AND id = ?2 AND is_current = 1",
                rusqlite::params![resource_type, id],
                |row| row.get(0),
            )
            .optional()?;
        match payload {
            Some(s) => Ok(Some(
                serde_json::from_str(&s).map_err(|e| StoreError::Db(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    fn list(&self, resource_type: &str) -> Result<Vec<Value>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT payload FROM resources WHERE resource_type = ?1 AND is_current = 1",
        )?;
        let rows = stmt.query_map(rusqlite::params![resource_type], |row| {
            row.get::<_, String>(0)
        })?;
        collect_payloads(rows)
    }

    fn history(&self, resource_type: &str, id: &str) -> Result<Vec<Value>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT payload FROM resources
             WHERE resource_type = ?1 AND id = ?2 ORDER BY version ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![resource_type, id], |row| {
            row.get::<_, String>(0)
        })?;
        collect_payloads(rows)
    }

    fn find_by_patient(
        &self,
        resource_type: &str,
        patient_id: &str,
    ) -> Result<Vec<Value>, StoreError> {
        // B3: an empty patient id returns nothing, explicitly (see trait doc).
        if patient_id.is_empty() {
            return Ok(vec![]);
        }
        let target = format!("Patient/{patient_id}");
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT payload FROM resources
             WHERE resource_type = ?1 AND patient_ref = ?2 AND is_current = 1",
        )?;
        let rows = stmt.query_map(rusqlite::params![resource_type, target], |row| {
            row.get::<_, String>(0)
        })?;
        collect_payloads(rows)
    }

    fn verify_audit_chain(&self) -> Result<bool, StoreError> {
        use rusqlite::OptionalExtension;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT event_id, prev_hash, hash FROM audit_chain ORDER BY seq ASC")?;
        let links = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut prev = AUDIT_GENESIS.to_string();
        for link in links {
            let (event_id, prev_hash, hash) = link?;
            if prev_hash != prev {
                return Ok(false);
            }
            // Recompute from the CURRENT stored event payload; a tampered payload
            // yields a different hash and breaks the chain here.
            let payload: Option<String> = conn
                .query_row(
                    "SELECT payload FROM resources
                     WHERE resource_type = 'AuditEvent' AND id = ?1 AND is_current = 1",
                    rusqlite::params![event_id],
                    |row| row.get(0),
                )
                .optional()?;
            let payload = match payload {
                Some(s) => serde_json::from_str::<Value>(&s)
                    .map_err(|e| StoreError::Db(e.to_string()))?,
                None => return Ok(false), // event removed
            };
            if chain_hash(&prev, &payload) != hash {
                return Ok(false);
            }
            prev = hash;
        }
        Ok(true)
    }
}

/// Collect a `query_map` of JSON strings into parsed `Value`s, propagating both
/// row-fetch and parse errors as `StoreError`.
fn collect_payloads(
    rows: impl Iterator<Item = rusqlite::Result<String>>,
) -> Result<Vec<Value>, StoreError> {
    let mut out = Vec::new();
    for r in rows {
        let s = r?;
        out.push(serde_json::from_str(&s).map_err(|e| StoreError::Db(e.to_string()))?);
    }
    Ok(out)
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

    /// Change 1: a PUT does not overwrite — every version is retained, oldest→newest.
    #[test]
    fn history_retains_every_version_in_both_backends() {
        for store in backends() {
            store
                .put("Patient", "p1", &json!({"resourceType": "Patient", "name": "v1"}))
                .unwrap();
            store
                .put("Patient", "p1", &json!({"resourceType": "Patient", "name": "v2"}))
                .unwrap();
            store
                .put("Patient", "p1", &json!({"resourceType": "Patient", "name": "v3"}))
                .unwrap();

            // get() returns only the current version...
            assert_eq!(store.get("Patient", "p1").unwrap().unwrap()["name"], "v3");
            // ...but history keeps all three, in order.
            let hist = store.history("Patient", "p1").unwrap();
            assert_eq!(hist.len(), 3, "all three versions retained");
            assert_eq!(hist[0]["name"], "v1");
            assert_eq!(hist[1]["name"], "v2");
            assert_eq!(hist[2]["name"], "v3");
            // list() still sees exactly one (the current) row.
            assert_eq!(store.list("Patient").unwrap().len(), 1);
        }
    }

    /// Change 2: a batch that fails partway leaves the store UNCHANGED — no
    /// orphaned resource without its Provenance/Audit.
    #[test]
    fn commit_is_all_or_nothing() {
        for store in backends() {
            // Last op is invalid (empty id) — the whole batch must roll back.
            let batch = vec![
                WriteOp::new("Patient", "p1", json!({"resourceType": "Patient"})),
                WriteOp::new("Provenance", "prov1", json!({"resourceType": "Provenance"})),
                WriteOp::new("AuditEvent", "", json!({"resourceType": "AuditEvent"})),
            ];
            assert!(store.commit(&batch).is_err(), "bad op must fail the batch");

            // Nothing from the batch persisted.
            assert!(store.get("Patient", "p1").unwrap().is_none(), "no orphaned resource");
            assert!(store.get("Provenance", "prov1").unwrap().is_none(), "no orphaned provenance");
            assert_eq!(store.list("AuditEvent").unwrap().len(), 0, "no audit event");
        }
    }

    /// Change 2 (happy path): a good multi-op batch persists all ops atomically.
    #[test]
    fn commit_persists_the_whole_batch() {
        for store in backends() {
            let batch = vec![
                WriteOp::new("Patient", "p1", json!({"resourceType": "Patient"})),
                WriteOp::new("Provenance", "prov1", json!({"resourceType": "Provenance"})),
                WriteOp::new("AuditEvent", "a1", json!({"resourceType": "AuditEvent"})),
            ];
            let versions = store.commit(&batch).unwrap();
            assert_eq!(versions, vec![1, 1, 1]);
            assert!(store.get("Patient", "p1").unwrap().is_some());
            assert!(store.get("Provenance", "prov1").unwrap().is_some());
            assert!(store.get("AuditEvent", "a1").unwrap().is_some());
        }
    }

    /// Change 3(a): a run of audited writes leaves the chain verifiable.
    #[test]
    fn audit_chain_verifies_after_several_writes() {
        for store in backends() {
            for i in 0..5 {
                let id = format!("a{i}");
                store
                    .commit(&[WriteOp::new(
                        "AuditEvent",
                        &id,
                        json!({"resourceType": "AuditEvent", "action": "R", "seq": i}),
                    )])
                    .unwrap();
            }
            assert!(store.verify_audit_chain().unwrap(), "intact chain verifies true");
        }
    }

    /// Change 3(b): mutating an audit event's payload in the store breaks the chain.
    #[test]
    fn mutating_an_audit_event_breaks_the_chain_sqlite() {
        let store = SqliteStore::open_in_memory().unwrap();
        for i in 0..3 {
            store
                .commit(&[WriteOp::new(
                    "AuditEvent",
                    &format!("a{i}"),
                    json!({"resourceType": "AuditEvent", "action": "R", "seq": i}),
                )])
                .unwrap();
        }
        assert!(store.verify_audit_chain().unwrap());

        // Tamper directly with a stored event payload (raw SQL, bypassing commit).
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE resources SET payload = ?1
                 WHERE resource_type = 'AuditEvent' AND id = 'a1' AND is_current = 1",
                rusqlite::params![
                    json!({"resourceType": "AuditEvent", "action": "TAMPERED", "seq": 1})
                        .to_string()
                ],
            )
            .unwrap();
        }
        assert!(
            !store.verify_audit_chain().unwrap(),
            "a tampered audit payload must break the chain"
        );
    }

    #[test]
    fn mutating_an_audit_event_breaks_the_chain_in_memory() {
        let store = InMemoryStore::default();
        for i in 0..3 {
            store
                .commit(&[WriteOp::new(
                    "AuditEvent",
                    &format!("a{i}"),
                    json!({"resourceType": "AuditEvent", "action": "R", "seq": i}),
                )])
                .unwrap();
        }
        assert!(store.verify_audit_chain().unwrap());

        // Overwrite the current payload of a1 in place (bypassing commit's chaining).
        {
            let mut state = store.state.lock().unwrap();
            let vs = state.data.get_mut("AuditEvent/a1").unwrap();
            let cur = vs.iter_mut().find(|v| v.is_current).unwrap();
            cur.payload = json!({"resourceType": "AuditEvent", "action": "TAMPERED", "seq": 1});
        }
        assert!(
            !store.verify_audit_chain().unwrap(),
            "a tampered audit payload must break the chain"
        );
    }

    /// Change 4: find_by_patient uses the promoted ref; empty id matches nothing.
    #[test]
    fn find_by_patient_filters_by_promoted_ref() {
        for store in backends() {
            store
                .put(
                    "Condition",
                    "c-alice-subj",
                    &json!({"resourceType": "Condition", "subject": {"reference": "Patient/alice"}}),
                )
                .unwrap();
            store
                .put(
                    "Condition",
                    "c-alice-pat",
                    &json!({"resourceType": "Condition", "patient": {"reference": "Patient/alice"}}),
                )
                .unwrap();
            store
                .put(
                    "Condition",
                    "c-bob",
                    &json!({"resourceType": "Condition", "subject": {"reference": "Patient/bob"}}),
                )
                .unwrap();

            assert_eq!(store.find_by_patient("Condition", "alice").unwrap().len(), 2);
            assert_eq!(store.find_by_patient("Condition", "bob").unwrap().len(), 1);
            // Empty id → "Patient/" → matches nothing (empty-filter contract).
            assert_eq!(store.find_by_patient("Condition", "").unwrap().len(), 0);
        }
    }

    /// B1: a second write to an existing AuditEvent id is rejected, nothing from
    /// the violating batch persists, and the audit chain stays intact — in both
    /// backends. The violating op comes AFTER a valid op to prove the in-memory
    /// backend doesn't leak the earlier mutation.
    #[test]
    fn audit_event_is_insert_only_and_batch_rolls_back() {
        for store in backends() {
            // Seed one legitimate AuditEvent (version 1).
            store
                .commit(&[WriteOp::new(
                    "AuditEvent",
                    "a1",
                    json!({"resourceType": "AuditEvent", "action": "R"}),
                )])
                .unwrap();
            assert!(store.verify_audit_chain().unwrap());

            // A batch: a valid Patient write, then an illegal SECOND version of a1.
            let batch = vec![
                WriteOp::new("Patient", "p-rollback", json!({"resourceType": "Patient"})),
                WriteOp::new(
                    "AuditEvent",
                    "a1",
                    json!({"resourceType": "AuditEvent", "action": "TAMPER"}),
                ),
            ];
            assert!(
                matches!(store.commit(&batch), Err(StoreError::ImmutableResource(_))),
                "a second version of an AuditEvent id must be rejected"
            );

            // Nothing from the violating batch persisted (not even the earlier op).
            assert!(
                store.get("Patient", "p-rollback").unwrap().is_none(),
                "the valid op in a rejected batch must not persist"
            );
            // a1 is untouched: still version 1, still the original payload.
            assert_eq!(store.history("AuditEvent", "a1").unwrap().len(), 1);
            assert_eq!(store.get("AuditEvent", "a1").unwrap().unwrap()["action"], "R");

            // A normal audited op still succeeds and the chain stays verifiable.
            store
                .commit(&[WriteOp::new(
                    "AuditEvent",
                    "a2",
                    json!({"resourceType": "AuditEvent", "action": "R"}),
                )])
                .unwrap();
            assert!(store.verify_audit_chain().unwrap(), "chain intact after a legit write");
        }
    }

    /// B3: find_by_patient("", ...) returns empty EVEN WHEN a resource carries an
    /// empty `Patient/` reference — the guard, not the data, enforces the boundary.
    #[test]
    fn find_by_patient_empty_id_returns_nothing_even_with_patient_slash_row() {
        for store in backends() {
            // An adversarial row whose promoted patient_ref is exactly "Patient/".
            store
                .put(
                    "Condition",
                    "c-empty-ref",
                    &json!({"resourceType": "Condition", "subject": {"reference": "Patient/"}}),
                )
                .unwrap();
            assert_eq!(
                store.find_by_patient("Condition", "").unwrap().len(),
                0,
                "empty patient id must return nothing even with a Patient/ reference present"
            );
        }
    }

    fn backends() -> Vec<Box<dyn ChartStore>> {
        vec![
            Box::new(InMemoryStore::default()),
            Box::new(SqliteStore::open_in_memory().unwrap()),
        ]
    }
}
