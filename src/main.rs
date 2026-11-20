//! ChartCraft — Milestone 0 skeleton.
//!
//! The smallest honest start: a FHIR `Patient` stored and read back through a
//! `ChartStore` trait, over an axum HTTP server. The store keeps the whole FHIR
//! resource as JSON and promotes `id` to the key — exactly the shape the real
//! Postgres backend will take (JSONB payload + promoted columns), so swapping
//! in a persistent store is an implementation of this trait, not a rewrite.
//!
//! Deliberately NOT here yet (these are the first good-first-issues):
//!   - SQLite/Postgres `ChartStore` impl (right now it's in-memory)
//!   - AuditEvent on read, Provenance on write
//!   - auth
//! ponytail: in-memory store is the known ceiling; first issue is a SQLite impl of ChartStore.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

/// A store of FHIR resources. One trait, many backends.
trait ChartStore: Send + Sync {
    /// Store a resource, returning the id it was filed under.
    fn put(&self, resource_type: &str, id: &str, resource: Value);
    /// Fetch a resource by type + id.
    fn get(&self, resource_type: &str, id: &str) -> Option<Value>;
}

/// Milestone 0 backend: everything in a map. No persistence. Replace me.
#[derive(Default)]
struct InMemoryStore {
    // key: "ResourceType/id" -> FHIR resource JSON
    data: Mutex<HashMap<String, Value>>,
}

impl ChartStore for InMemoryStore {
    fn put(&self, resource_type: &str, id: &str, resource: Value) {
        self.data
            .lock()
            .unwrap()
            .insert(format!("{resource_type}/{id}"), resource);
    }
    fn get(&self, resource_type: &str, id: &str) -> Option<Value> {
        self.data
            .lock()
            .unwrap()
            .get(&format!("{resource_type}/{id}"))
            .cloned()
    }
}

type SharedStore = Arc<dyn ChartStore>;

/// POST /Patient — assign a server id, store the FHIR resource, echo it back.
async fn create_patient(
    State(store): State<SharedStore>,
    Json(mut patient): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let id = uuid::Uuid::new_v4().to_string();
    patient["resourceType"] = json!("Patient");
    patient["id"] = json!(id);
    store.put("Patient", &id, patient.clone());
    (StatusCode::CREATED, Json(patient))
}

/// GET /Patient/:id — read it back, or a FHIR OperationOutcome 404.
async fn read_patient(
    State(store): State<SharedStore>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match store.get("Patient", &id) {
        Some(p) => (StatusCode::OK, Json(p)),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "resourceType": "OperationOutcome",
                "issue": [{"severity": "error", "code": "not-found",
                           "diagnostics": format!("Patient/{id} not found")}]
            })),
        ),
    }
}

fn app(store: SharedStore) -> Router {
    Router::new()
        .route("/Patient", post(create_patient))
        .route("/Patient/:id", get(read_patient))
        .with_state(store)
}

#[tokio::main]
async fn main() {
    let store: SharedStore = Arc::new(InMemoryStore::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind 127.0.0.1:8080");
    println!("ChartCraft M0 listening on http://127.0.0.1:8080  (POST /Patient, GET /Patient/:id)");
    axum::serve(listener, app(store)).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    // The one check: a Patient stored is a Patient returned, with a server id.
    #[test]
    fn patient_roundtrips_through_the_store() {
        let store = InMemoryStore::default();
        let id = "abc-123";
        store.put("Patient", id, json!({"resourceType": "Patient", "id": id,
                                        "name": [{"family": "Sharma"}]}));

        let got = store.get("Patient", id).expect("stored patient should read back");
        assert_eq!(got["resourceType"], "Patient");
        assert_eq!(got["name"][0]["family"], "Sharma");
        assert!(store.get("Patient", "nope").is_none());
    }
}
