//! ChartCraft — Milestone 1.
//!
//! A FHIR-native EMR core: generic CRUD over any supported US Core resource
//! type, persisted through a `ChartStore` (SQLite for the real binary,
//! in-memory for tests), with a governance spine — a `Provenance` written on
//! every create/update and an append-only `AuditEvent` on every read — plus a
//! `/metadata` CapabilityStatement.
//!
//! The store keeps each FHIR resource as its whole JSON payload keyed by
//! `(resourceType, id)` with an integer version, exactly the shape the eventual
//! Postgres backend will take (JSONB payload + promoted columns), so swapping
//! stores is implementing a trait, not a rewrite.

mod audit;
mod fhir;
mod store;

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use fhir::{capability_statement, is_supported, operation_outcome};
use store::{ChartStore, SqliteStore};

type SharedStore = Arc<dyn ChartStore>;

/// POST /:resource_type — assign a uuid id, stamp resourceType, store, 201.
async fn create_resource(
    State(store): State<SharedStore>,
    Path(resource_type): Path<String>,
    Json(mut body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Some(bad) = reject_type(&resource_type, &body) {
        return bad;
    }

    let id = uuid::Uuid::new_v4().to_string();
    body["resourceType"] = json!(resource_type);
    body["id"] = json!(id);

    write(&store, &resource_type, &id, &body)
}

/// PUT /:resource_type/:id — upsert at a client-chosen id, bump version, 200/201.
async fn update_resource(
    State(store): State<SharedStore>,
    Path((resource_type, id)): Path<(String, String)>,
    Json(mut body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Some(bad) = reject_type(&resource_type, &body) {
        return bad;
    }

    body["resourceType"] = json!(resource_type);
    body["id"] = json!(id);

    write(&store, &resource_type, &id, &body)
}

/// GET /:resource_type/:id — read, logging an AuditEvent, or 404 OperationOutcome.
async fn read_resource(
    State(store): State<SharedStore>,
    Path((resource_type, id)): Path<(String, String)>,
) -> (StatusCode, Json<Value>) {
    if !is_supported(&resource_type) {
        return unsupported(&resource_type);
    }

    match store.get(&resource_type, &id) {
        Ok(Some(resource)) => {
            // Append-only audit of the read. A failure to audit must not leak PHI,
            // so surface it as a 500 rather than returning the resource unlogged.
            if let Err(e) = audit::record_audit_read(store.as_ref(), &resource_type, &id) {
                return server_error(&e.to_string());
            }
            (StatusCode::OK, Json(resource))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(operation_outcome(
                "error",
                "not-found",
                &format!("{resource_type}/{id} not found"),
            )),
        ),
        Err(e) => server_error(&e.to_string()),
    }
}

/// GET /metadata — the FHIR CapabilityStatement for this server.
async fn metadata() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(capability_statement()))
}

// --- shared handler logic ---------------------------------------------------

/// Validate the type, store the resource, and record its Provenance. Returns the
/// 201 + resource on success, or the appropriate OperationOutcome error.
fn write(
    store: &SharedStore,
    resource_type: &str,
    id: &str,
    body: &Value,
) -> (StatusCode, Json<Value>) {
    let version = match store.put(resource_type, id, body) {
        Ok(v) => v,
        Err(e) => return server_error(&e.to_string()),
    };
    if let Err(e) = audit::record_provenance(store.as_ref(), resource_type, id) {
        return server_error(&e.to_string());
    }
    // FHIR: 201 when this write created the resource, 200 when it updated one.
    let code = if version == 1 {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (code, Json(body.clone()))
}

/// 400 if the type is unsupported, or if the body's resourceType contradicts the
/// path. Returns `Some(error response)` to reject, `None` to proceed.
fn reject_type(resource_type: &str, body: &Value) -> Option<(StatusCode, Json<Value>)> {
    if !is_supported(resource_type) {
        return Some(unsupported(resource_type));
    }
    if let Some(body_type) = body.get("resourceType").and_then(Value::as_str) {
        if body_type != resource_type {
            return Some((
                StatusCode::BAD_REQUEST,
                Json(operation_outcome(
                    "error",
                    "invalid",
                    &format!(
                        "body resourceType '{body_type}' does not match path '{resource_type}'"
                    ),
                )),
            ));
        }
    }
    None
}

fn unsupported(resource_type: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(operation_outcome(
            "error",
            "not-supported",
            &format!("resource type '{resource_type}' is not supported"),
        )),
    )
}

fn server_error(detail: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(operation_outcome("error", "exception", detail)),
    )
}

fn app(store: SharedStore) -> Router {
    Router::new()
        .route("/metadata", get(metadata))
        .route("/:resource_type", post(create_resource))
        .route(
            "/:resource_type/:id",
            get(read_resource).put(update_resource),
        )
        .with_state(store)
}

#[tokio::main]
async fn main() {
    let store: SharedStore =
        Arc::new(SqliteStore::open("chartcraft.db").expect("open chartcraft.db"));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind 127.0.0.1:8080");
    println!(
        "ChartCraft M1 on http://127.0.0.1:8080 \
         (POST/GET/PUT /:resource_type[/:id], GET /metadata)"
    );
    axum::serve(listener, app(store)).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_store() -> SharedStore {
        Arc::new(SqliteStore::open_in_memory().expect("in-memory sqlite"))
    }

    #[tokio::test]
    async fn sqlite_roundtrips_two_resource_types() {
        let store = mem_store();

        // A Patient...
        let (code, Json(patient)) = create_resource(
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Sharma"}]})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let patient_id = patient["id"].as_str().unwrap().to_string();
        assert_eq!(patient["resourceType"], "Patient");

        let (code, Json(got)) = read_resource(
            State(store.clone()),
            Path(("Patient".into(), patient_id.clone())),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(got["name"][0]["family"], "Sharma");

        // ...and a Condition, different type, same store.
        let (code, Json(cond)) = create_resource(
            State(store.clone()),
            Path("Condition".into()),
            Json(json!({"code": {"text": "Hypertension"}})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let cond_id = cond["id"].as_str().unwrap().to_string();

        let (code, Json(got)) =
            read_resource(State(store.clone()), Path(("Condition".into(), cond_id))).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(got["code"]["text"], "Hypertension");
    }

    #[tokio::test]
    async fn put_upserts_and_bumps_version() {
        let store = mem_store();
        let v1 = store
            .put("Observation", "obs-1", &json!({"resourceType": "Observation"}))
            .unwrap();
        let v2 = store
            .put("Observation", "obs-1", &json!({"resourceType": "Observation"}))
            .unwrap();
        assert_eq!(v1, 1);
        assert_eq!(v2, 2);

        // First PUT at a new id creates (201); a second PUT updates (200).
        let (code, _) = update_resource(
            State(store.clone()),
            Path(("Observation".into(), "obs-2".into())),
            Json(json!({"status": "final"})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);

        let (code, _) = update_resource(
            State(store.clone()),
            Path(("Observation".into(), "obs-2".into())),
            Json(json!({"status": "amended"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
    }

    #[tokio::test]
    async fn resource_type_path_mismatch_is_400() {
        let store = mem_store();
        let (code, Json(oo)) = create_resource(
            State(store),
            Path("Patient".into()),
            Json(json!({"resourceType": "Condition"})),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(oo["resourceType"], "OperationOutcome");
    }

    #[tokio::test]
    async fn unknown_resource_type_is_400() {
        let store = mem_store();
        let (code, Json(oo)) = create_resource(
            State(store),
            Path("Dragon".into()),
            Json(json!({"hoard": "gold"})),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(oo["resourceType"], "OperationOutcome");
    }

    #[tokio::test]
    async fn write_produces_a_provenance() {
        let store = mem_store();
        let (code, Json(patient)) = create_resource(
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Rao"}]})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let target = format!("Patient/{}", patient["id"].as_str().unwrap());

        // Scan the store: exactly one Provenance targeting the new Patient.
        let found = find_by(&store, "Provenance", |p| {
            p["target"][0]["reference"] == json!(target)
        });
        assert!(found, "expected a Provenance targeting {target}");
    }

    #[tokio::test]
    async fn read_produces_an_audit_event() {
        let store = mem_store();
        let (_, Json(patient)) = create_resource(
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Komi"}]})),
        )
        .await;
        let id = patient["id"].as_str().unwrap().to_string();

        let (code, _) =
            read_resource(State(store.clone()), Path(("Patient".into(), id.clone()))).await;
        assert_eq!(code, StatusCode::OK);

        let reference = format!("Patient/{id}");
        let found = find_by(&store, "AuditEvent", |e| {
            e["action"] == json!("R") && e["entity"][0]["what"]["reference"] == json!(reference)
        });
        assert!(found, "expected an AuditEvent (action R) for {reference}");
    }

    #[tokio::test]
    async fn metadata_returns_a_capability_statement() {
        let (code, Json(cap)) = metadata().await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(cap["resourceType"], "CapabilityStatement");
        assert_eq!(cap["fhirVersion"], "4.0.1");
        // Patient must appear among the advertised resources.
        let types: Vec<&str> = cap["rest"][0]["resource"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"Patient"));
        assert!(types.contains(&"DocumentReference"));
    }

    /// Audit/provenance records each get a fresh uuid, so they're found by
    /// listing the type and matching a predicate, not by a known id.
    fn find_by(store: &SharedStore, resource_type: &str, pred: impl Fn(&Value) -> bool) -> bool {
        store.list(resource_type).unwrap().iter().any(pred)
    }
}
