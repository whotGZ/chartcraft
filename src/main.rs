//! ChartCraft — Milestone 3.
//!
//! A FHIR-native EMR core: generic CRUD plus type-level search over any supported
//! US Core resource type, persisted through a `ChartStore` (SQLite for the real
//! binary, in-memory for tests), with a governance spine — a `Provenance` written
//! on every create/update and an append-only `AuditEvent` on every read and
//! search — plus a `/metadata` CapabilityStatement. The static web frontend is
//! served from `web/` as a fallback behind the FHIR routes.
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
    extract::{Path, RawQuery, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tower_http::services::ServeDir;

use fhir::{capability_statement, is_supported, now_iso8601, operation_outcome};
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
    if let Some(bad) = reject_non_object(&body) {
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
    if let Some(bad) = reject_non_object(&body) {
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

/// GET /:resource_type — list/search, returning a FHIR `Bundle` of type
/// `searchset`. An optional `?patient=<id>` filters to resources that reference
/// that patient via either `subject.reference` or `patient.reference` (different
/// US Core types use different fields).
async fn search_resources(
    State(store): State<SharedStore>,
    Path(resource_type): Path<String>,
    RawQuery(query): RawQuery,
) -> (StatusCode, Json<Value>) {
    if !is_supported(&resource_type) {
        return unsupported(&resource_type);
    }

    let patient = query.as_deref().and_then(patient_param);

    let all = match store.list(&resource_type) {
        Ok(v) => v,
        Err(e) => return server_error(&e.to_string()),
    };

    let entries: Vec<Value> = all
        .into_iter()
        .filter(|r| match &patient {
            Some(p) => references_patient(r, p),
            None => true,
        })
        .map(|resource| json!({ "resource": resource }))
        .collect();

    // Audit the search as one event, then surface the Bundle. As with reads, a
    // failure to audit must not leak PHI, so it becomes a 500.
    if let Err(e) = audit::record_audit_search(store.as_ref(), &resource_type, patient.as_deref()) {
        return server_error(&e.to_string());
    }

    let bundle = json!({
        "resourceType": "Bundle",
        "type": "searchset",
        "total": entries.len(),
        "entry": entries,
    });
    (StatusCode::OK, Json(bundle))
}

/// Parse `?patient=<id>` out of a raw query string, if present. Returns the
/// (percent-literal) id; ids are server-assigned uuids, so no decoding is needed.
fn patient_param(query: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        // A present-but-empty `patient=` must NOT be dropped: a `Some("")` flows
        // through to `references_patient`, which builds target "Patient/" and
        // matches nothing — so an empty filter returns an empty searchset, not
        // every patient's resources. Dropping it here would re-open that
        // cross-patient PHI overexposure. Only a wholly absent param → None.
        pair.strip_prefix("patient=").map(|v| v.to_string())
    })
}

/// True if a resource references `Patient/<id>` through either `subject.reference`
/// or `patient.reference`.
fn references_patient(resource: &Value, id: &str) -> bool {
    let target = format!("Patient/{id}");
    let matches = |field: &str| {
        resource[field]["reference"].as_str() == Some(target.as_str())
    };
    matches("subject") || matches("patient")
}

/// True if a Condition belongs on a billable "active problem list": clinically
/// active AND not an erroneous record.
///
/// `clinicalStatus` is `mustSupport` (not required) in US Core, so a Condition may
/// legitimately carry none — we treat an ABSENT status as billable rather than
/// silently dropping real problems. When present, only active-family codes
/// (`active`/`recurrence`/`relapse`) count; `resolved`/`inactive`/`remission` do not.
/// Separately, a `verificationStatus` of `entered-in-error`/`refuted` marks the
/// record itself as bogus, so it's excluded regardless of clinical status.
fn is_billable_condition(c: &Value) -> bool {
    let clinical_ok = match c["clinicalStatus"]["coding"][0]["code"].as_str() {
        None => true, // absent status: mustSupport, not required — keep it
        Some(code) => matches!(code, "active" | "recurrence" | "relapse"),
    };
    let verification_ok = !matches!(
        c["verificationStatus"]["coding"][0]["code"].as_str(),
        Some("entered-in-error") | Some("refuted")
    );
    clinical_ok && verification_ok
}

/// GET /Patient/:id/$superbill — a coded-charge (superbill) export for one
/// patient, as a FHIR instance operation. Reads the Patient and their active
/// Conditions and returns a fixed-shape JSON document the frontend codes against:
/// patient identity, today's date, the derived diagnosis list, and a placeholder
/// E/M charge. Reading it touches PHI, so it records one `AuditEvent`.
async fn superbill(
    State(store): State<SharedStore>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let patient = match store.get("Patient", &id) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(operation_outcome(
                    "error",
                    "not-found",
                    &format!("Patient/{id} not found"),
                )),
            )
        }
        Err(e) => return server_error(&e.to_string()),
    };

    // Diagnoses: the patient's Conditions, matched with the SAME helper the
    // search handler uses (subject.reference OR patient.reference == Patient/id).
    let conditions = match store.list("Condition") {
        Ok(v) => v,
        Err(e) => return server_error(&e.to_string()),
    };
    let diagnoses: Vec<Value> = conditions
        .into_iter()
        .filter(|c| references_patient(c, &id) && is_billable_condition(c))
        .map(|c| json!({ "text": c["code"]["text"] }))
        .collect();

    // Audit the PHI read before returning data, reusing the read helper. The
    // `<id>/$superbill` entity distinguishes a superbill read from a plain read.
    // Auditing failure is a 500, never a body returned unlogged (matches reads).
    if let Err(e) = audit::record_audit_read(store.as_ref(), "Patient", &format!("{id}/$superbill"))
    {
        return server_error(&e.to_string());
    }

    let body = json!({
        "patient": {
            "id": id,
            "name": patient_display_name(&patient),
            // birthDate only when the Patient carries one.
            "birthDate": patient["birthDate"],
        },
        "date": now_iso8601(),
        "diagnoses": diagnoses,
        // ponytail: fixed placeholder E/M. Real MDM/time-based leveling (picking
        // 99212–99215 from the chart) is future work; for now one hard-coded code.
        "charge": {
            "cpt": "99214",
            "description": "Office/outpatient visit, established patient, moderate MDM",
        },
        "note": "Diagnoses are derived from the chart's active problem list. \
                 The E/M level is a placeholder pending MDM-based leveling.",
    });

    // Drop birthDate when the Patient had none, honoring the "if present" contract.
    let mut body = body;
    if body["patient"]["birthDate"].is_null() {
        body["patient"]
            .as_object_mut()
            .expect("patient is an object")
            .remove("birthDate");
    }

    (StatusCode::OK, Json(body))
}

/// A human display name from a FHIR Patient's `name[0]`, using the same
/// FHIR-conventional precedence as the frontend so the chart header and the
/// superbill never disagree: prefer `name[0].text`, else given tokens joined with
/// the family name, else an empty string.
fn patient_display_name(patient: &Value) -> String {
    let name = &patient["name"][0];
    if let Some(text) = name["text"].as_str() {
        if !text.is_empty() {
            return text.to_string();
        }
    }
    let mut parts: Vec<String> = name["given"]
        .as_array()
        .map(|g| g.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
        .unwrap_or_default();
    if let Some(family) = name["family"].as_str() {
        parts.push(family.to_string());
    }
    parts.join(" ")
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
    // A write is a PHI touch, so it must be audited too (Provenance attributes,
    // AuditEvent logs the access). "C" on a create (version 1), "U" on update.
    // As with reads, a failure to audit must not return a body unlogged — 500.
    let action = if version == 1 { "C" } else { "U" };
    if let Err(e) = audit::record_audit_write(store.as_ref(), resource_type, id, action) {
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

/// 400 if the parsed body isn't a JSON object. A non-object (array/string/number)
/// would panic on `body["resourceType"] = ...` (serde_json `IndexMut` only works
/// on objects), so reject it before any such mutation. `None` to proceed.
fn reject_non_object(body: &Value) -> Option<(StatusCode, Json<Value>)> {
    if body.is_object() {
        return None;
    }
    Some((
        StatusCode::BAD_REQUEST,
        Json(operation_outcome(
            "error",
            "invalid",
            "request body must be a FHIR resource (JSON object)",
        )),
    ))
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
        // Instance operation: a 3-segment literal-tail route. It does NOT collide
        // with the 2-segment `/:resource_type/:id` param route below; axum matches
        // by segment count, so this wins for `/Patient/<id>/$superbill`.
        .route("/Patient/:id/$superbill", get(superbill))
        .route(
            "/:resource_type",
            post(create_resource).get(search_resources),
        )
        .route(
            "/:resource_type/:id",
            get(read_resource).put(update_resource),
        )
        // Static assets under a reserved literal prefix. A literal segment
        // (`/static`) wins over the `/:resource_type` param route in axum's
        // router, so CSS/JS are served here instead of being shadowed by search.
        .nest_service("/static", ServeDir::new("web"))
        .with_state(store)
        // Fallback serves `web/index.html` for `GET /` (and any other unmatched
        // path). The FHIR routes and /static above win first.
        .fallback_service(ServeDir::new("web"))
}

#[tokio::main]
async fn main() {
    let store: SharedStore =
        Arc::new(SqliteStore::open("chartcraft.db").expect("open chartcraft.db"));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind 127.0.0.1:8080");
    println!(
        "ChartCraft M3 on http://127.0.0.1:8080 \
         (POST/GET /:resource_type, GET/PUT /:resource_type/:id, \
         GET /Patient/:id/$superbill, GET /metadata, static web/ at /)"
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
    async fn create_records_a_c_audit_event_and_update_records_a_u() {
        let store = mem_store();

        // A create (first write of this id) must log a "C" AuditEvent.
        let (code, Json(patient)) = create_resource(
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Audit"}]})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let id = patient["id"].as_str().unwrap().to_string();
        let reference = format!("Patient/{id}");

        let created = find_by(&store, "AuditEvent", |e| {
            e["action"] == json!("C") && e["entity"][0]["what"]["reference"] == json!(reference)
        });
        assert!(created, "a create must record a 'C' AuditEvent for {reference}");

        // A PUT at that same id updates it (version 2) → must log a "U" AuditEvent.
        let (code, _) = update_resource(
            State(store.clone()),
            Path(("Patient".into(), id.clone())),
            Json(json!({"name": [{"family": "Audited"}]})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);

        let updated = find_by(&store, "AuditEvent", |e| {
            e["action"] == json!("U") && e["entity"][0]["what"]["reference"] == json!(reference)
        });
        assert!(updated, "a PUT-update must record a 'U' AuditEvent for {reference}");
    }

    #[tokio::test]
    async fn non_object_body_is_400_not_a_panic() {
        let store = mem_store();
        // A JSON array as the body would panic on `body["resourceType"] = ...`;
        // it must be rejected as 400 instead.
        let (code, Json(oo)) = create_resource(
            State(store),
            Path("Patient".into()),
            Json(json!([1, 2, 3])),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(oo["resourceType"], "OperationOutcome");
    }

    #[tokio::test]
    async fn empty_patient_param_returns_an_empty_bundle() {
        let store = mem_store();
        // Store a Condition that WOULD be returned by a bare type search.
        store
            .put(
                "Condition",
                "c1",
                &json!({
                    "resourceType": "Condition",
                    "subject": {"reference": "Patient/alice"},
                    "code": {"text": "Hypertension"},
                }),
            )
            .unwrap();

        // `?patient=` present but empty must match NOTHING, not everything.
        let (code, Json(bundle)) = search_resources(
            State(store.clone()),
            Path("Condition".into()),
            RawQuery(Some("patient=".into())),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(bundle["type"], "searchset");
        assert_eq!(bundle["total"], 0, "empty patient filter must return nothing");
        assert!(bundle["entry"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn encounter_is_an_accepted_type() {
        let store = mem_store();
        // MF-11: the architecture doc advertises Encounter; POST must be accepted.
        let (code, Json(enc)) = create_resource(
            State(store),
            Path("Encounter".into()),
            Json(json!({"status": "finished"})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(enc["resourceType"], "Encounter");
    }

    #[tokio::test]
    async fn get_type_returns_a_searchset_bundle() {
        let store = mem_store();
        for family in ["Sharma", "Rao", "Komi"] {
            let (code, _) = create_resource(
                State(store.clone()),
                Path("Patient".into()),
                Json(json!({"name": [{"family": family}]})),
            )
            .await;
            assert_eq!(code, StatusCode::CREATED);
        }

        let (code, Json(bundle)) =
            search_resources(State(store.clone()), Path("Patient".into()), RawQuery(None)).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(bundle["resourceType"], "Bundle");
        assert_eq!(bundle["type"], "searchset");
        assert_eq!(bundle["total"], 3);
        assert_eq!(bundle["entry"].as_array().unwrap().len(), 3);
        // Each entry wraps the resource under "resource".
        assert_eq!(bundle["entry"][0]["resource"]["resourceType"], "Patient");
    }

    #[tokio::test]
    async fn patient_filter_matches_subject_and_patient_references() {
        let store = mem_store();

        // A Condition for Alice via subject.reference (the field Condition uses).
        store
            .put(
                "Condition",
                "c-alice-subj",
                &json!({
                    "resourceType": "Condition",
                    "subject": {"reference": "Patient/alice"},
                    "code": {"text": "Hypertension"},
                }),
            )
            .unwrap();
        // A Condition for Alice that instead carries patient.reference — proves we
        // match BOTH fields, since different resource types populate different ones.
        store
            .put(
                "Condition",
                "c-alice-pat",
                &json!({
                    "resourceType": "Condition",
                    "patient": {"reference": "Patient/alice"},
                    "code": {"text": "Diabetes"},
                }),
            )
            .unwrap();
        // A Condition for a DIFFERENT patient must be excluded.
        store
            .put(
                "Condition",
                "c-bob",
                &json!({
                    "resourceType": "Condition",
                    "subject": {"reference": "Patient/bob"},
                    "code": {"text": "Asthma"},
                }),
            )
            .unwrap();

        let (code, Json(bundle)) = search_resources(
            State(store.clone()),
            Path("Condition".into()),
            RawQuery(Some("patient=alice".into())),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(bundle["total"], 2, "both of Alice's Conditions, neither of Bob's");

        // Confirm Bob's Condition is not present.
        let texts: Vec<&str> = bundle["entry"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["resource"]["code"]["text"].as_str().unwrap())
            .collect();
        assert!(texts.contains(&"Hypertension"));
        assert!(texts.contains(&"Diabetes"));
        assert!(!texts.contains(&"Asthma"));
    }

    #[tokio::test]
    async fn search_of_unknown_type_is_400() {
        let store = mem_store();
        let (code, Json(oo)) =
            search_resources(State(store), Path("Dragon".into()), RawQuery(None)).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(oo["resourceType"], "OperationOutcome");
    }

    #[tokio::test]
    async fn search_records_exactly_one_audit_event() {
        let store = mem_store();
        // Two matching resources; the search must still log ONE AuditEvent, not one per hit.
        for id in ["o1", "o2"] {
            store
                .put(
                    "Observation",
                    id,
                    &json!({
                        "resourceType": "Observation",
                        "subject": {"reference": "Patient/zed"},
                    }),
                )
                .unwrap();
        }

        let (code, _) = search_resources(
            State(store.clone()),
            Path("Observation".into()),
            RawQuery(Some("patient=zed".into())),
        )
        .await;
        assert_eq!(code, StatusCode::OK);

        let search_events: Vec<Value> = store
            .list("AuditEvent")
            .unwrap()
            .into_iter()
            .filter(|e| e["action"] == json!("E"))
            .collect();
        assert_eq!(
            search_events.len(),
            1,
            "a search records exactly one AuditEvent, not one per matched resource"
        );
        assert_eq!(
            search_events[0]["entity"][0]["what"]["reference"],
            "Observation?patient=zed"
        );
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
        // MF-11: the newly-supported types must also be advertised.
        assert!(types.contains(&"Encounter"));
        assert!(types.contains(&"ServiceRequest"));
        assert!(types.contains(&"DiagnosticReport"));

        // M2: every resource must advertise the search-type interaction.
        for resource in cap["rest"][0]["resource"].as_array().unwrap() {
            let codes: Vec<&str> = resource["interaction"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["code"].as_str().unwrap())
                .collect();
            assert!(
                codes.contains(&"search-type"),
                "{} should advertise search-type",
                resource["type"]
            );
        }
    }

    #[tokio::test]
    async fn superbill_lists_the_patients_active_diagnoses_and_name() {
        let store = mem_store();

        // A patient with a given+family name and a birthDate.
        let (_, Json(patient)) = create_resource(
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({
                "name": [{"given": ["Eleanor", "M"], "family": "Whitfield"}],
                "birthDate": "1948-03-21",
            })),
        )
        .await;
        let id = patient["id"].as_str().unwrap().to_string();

        // Two Conditions for this patient (one via subject, one via patient ref)...
        store
            .put(
                "Condition",
                "c1",
                &json!({
                    "resourceType": "Condition",
                    "subject": {"reference": format!("Patient/{id}")},
                    "code": {"text": "Essential hypertension"},
                }),
            )
            .unwrap();
        store
            .put(
                "Condition",
                "c2",
                &json!({
                    "resourceType": "Condition",
                    "patient": {"reference": format!("Patient/{id}")},
                    "code": {"text": "Type 2 diabetes mellitus"},
                }),
            )
            .unwrap();
        // ...and one for someone else, which must NOT appear.
        store
            .put(
                "Condition",
                "c3",
                &json!({
                    "resourceType": "Condition",
                    "subject": {"reference": "Patient/someone-else"},
                    "code": {"text": "Asthma"},
                }),
            )
            .unwrap();

        let (code, Json(bill)) =
            superbill(State(store.clone()), Path(id.clone())).await;
        assert_eq!(code, StatusCode::OK);

        assert_eq!(bill["patient"]["id"], id);
        assert_eq!(bill["patient"]["name"], "Eleanor M Whitfield");
        assert_eq!(bill["patient"]["birthDate"], "1948-03-21");
        assert_eq!(bill["charge"]["cpt"], "99214");

        let texts: Vec<&str> = bill["diagnoses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["text"].as_str().unwrap())
            .collect();
        assert_eq!(texts.len(), 2, "exactly the patient's two Conditions");
        assert!(texts.contains(&"Essential hypertension"));
        assert!(texts.contains(&"Type 2 diabetes mellitus"));
        assert!(!texts.contains(&"Asthma"), "another patient's Condition must be excluded");
    }

    #[tokio::test]
    async fn superbill_excludes_resolved_and_entered_in_error_conditions() {
        let store = mem_store();

        let (_, Json(patient)) = create_resource(
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Okafor"}]})),
        )
        .await;
        let id = patient["id"].as_str().unwrap().to_string();
        let subject = json!({"reference": format!("Patient/{id}")});

        // Active (no clinicalStatus at all) — US Core mustSupport, so this MUST bill.
        store
            .put(
                "Condition",
                "c-active",
                &json!({
                    "resourceType": "Condition",
                    "subject": subject,
                    "code": {"text": "Essential hypertension"},
                }),
            )
            .unwrap();
        // Resolved — clinically inactive, MUST be excluded.
        store
            .put(
                "Condition",
                "c-resolved",
                &json!({
                    "resourceType": "Condition",
                    "subject": subject,
                    "clinicalStatus": {"coding": [{"code": "resolved"}]},
                    "code": {"text": "Acute bronchitis"},
                }),
            )
            .unwrap();
        // Entered-in-error — bogus record, MUST be excluded regardless of status.
        store
            .put(
                "Condition",
                "c-error",
                &json!({
                    "resourceType": "Condition",
                    "subject": subject,
                    "verificationStatus": {"coding": [{"code": "entered-in-error"}]},
                    "code": {"text": "Keyed in error"},
                }),
            )
            .unwrap();

        let (code, Json(bill)) = superbill(State(store.clone()), Path(id)).await;
        assert_eq!(code, StatusCode::OK);

        let texts: Vec<&str> = bill["diagnoses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["text"].as_str().unwrap())
            .collect();
        assert_eq!(texts, vec!["Essential hypertension"], "only the active Condition bills");
        assert!(!texts.contains(&"Acute bronchitis"), "resolved Condition must be excluded");
        assert!(!texts.contains(&"Keyed in error"), "entered-in-error Condition must be excluded");
    }

    #[tokio::test]
    async fn superbill_for_missing_patient_is_404_operation_outcome() {
        let store = mem_store();
        let (code, Json(oo)) =
            superbill(State(store), Path("ghost".into())).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        assert_eq!(oo["resourceType"], "OperationOutcome");
    }

    #[tokio::test]
    async fn superbill_records_an_audit_event() {
        let store = mem_store();
        let (_, Json(patient)) = create_resource(
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Rao"}]})),
        )
        .await;
        let id = patient["id"].as_str().unwrap().to_string();

        let (code, _) = superbill(State(store.clone()), Path(id.clone())).await;
        assert_eq!(code, StatusCode::OK);

        // One read AuditEvent whose entity marks it as the superbill read.
        let reference = format!("Patient/{id}/$superbill");
        let found = find_by(&store, "AuditEvent", |e| {
            e["action"] == json!("R") && e["entity"][0]["what"]["reference"] == json!(reference)
        });
        assert!(found, "expected an AuditEvent (action R) for {reference}");
    }

    /// Audit/provenance records each get a fresh uuid, so they're found by
    /// listing the type and matching a predicate, not by a known id.
    fn find_by(store: &SharedStore, resource_type: &str, pred: impl Fn(&Value) -> bool) -> bool {
        store.list(resource_type).unwrap().iter().any(pred)
    }
}
