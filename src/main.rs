//! ChartCraft — FHIR-native EMR core.
//!
//! Generic CRUD plus type-level search over any supported US Core resource type,
//! persisted through a `ChartStore` (SQLite for the real binary, in-memory for
//! tests), with a governance spine — a `Provenance` and an `AuditEvent` on every
//! create/update, an `AuditEvent` on every read and search — plus a `/metadata`
//! CapabilityStatement. The static web frontend is served from `web/` as a
//! fallback behind the FHIR routes.
//!
//! The store is append-only and versioned: a write never overwrites: it appends a
//! new version and retains the old (history is preserved). A single atomic
//! `commit(&[WriteOp])` is the ONE write path, so a clinical resource and its
//! Provenance + AuditEvent persist all-or-nothing. Every `AuditEvent` is linked
//! into a SHA-256 hash chain that `verify_audit_chain` can recompute end-to-end,
//! and governance records (AuditEvent/Provenance) are insert-only. Patient-scoped
//! queries go through `find_by_patient` over a promoted, indexed `patient_ref`
//! column.
//!
//! Milestone 4 adds authentication: local username/password login with argon2id
//! hashing and server-side sessions, an `AuthPrincipal` extractor gating every
//! FHIR data endpoint (`/auth/*`, `GET /`, and `/static/*` stay reachable
//! logged-out so the login page loads), and the authenticated user threaded into
//! the governance spine as the real Provenance/AuditEvent signer, replacing the
//! former fixed demo label. Encryption-at-rest and TOTP MFA are still pending.

mod audit;
mod auth;
mod fhir;
mod store;

use std::sync::Arc;

use axum::{
    extract::{FromRef, Path, RawQuery, State},
    http::{header::SET_COOKIE, StatusCode},
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tower_http::services::ServeDir;

use auth::{
    clear_session_cookie, set_session_cookie, AuthPrincipal, AuthState, Credentials,
    SqliteAuthStore,
};
use fhir::{capability_statement, is_supported, now_iso8601, operation_outcome};
use store::{ChartStore, SqliteStore, WriteOp};

type SharedStore = Arc<dyn ChartStore>;

/// Shared application state: the FHIR `ChartStore` and the auth runtime, kept
/// cleanly separate. Cheap to `Clone` (both fields are `Arc`). Existing handlers
/// keep taking `State<SharedStore>` via the `FromRef` impls below, so M4 adds the
/// auth field without churning their signatures.
#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub auth: Arc<AuthState>,
}

impl FromRef<AppState> for SharedStore {
    fn from_ref(app: &AppState) -> SharedStore {
        app.store.clone()
    }
}

impl FromRef<AppState> for Arc<AuthState> {
    fn from_ref(app: &AppState) -> Arc<AuthState> {
        app.auth.clone()
    }
}

/// POST /:resource_type — assign a uuid id, stamp resourceType, store, 201.
async fn create_resource(
    AuthPrincipal(principal): AuthPrincipal,
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

    write(&store, &resource_type, &id, &body, &principal)
}

/// PUT /:resource_type/:id — upsert at a client-chosen id, bump version, 200/201.
async fn update_resource(
    AuthPrincipal(principal): AuthPrincipal,
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

    write(&store, &resource_type, &id, &body, &principal)
}

/// GET /:resource_type/:id — read, logging an AuditEvent, or 404 OperationOutcome.
async fn read_resource(
    AuthPrincipal(principal): AuthPrincipal,
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
            if let Err(e) = store.commit(&[audit::audit_read_op(&resource_type, &id, &principal)]) {
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
    AuthPrincipal(principal): AuthPrincipal,
    State(store): State<SharedStore>,
    Path(resource_type): Path<String>,
    RawQuery(query): RawQuery,
) -> (StatusCode, Json<Value>) {
    if !is_supported(&resource_type) {
        return unsupported(&resource_type);
    }

    let patient = query.as_deref().and_then(patient_param);

    // The `?patient=` path goes through the indexed `find_by_patient` primitive
    // (promoted `patient_ref` column) instead of list()+in-handler filter; the
    // no-filter picker case keeps list(). An empty `patient=` → `Some("")` →
    // find_by_patient(type, "") returns empty by an explicit guard (B3), so an
    // empty patient filter returns an empty searchset — the PHI boundary is
    // enforced in the store, not left to depend on the data.
    let resources = match &patient {
        Some(p) => store.find_by_patient(&resource_type, p),
        None => store.list(&resource_type),
    };
    let resources = match resources {
        Ok(v) => v,
        Err(e) => return server_error(&e.to_string()),
    };

    let entries: Vec<Value> = resources
        .into_iter()
        .map(|resource| json!({ "resource": resource }))
        .collect();

    // Audit the search as one event, then surface the Bundle. As with reads, a
    // failure to audit must not leak PHI, so it becomes a 500.
    if let Err(e) = store.commit(&[audit::audit_search_op(
        &resource_type,
        patient.as_deref(),
        &principal,
    )]) {
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
        // through to `find_by_patient(type, "")`, which returns empty by an
        // explicit guard (B3) — so an empty filter returns an empty searchset, not
        // every patient's resources. Dropping it here would re-open that
        // cross-patient PHI overexposure. Only a wholly absent param → None.
        pair.strip_prefix("patient=").map(|v| v.to_string())
    })
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
    AuthPrincipal(principal): AuthPrincipal,
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

    // Diagnoses: the patient's Conditions, fetched through the indexed
    // `find_by_patient` primitive (promoted patient_ref), then narrowed to the
    // billable active problem list in-handler. The index handles *whose*
    // Conditions; is_billable_condition handles *which* of them bill.
    let conditions = match store.find_by_patient("Condition", &id) {
        Ok(v) => v,
        Err(e) => return server_error(&e.to_string()),
    };
    let diagnoses: Vec<Value> = conditions
        .into_iter()
        .filter(is_billable_condition)
        .map(|c| json!({ "text": c["code"]["text"] }))
        .collect();

    // Audit the PHI read before returning data. The `<id>/$superbill` entity
    // distinguishes a superbill read from a plain read. Auditing failure is a
    // 500, never a body returned unlogged (matches reads).
    if let Err(e) = store.commit(&[audit::audit_read_op(
        "Patient",
        &format!("{id}/$superbill"),
        &principal,
    )]) {
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

/// GET /metadata — the FHIR CapabilityStatement for this server. Gated: it
/// describes the server's PHI surface, so it requires a valid session too
/// (`_principal` is unused beyond proving authentication).
async fn metadata(_principal: AuthPrincipal) -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(capability_statement()))
}

// --- auth handlers ----------------------------------------------------------

/// The success body shared by register/login/me: the public user identity.
fn principal_json(p: &auth::Principal) -> Value {
    json!({"id": p.id, "username": p.username, "displayName": p.display_name})
}

/// A JSON error with a `{"error": ...}` shape, for the auth endpoints (the
/// frontend codes against this, not an OperationOutcome).
fn auth_error(code: StatusCode, message: &str) -> axum::response::Response {
    (code, Json(json!({"error": message}))).into_response()
}

/// POST /auth/register — BOOTSTRAP ONLY. Allowed only when zero users exist:
/// creates the first admin, auto-logs them in (sets the session cookie), 201.
/// Once any user exists, registration is closed → 403.
async fn register(
    State(auth): State<Arc<AuthState>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let creds = Credentials::from_value(&body);
    match auth.no_users_yet() {
        Ok(true) => {}
        Ok(false) => {
            return auth_error(StatusCode::FORBIDDEN, "registration is closed");
        }
        Err(e) => return auth_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }

    let principal = match auth.register(&creds) {
        Ok(p) => p,
        // UsernameTaken can only mean a concurrent bootstrap won the race.
        Err(auth::AuthError::UsernameTaken) => {
            return auth_error(StatusCode::FORBIDDEN, "registration is closed");
        }
        Err(e) => return auth_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let body = principal_json(&principal);
    let token = auth.create_session(principal);
    (
        StatusCode::CREATED,
        AppendHeaders([(SET_COOKIE, set_session_cookie(&token))]),
        Json(body),
    )
        .into_response()
}

/// POST /auth/login — verify credentials; on success set the session cookie and
/// return the user, 200. On failure return a GENERIC 401 (no hint whether the
/// username or the password was wrong — no user enumeration).
async fn login(
    State(auth): State<Arc<AuthState>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let creds = Credentials::from_value(&body);
    match auth.verify(&creds.username, &creds.password) {
        Ok(Some(principal)) => {
            let body = principal_json(&principal);
            let token = auth.create_session(principal);
            (
                StatusCode::OK,
                AppendHeaders([(SET_COOKIE, set_session_cookie(&token))]),
                Json(body),
            )
                .into_response()
        }
        Ok(None) => auth_error(StatusCode::UNAUTHORIZED, "invalid username or password"),
        Err(e) => auth_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// POST /auth/logout — invalidate the session (if any) and clear the cookie, 204.
async fn logout(
    State(auth): State<Arc<AuthState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if let Some(token) = auth::session_token_from_headers(&headers) {
        auth.destroy_session(&token);
    }
    (
        StatusCode::NO_CONTENT,
        AppendHeaders([(SET_COOKIE, clear_session_cookie())]),
    )
        .into_response()
}

/// GET /auth/me — the current session's user, 200; or 401 if unauthenticated.
/// Takes `AuthPrincipal` so the extractor supplies the 401 on a missing/invalid
/// session (as a JSON OperationOutcome, same as the gated FHIR routes).
async fn me(AuthPrincipal(principal): AuthPrincipal) -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(principal_json(&principal)))
}

// --- shared handler logic ---------------------------------------------------

/// Validate the type, then persist the resource, its Provenance, and its
/// AuditEvent in ONE atomic `commit` — all-or-nothing, so a resource is never
/// left without its governance records. Returns 201 on create / 200 on update,
/// or an OperationOutcome error.
fn write(
    store: &SharedStore,
    resource_type: &str,
    id: &str,
    body: &Value,
    principal: &auth::Principal,
) -> (StatusCode, Json<Value>) {
    // The "C"/"U" AUDIT LABEL is baked into the audit WriteOp before `commit`
    // runs (before the version is known), so it's still decided from a pre-commit
    // get(): a fresh id → create, an existing one → update.
    //
    // ponytail: the C/U audit LABEL can still be wrong under a concurrent
    // first-write race — two first-PUTs to the same id could both read "no current
    // version" and both log "C". The HTTP STATUS below is now race-free (derived
    // from the version commit returns), but fully fixing the label needs the audit
    // op to learn its version after commit, which means restructuring the write
    // path — an M4 (auth) concern. Status is fixed now; label defers to M4.
    let is_create = match store.get(resource_type, id) {
        Ok(existing) => existing.is_none(),
        Err(e) => return server_error(&e.to_string()),
    };
    let action = if is_create { "C" } else { "U" };

    // Resource + Provenance + AuditEvent persist together or not at all. The
    // resource op is batch[0], so versions[0] is its committed version.
    let batch = vec![
        WriteOp::new(resource_type, id, body.clone()),
        audit::provenance_op(resource_type, id, principal),
        audit::audit_write_op(resource_type, id, action, principal),
    ];
    let versions = match store.commit(&batch) {
        Ok(v) => v,
        Err(e) => return server_error(&e.to_string()),
    };

    // FHIR: 201 when this write CREATED the resource, 200 when it updated one.
    // Derived from the version `commit` actually assigned (version 1 → created),
    // computed AFTER the commit — so the status can't disagree with what persisted,
    // even if a concurrent first-write raced the pre-commit get() above.
    let code = if versions[0] == 1 {
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

fn app(state: AppState) -> Router {
    Router::new()
        // Auth endpoints — EXEMPT from the session gate (none take AuthPrincipal
        // except `me`, which uses it to produce its own 401). Literal 2-segment
        // routes like `/auth/login` win over the `/:resource_type/:id` param route
        // in axum's router, so they are never shadowed by the FHIR CRUD path.
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
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
        // Static assets under a reserved literal prefix — EXEMPT from auth so the
        // login page's CSS/JS load logged-out. A literal segment (`/static`) wins
        // over the `/:resource_type` param route; a `ServeDir` service takes no
        // `AuthPrincipal`, so it is never gated.
        .nest_service("/static", ServeDir::new("web"))
        .with_state(state)
        // Fallback serves `web/index.html` for `GET /` (and any other unmatched
        // path) — EXEMPT so the UI shell / login screen loads logged-out. The FHIR
        // routes and /static above win first.
        .fallback_service(ServeDir::new("web"))
}

#[tokio::main]
async fn main() {
    let store: SharedStore =
        Arc::new(SqliteStore::open("chartcraft.db").expect("open chartcraft.db"));
    // Auth store shares the db FILE but owns its own connection — the clinical
    // store and the auth store stay cleanly separated.
    let auth_store = SqliteAuthStore::open("chartcraft.db").expect("open auth store");
    let state = AppState {
        store,
        auth: Arc::new(AuthState::new(Box::new(auth_store))),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind 127.0.0.1:8080");
    println!(
        "ChartCraft M4 on http://127.0.0.1:8080 \
         (auth at /auth/*, POST/GET /:resource_type, GET/PUT /:resource_type/:id, \
         GET /Patient/:id/$superbill, GET /metadata, static web/ at /)"
    );
    axum::serve(listener, app(state)).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth::{AuthPrincipal, InMemoryAuthStore, Principal};

    fn mem_store() -> SharedStore {
        Arc::new(SqliteStore::open_in_memory().expect("in-memory sqlite"))
    }

    /// A fixed test principal: the handlers now take an `AuthPrincipal`, so the
    /// direct-call tests (which bypass the extractor/routing) construct one.
    fn test_principal() -> AuthPrincipal {
        AuthPrincipal(Principal {
            id: "test-user-1".into(),
            username: "dr.test".into(),
            display_name: "Dr Test".into(),
        })
    }

    /// Build the full `AppState` for router-level tests (unauth gate, cookies).
    fn mem_app_state() -> AppState {
        AppState {
            store: mem_store(),
            auth: Arc::new(AuthState::new(Box::new(InMemoryAuthStore::default()))),
        }
    }

    #[tokio::test]
    async fn sqlite_roundtrips_two_resource_types() {
        let store = mem_store();

        // A Patient...
        let (code, Json(patient)) = create_resource(
            test_principal(),
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Sharma"}]})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let patient_id = patient["id"].as_str().unwrap().to_string();
        assert_eq!(patient["resourceType"], "Patient");

        let (code, Json(got)) = read_resource(
            test_principal(),
            State(store.clone()),
            Path(("Patient".into(), patient_id.clone())),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(got["name"][0]["family"], "Sharma");

        // ...and a Condition, different type, same store.
        let (code, Json(cond)) = create_resource(
            test_principal(),
            State(store.clone()),
            Path("Condition".into()),
            Json(json!({"code": {"text": "Hypertension"}})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let cond_id = cond["id"].as_str().unwrap().to_string();

        let (code, Json(got)) =
            read_resource(test_principal(), State(store.clone()), Path(("Condition".into(), cond_id))).await;
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
            test_principal(),
            State(store.clone()),
            Path(("Observation".into(), "obs-2".into())),
            Json(json!({"status": "final"})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);

        let (code, _) = update_resource(
            test_principal(),
            State(store.clone()),
            Path(("Observation".into(), "obs-2".into())),
            Json(json!({"status": "amended"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
    }

    /// B2: the HTTP status is driven by the version `commit` returns — version 1
    /// → 201 Created, a later version → 200 OK — not by the racy pre-commit get().
    #[tokio::test]
    async fn write_status_follows_committed_version() {
        let store = mem_store();

        // First write at a fresh id commits version 1 → 201.
        let (code, _) = update_resource(
            test_principal(),
            State(store.clone()),
            Path(("Observation".into(), "ob-b2".into())),
            Json(json!({"status": "final"})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "version 1 → 201");

        // Second write at the same id commits version 2 → 200.
        let (code, _) = update_resource(
            test_principal(),
            State(store.clone()),
            Path(("Observation".into(), "ob-b2".into())),
            Json(json!({"status": "amended"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "version 2 → 200");
    }

    #[tokio::test]
    async fn resource_type_path_mismatch_is_400() {
        let store = mem_store();
        let (code, Json(oo)) = create_resource(
            test_principal(),
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
            test_principal(),
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
            test_principal(),
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
            test_principal(),
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Komi"}]})),
        )
        .await;
        let id = patient["id"].as_str().unwrap().to_string();

        let (code, _) =
            read_resource(test_principal(), State(store.clone()), Path(("Patient".into(), id.clone()))).await;
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
            test_principal(),
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
            test_principal(),
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
            test_principal(),
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
            test_principal(),
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
            test_principal(),
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
                test_principal(),
                State(store.clone()),
                Path("Patient".into()),
                Json(json!({"name": [{"family": family}]})),
            )
            .await;
            assert_eq!(code, StatusCode::CREATED);
        }

        let (code, Json(bundle)) =
            search_resources(test_principal(), State(store.clone()), Path("Patient".into()), RawQuery(None)).await;
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
            test_principal(),
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
            search_resources(test_principal(), State(store), Path("Dragon".into()), RawQuery(None)).await;
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
            test_principal(),
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
        let (code, Json(cap)) = metadata(test_principal()).await;
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
            test_principal(),
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
            superbill(test_principal(), State(store.clone()), Path(id.clone())).await;
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
            test_principal(),
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

        let (code, Json(bill)) = superbill(test_principal(), State(store.clone()), Path(id)).await;
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
            superbill(test_principal(), State(store), Path("ghost".into())).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        assert_eq!(oo["resourceType"], "OperationOutcome");
    }

    #[tokio::test]
    async fn superbill_records_an_audit_event() {
        let store = mem_store();
        let (_, Json(patient)) = create_resource(
            test_principal(),
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Rao"}]})),
        )
        .await;
        let id = patient["id"].as_str().unwrap().to_string();

        let (code, _) = superbill(test_principal(), State(store.clone()), Path(id.clone())).await;
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

    // --- M4 auth tests ------------------------------------------------------

    use axum::body::Body;
    use axum::http::{header, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt; // for `oneshot`

    /// Send a request through the full `Router` and return (status, Set-Cookie,
    /// json body). Exercises the extractor/gate and cookie headers, which the
    /// direct-call tests bypass.
    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Option<String>, Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, set_cookie, json)
    }

    /// Pull just the `name=value` pair out of a Set-Cookie header, to replay it as
    /// a Cookie on the next request.
    fn cookie_pair(set_cookie: &str) -> String {
        set_cookie.split(';').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn register_bootstraps_once_then_is_closed() {
        let state = mem_app_state();
        let auth = state.auth.clone();
        let app = app(state);

        // First registration bootstraps the admin, auto-logs-in (sets cookie), 201.
        let (code, cookie, body) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "admin", "password": "pw", "displayName": "Dr Admin"})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(body["username"], "admin");
        assert_eq!(body["displayName"], "Dr Admin");
        assert!(body["id"].is_string());
        let sc = cookie.expect("register sets a session cookie");
        assert!(sc.contains("chartcraft_session="));
        assert!(sc.contains("HttpOnly"));
        assert!(sc.contains("SameSite=Strict"));

        // A second registration is forbidden — bootstrap is one-shot.
        let (code, _, body) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "intruder", "password": "pw", "displayName": "X"})),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        assert!(body["error"].is_string(), "403 carries a JSON error");

        // The rejected register changed nothing — still exactly the one admin, and
        // the intruder can't log in (proves the second insert never landed).
        assert!(auth.no_users_yet().is_ok());
        assert_eq!(auth.no_users_yet().unwrap(), false);
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "intruder", "password": "pw"})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "the rejected register created no user");
    }

    #[tokio::test]
    async fn login_success_and_wrong_password_is_generic_401() {
        let app = app(mem_app_state());
        // Bootstrap a user first.
        send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "bob", "password": "hunter2", "displayName": "Bob"})),
        )
        .await;

        // Right password → 200 + cookie + identity.
        let (code, cookie, body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "bob", "password": "hunter2"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["username"], "bob");
        assert!(cookie.unwrap().contains("chartcraft_session="));

        // Wrong password → 401, generic message (no "wrong password" vs "no user").
        let (code, _, body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "bob", "password": "WRONG"})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        // The message names both fields together ("invalid username or password"),
        // which does NOT reveal which was wrong — the non-enumeration property is
        // that the SAME message is returned for a wrong password and an unknown
        // user (asserted below), not that it omits the word "password".
        assert!(body["error"].is_string());

        // Unknown username → same generic 401 (no user enumeration).
        let (code, _, body2) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "ghost", "password": "whatever"})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert_eq!(body2["error"], body["error"], "identical message for both failures");
    }

    #[tokio::test]
    async fn me_reflects_the_session_and_logout_clears_it() {
        let app = app(mem_app_state());
        let (_, cookie, _) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "carol", "password": "pw", "displayName": "Carol"})),
        )
        .await;
        let cookie = cookie_pair(&cookie.unwrap());

        // /auth/me with the session cookie returns the user.
        let (code, _, body) = send(&app, "GET", "/auth/me", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["username"], "carol");

        // /auth/me with NO cookie is 401.
        let (code, _, _) = send(&app, "GET", "/auth/me", None, None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);

        // Logout invalidates the session (204) and the cookie no longer resolves.
        let (code, _, _) = send(&app, "POST", "/auth/logout", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::NO_CONTENT);
        let (code, _, _) = send(&app, "GET", "/auth/me", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "session is dead after logout");
    }

    #[tokio::test]
    async fn unauthenticated_fhir_request_is_401_operation_outcome() {
        let app = app(mem_app_state());

        // No session cookie → the extractor rejects before the handler runs.
        let (code, _, body) = send(&app, "GET", "/Patient", None, None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert_eq!(body["resourceType"], "OperationOutcome");

        // A write is gated too.
        let (code, _, _) = send(
            &app,
            "POST",
            "/Patient",
            None,
            Some(json!({"name": [{"family": "NoAuth"}]})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);

        // And /metadata.
        let (code, _, _) = send(&app, "GET", "/metadata", None, None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn static_and_root_are_reachable_logged_out() {
        let app = app(mem_app_state());
        // The fallback (UI shell / login page) must NOT be gated, or the login
        // screen can never load. It serves from web/, so a 200 or 404 is fine —
        // what matters is it's NOT a 401.
        let (code, _, _) = send(&app, "GET", "/", None, None).await;
        assert_ne!(code, StatusCode::UNAUTHORIZED, "the UI shell must load logged-out");
    }

    #[tokio::test]
    async fn authenticated_write_records_the_real_principal_as_signer() {
        let store = mem_store();
        let principal = Principal {
            id: "dr-xyz".into(),
            username: "dr.xyz".into(),
            display_name: "Dr Xyz".into(),
        };

        // Write a Patient as this principal (direct handler call with a real id).
        let (code, Json(patient)) = create_resource(
            AuthPrincipal(principal.clone()),
            State(store.clone()),
            Path("Patient".into()),
            Json(json!({"name": [{"family": "Signed"}]})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let target = format!("Patient/{}", patient["id"].as_str().unwrap());

        // The Provenance signer is the logged-in user, not a demo label.
        let signed = find_by(&store, "Provenance", |p| {
            p["target"][0]["reference"] == json!(target)
                && p["agent"][0]["who"]["display"] == json!("Dr Xyz")
                && p["agent"][0]["who"]["identifier"]["value"] == json!("dr-xyz")
        });
        assert!(signed, "Provenance must record the real principal as signer");

        // The AuditEvent actor is the same real user.
        let audited = find_by(&store, "AuditEvent", |e| {
            e["action"] == json!("C")
                && e["entity"][0]["what"]["reference"] == json!(target)
                && e["agent"][0]["who"]["display"] == json!("Dr Xyz")
        });
        assert!(audited, "AuditEvent must record the real principal as actor");
    }
}
