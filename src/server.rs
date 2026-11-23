//! The HTTP layer: application state, the axum handlers, the auth extractors'
//! wiring (`FromRef`), the shared `write()` governance path, demo seeding, and
//! [`core_router`] — the full FHIR + auth + static core router a downstream crate
//! merges its own routes onto.

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

use crate::audit;
use crate::auth::{
    self, clear_session_cookie, set_session_cookie, AuthLevel, AuthPrincipal, AuthState,
    Credentials, MfaPrincipal,
};
use crate::fhir::{capability_statement, is_supported, now_iso8601, operation_outcome};
use crate::store::{ChartStore, WriteOp};

/// The shared clinical store, type-erased behind an `Arc`. A downstream crate
/// reads FHIR resources through the [`ChartStore`] trait on this handle.
pub type SharedStore = Arc<dyn ChartStore>;

/// Shared application state: the FHIR `ChartStore` and the auth runtime, kept
/// cleanly separate. Cheap to `Clone` (both fields are `Arc`). Existing handlers
/// keep taking `State<SharedStore>` via the `FromRef` impls below, so M4 adds the
/// auth field without churning their signatures.
#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub auth: Arc<AuthState>,
    /// Demo mode (CHARTCRAFT_DEMO truthy). When set, a password login of a user
    /// who has NOT enrolled TOTP is granted a `Full` session instead of
    /// `PendingMfa` — so the seeded demo user reaches the chart without an
    /// authenticator. ZERO effect when unset: the default path keeps enforced MFA.
    pub demo: bool,
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

/// The success body shared by register/login/me: the public user identity plus
/// its MFA state. `mfa_enrolled` is read fresh from the store (it flips at
/// confirm), and `level` is the session's current auth level.
fn principal_json(p: &auth::Principal, mfa_enrolled: bool, level: AuthLevel) -> Value {
    json!({
        "id": p.id,
        "username": p.username,
        "displayName": p.display_name,
        "mfaEnrolled": mfa_enrolled,
        "authLevel": level.as_str(),
    })
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
        // MF-4: real error logged server-side, generic body to the client.
        Err(e) => return auth_server_error(&e.to_string()),
    }

    // MF-1: `register` does argon2 hashing (CPU-bound). Run it on the blocking
    // pool so a flood of registers can't starve the tokio runtime. Validation
    // (MF-3) lives inside `AuthState::register`, so it runs here too.
    let auth2 = auth.clone();
    let register_result = tokio::task::spawn_blocking(move || auth2.register(&creds))
        .await
        .expect("register task");
    let principal = match register_result {
        Ok(p) => p,
        // UsernameTaken can only mean a concurrent bootstrap won the race.
        Err(auth::AuthError::UsernameTaken) => {
            return auth_error(StatusCode::FORBIDDEN, "registration is closed");
        }
        // MF-3: validation failure → 400 with the (safe, policy-naming) message.
        Err(auth::AuthError::InvalidInput(msg)) => {
            return auth_error(StatusCode::BAD_REQUEST, msg);
        }
        // MF-4: DB/store error logged server-side, generic body to the client.
        Err(e) => return auth_server_error(&e.to_string()),
    };

    // A fresh register has not enrolled TOTP yet → PendingMfa session, and the
    // body reports mfaEnrolled:false / authLevel:"pending".
    let body = principal_json(&principal, false, AuthLevel::PendingMfa);
    let token = auth.create_session(principal, AuthLevel::PendingMfa);
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
    State(app): State<AppState>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let auth = app.auth.clone();
    let creds = Credentials::from_value(&body);

    // MF-1: refuse a locked-out username BEFORE any argon2 work — a login flood
    // can't even reach the crypto path, let alone succeed. Generic message (no
    // hint whether the lockout vs the credentials is the reason).
    if auth.is_locked(&creds.username) {
        return auth_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts, try again later",
        );
    }

    // MF-1: argon2 verify is CPU-bound — run it on the blocking pool so it can't
    // starve the async runtime under a login flood.
    let auth2 = auth.clone();
    let username = creds.username.clone();
    let password = creds.password.clone();
    let verify_result = tokio::task::spawn_blocking(move || auth2.verify(&username, &password))
        .await
        .expect("login verify task");

    match verify_result {
        Ok(Some(principal)) => {
            // Password is correct. Second factor gates the SESSION LEVEL.
            let enrolled = match auth.mfa_enrolled(&principal.username) {
                Ok(e) => e,
                Err(e) => return auth_server_error(&e.to_string()),
            };

            let level = if enrolled {
                // TOTP is required: verify the submitted code. A missing or wrong
                // code is a login FAILURE — same generic 401 as a wrong password,
                // so the client can't tell which factor failed — and it counts
                // toward the lockout.
                let code_ok = match auth.totp_code_valid(&principal.username, &creds.totp) {
                    Ok(ok) => ok,
                    Err(e) => return auth_server_error(&e.to_string()),
                };
                if !code_ok {
                    auth.record_failure(&creds.username);
                    return auth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid username or password",
                    );
                }
                AuthLevel::Full
            } else if app.demo {
                // DEMO ONLY: a non-enrolled user is granted a Full session so the
                // seeded demo account reaches the chart without an authenticator.
                // This relaxation is STRICTLY gated on `app.demo` (CHARTCRAFT_DEMO);
                // the default path below is unchanged.
                AuthLevel::Full
            } else {
                // Not enrolled: a correct password yields a PendingMfa session that
                // can only reach `/auth/totp/*` to finish enrollment.
                AuthLevel::PendingMfa
            };

            // MF-1: a clean login clears the failure counter.
            auth.record_success(&creds.username);
            let body = principal_json(&principal, enrolled, level);
            let token = auth.create_session(principal, level);
            (
                StatusCode::OK,
                AppendHeaders([(SET_COOKIE, set_session_cookie(&token))]),
                Json(body),
            )
                .into_response()
        }
        Ok(None) => {
            // MF-1: a failed verify counts toward the lockout.
            auth.record_failure(&creds.username);
            auth_error(StatusCode::UNAUTHORIZED, "invalid username or password")
        }
        // MF-4: real error logged server-side, generic body to the client.
        Err(e) => auth_server_error(&e.to_string()),
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
/// Takes `MfaPrincipal` (ANY valid session — PendingMfa or Full), so a fresh
/// register / pre-MFA session can still read its own identity and `authLevel`.
/// The extractor supplies the 401 on a missing/invalid session.
async fn me(
    State(auth): State<Arc<AuthState>>,
    MfaPrincipal(principal, level): MfaPrincipal,
) -> axum::response::Response {
    let enrolled = match auth.mfa_enrolled(&principal.username) {
        Ok(e) => e,
        Err(e) => return auth_server_error(&e.to_string()),
    };
    (StatusCode::OK, Json(principal_json(&principal, enrolled, level))).into_response()
}

/// POST /auth/totp/enroll — stage a TOTP secret for the logged-in user and return
/// the provisioning artifacts. Requires ANY valid session (PendingMfa or Full).
/// The secret is staged (pending) but NOT yet live; the client must `confirm` a
/// code before TOTP takes effect. Returns `{otpauthUri, qrPngBase64, secret}` —
/// the secret is surfaced ONLY here.
///
/// M1/M2: for a not-yet-enrolled user this is idempotent (a reload returns the
/// same pending secret, not a fresh one). For an ALREADY-enrolled user it is a
/// re-key that REQUIRES re-authentication — the body must carry a current valid
/// `code` (verified against the LIVE secret); a missing/invalid code is rejected
/// with a generic 401 and touches no secret. The body is OPTIONAL so a pending
/// user's body-less POST (the enroll contract) still reaches the handler.
async fn totp_enroll(
    State(auth): State<Arc<AuthState>>,
    MfaPrincipal(principal, _level): MfaPrincipal,
    body: Option<Json<Value>>,
) -> axum::response::Response {
    let code = body
        .as_ref()
        .and_then(|Json(b)| b.get("code").and_then(Value::as_str))
        .unwrap_or("");
    match auth.totp_enroll(&principal.username, code) {
        Ok(e) => (
            StatusCode::OK,
            Json(json!({
                "otpauthUri": e.otpauth_uri,
                "qrPngBase64": e.qr_png_base64,
                "secret": e.secret,
            })),
        )
            .into_response(),
        // M1/M2: a re-key without a valid current code → generic 401, no secret
        // touched (no hint whether the code was missing vs wrong).
        Err(auth::AuthError::ReauthRequired) => {
            auth_error(StatusCode::UNAUTHORIZED, "re-authentication required")
        }
        Err(e) => auth_server_error(&e.to_string()),
    }
}

/// POST /auth/totp/confirm {code} — verify `code` against the user's PENDING
/// secret with ±1-step skew. Requires ANY valid session. On success, atomically
/// promote the pending secret to live (enabling TOTP), promote THIS session to
/// `Full`, and return `{mfaEnrolled:true, authLevel:"full"}`, 200. A wrong code →
/// generic 400.
///
/// N3: confirm gates the re-key path, so it carries the SAME username-keyed
/// lockout as login — a locked user is refused with 429 before any verify, and a
/// wrong code counts toward the lockout. N2: on success THIS pre-MFA token is
/// destroyed and a FRESH `Full` session token is minted (session-fixation hygiene).
async fn totp_confirm(
    State(auth): State<Arc<AuthState>>,
    headers: axum::http::HeaderMap,
    MfaPrincipal(principal, _level): MfaPrincipal,
    Json(body): Json<Value>,
) -> axum::response::Response {
    // N3: refuse a locked-out username before any verify work.
    if auth.is_locked(&principal.username) {
        return auth_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts, try again later",
        );
    }

    let code = body.get("code").and_then(Value::as_str).unwrap_or("");
    match auth.totp_confirm(&principal.username, code) {
        Ok(true) => {
            // N3: a clean confirm clears the failure counter.
            auth.record_success(&principal.username);
            // N2: rotate the session token. Destroy the pre-MFA token and mint a
            // fresh Full session, so the token that existed before the second factor
            // was proven is invalidated. The new cookie is set below.
            if let Some(old) = auth::session_token_from_headers(&headers) {
                auth.destroy_session(&old);
            }
            let token = auth.create_session(principal, AuthLevel::Full);
            (
                StatusCode::OK,
                AppendHeaders([(SET_COOKIE, set_session_cookie(&token))]),
                Json(json!({"mfaEnrolled": true, "authLevel": AuthLevel::Full.as_str()})),
            )
                .into_response()
        }
        Ok(false) => {
            // N3: a wrong code counts toward the lockout.
            auth.record_failure(&principal.username);
            auth_error(StatusCode::BAD_REQUEST, "invalid code")
        }
        Err(e) => auth_server_error(&e.to_string()),
    }
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
    // op to learn its committed version — the audit WriteOp rides in the SAME
    // atomic batch, so its action is fixed BEFORE `commit` returns the versions,
    // and deriving it from `versions[0]` would mean splitting the write path or a
    // post-commit label patch. Deferred to a later concurrency-hardening pass;
    // status is fixed now, the label is not.
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

/// MF-4: a 500. The real error (DB/store text) is logged SERVER-SIDE only; the
/// client body carries a FIXED generic message, never raw internal detail — so a
/// rusqlite/StoreError string can't leak to an attacker. All call sites already
/// pass `e.to_string()`, so this one change covers every `server_error(&e...)`
/// site with no call-site churn.
fn server_error(detail: &str) -> (StatusCode, Json<Value>) {
    eprintln!("[chartcraft] internal error: {detail}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(operation_outcome("error", "exception", "internal error")),
    )
}

/// MF-4: the auth-shaped parallel to `server_error` — log the real error, return
/// a generic `{"error":"internal error"}` 500. Routes the auth handlers' `Err(e)`
/// arms (which previously formatted the raw error into the body).
fn auth_server_error(detail: &str) -> axum::response::Response {
    eprintln!("[chartcraft] internal error: {detail}");
    auth_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// Build the full ChartCraft core router over an [`AppState`]: the FHIR CRUD +
/// search routes, the superbill instance operation, `/metadata`, the `/auth/*`
/// (and TOTP) endpoints, and the static `web/` frontend as the fallback. A
/// downstream crate calls `core_router(state.clone()).merge(my_router)` to compose
/// its own routes onto this core.
pub fn core_router(state: AppState) -> Router {
    Router::new()
        // Auth endpoints — EXEMPT from the session gate (none take AuthPrincipal
        // except `me`, which uses it to produce its own 401). Literal 2-segment
        // routes like `/auth/login` win over the `/:resource_type/:id` param route
        // in axum's router, so they are never shadowed by the FHIR CRUD path.
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        // TOTP MFA — reachable by ANY valid session (PendingMfa or Full) via the
        // `MfaPrincipal` extractor, so a not-yet-enrolled session can finish setup.
        .route("/auth/totp/enroll", post(totp_enroll))
        .route("/auth/totp/confirm", post(totp_confirm))
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

/// DEMO ONLY: seed a demo admin and a populated sample chart on first boot. Called
/// from `main()` only when demo mode is on AND the users table is empty, so it is
/// idempotent — re-running on a populated db is a no-op (the empty-users gate is
/// the whole idempotency contract). The user goes in via the normal bootstrap
/// `register`; every clinical resource goes in via the same `write()` path the HTTP
/// handlers use, so each gets its Provenance + AuditEvent through the real `commit`.
pub fn seed_demo(store: &SharedStore, auth: &AuthState) {
    let principal = match auth.register(&Credentials {
        username: "demo".to_string(),
        password: "demodemo1234".to_string(),
        display_name: "Demo Clinician".to_string(),
        totp: String::new(),
    }) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[chartcraft] demo seed: register failed: {e}");
            return;
        }
    };

    let pid = "demo-patient-1";
    let pref = format!("Patient/{pid}");
    let subject = json!({ "reference": pref });

    // Fixed ids so tests and re-runs are deterministic. All reference the demo
    // patient so the chart cards (which fetch `?patient=<id>`) populate.
    let resources: Vec<(&str, &str, Value)> = vec![
        (
            "Patient",
            pid,
            json!({
                "name": [{ "family": "Whitfield", "given": ["Eleanor", "M"] }],
                "gender": "female",
                "birthDate": "1958-04-12",
            }),
        ),
        (
            "Condition",
            "demo-cond-htn",
            json!({
                "clinicalStatus": { "coding": [{ "code": "active" }] },
                "code": { "text": "Essential hypertension" },
                "subject": subject,
            }),
        ),
        (
            "Condition",
            "demo-cond-dm2",
            json!({
                "clinicalStatus": { "coding": [{ "code": "active" }] },
                "code": { "text": "Type 2 diabetes mellitus" },
                "subject": subject,
            }),
        ),
        (
            "Condition",
            "demo-cond-hld",
            json!({
                "clinicalStatus": { "coding": [{ "code": "active" }] },
                "code": { "text": "Hyperlipidemia" },
                "subject": subject,
            }),
        ),
        (
            "MedicationRequest",
            "demo-med-lisinopril",
            json!({
                "status": "active",
                "intent": "order",
                "medicationCodeableConcept": { "text": "Lisinopril 10 mg oral tablet" },
                "subject": subject,
            }),
        ),
        (
            "MedicationRequest",
            "demo-med-metformin",
            json!({
                "status": "active",
                "intent": "order",
                "medicationCodeableConcept": { "text": "Metformin 500 mg oral tablet" },
                "subject": subject,
            }),
        ),
        (
            "MedicationRequest",
            "demo-med-atorvastatin",
            json!({
                "status": "active",
                "intent": "order",
                "medicationCodeableConcept": { "text": "Atorvastatin 20 mg oral tablet" },
                "subject": subject,
            }),
        ),
        (
            "AllergyIntolerance",
            "demo-allergy-penicillin",
            json!({
                "clinicalStatus": { "coding": [{ "code": "active" }] },
                "code": { "text": "Penicillin" },
                "reaction": [{ "manifestation": [{ "text": "Hives" }] }],
                "patient": subject,
            }),
        ),
        (
            "Observation",
            "demo-obs-bp",
            json!({
                "status": "final",
                "code": { "text": "Blood pressure" },
                "valueString": "138/86 mmHg",
                "effectiveDateTime": "2026-11-20",
                "subject": subject,
            }),
        ),
        (
            "Observation",
            "demo-obs-a1c",
            json!({
                "status": "final",
                "code": { "text": "Hemoglobin A1c" },
                "valueString": "7.4 %",
                "effectiveDateTime": "2026-11-20",
                "subject": subject,
            }),
        ),
        (
            "DocumentReference",
            "demo-doc-progress-note",
            json!({
                "status": "current",
                "type": { "text": "Progress note" },
                "description": "Routine follow-up: HTN, T2DM and hyperlipidemia stable on current regimen. Continue meds; recheck A1c in 3 months.",
                "subject": subject,
            }),
        ),
    ];

    for (rtype, id, mut body) in resources {
        body["resourceType"] = json!(rtype);
        body["id"] = json!(id);
        let (code, _) = write(store, rtype, id, &body, &principal);
        if code != StatusCode::CREATED {
            eprintln!("[chartcraft] demo seed: {rtype}/{id} unexpected status {code}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthPrincipal, InMemoryAuthStore, Principal};
    use crate::store::SqliteStore;

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
            demo: false,
        }
    }

    /// Like `mem_app_state`, but with demo mode ON (relaxed MFA + seeded chart via
    /// `seed_demo`). Used by the demo-mode tests.
    fn demo_app_state() -> AppState {
        let store = mem_store();
        let auth = Arc::new(AuthState::new(Box::new(InMemoryAuthStore::default())));
        seed_demo(&store, &auth);
        AppState {
            store,
            auth,
            demo: true,
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
        let app = core_router(state);

        // First registration bootstraps the admin, auto-logs-in (sets cookie), 201.
        let (code, cookie, body) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            // MF-3: bootstrap password must now meet the 12-char minimum.
            Some(json!({"username": "admin", "password": "admin-pw-1234", "displayName": "Dr Admin"})),
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
        let app = core_router(mem_app_state());
        // Bootstrap a user first.
        send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "bob", "password": "hunter2-long-pw", "displayName": "Bob"})),
        )
        .await;

        // Right password → 200 + cookie + identity.
        let (code, cookie, body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "bob", "password": "hunter2-long-pw"})),
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

    /// MF-1: five wrong passwords lock the username out — the 6th attempt is 429
    /// and never reaches a successful-looking path; a correct login resets it.
    #[tokio::test]
    async fn repeated_wrong_passwords_lock_out_then_429() {
        let app = core_router(mem_app_state());
        send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "dave", "password": "dave-strong-pw", "displayName": "Dave"})),
        )
        .await;

        // Five wrong-password attempts: each a plain 401 (still below the cap).
        for _ in 0..5 {
            let (code, _, _) = send(
                &app,
                "POST",
                "/auth/login",
                None,
                Some(json!({"username": "dave", "password": "WRONG"})),
            )
            .await;
            assert_eq!(code, StatusCode::UNAUTHORIZED);
        }

        // The 6th attempt — even with the CORRECT password — is refused as 429,
        // proving the lockout short-circuits before any successful path.
        let (code, cookie, _) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "dave", "password": "dave-strong-pw"})),
        )
        .await;
        assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
        assert!(cookie.is_none(), "a locked-out login mints no session cookie");
    }

    /// MF-1: a successful login (before the cap) resets the failure counter, so a
    /// later streak of failures starts fresh rather than tripping early.
    #[tokio::test]
    async fn successful_login_resets_the_failure_counter() {
        let app = core_router(mem_app_state());
        send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "erin", "password": "erin-strong-pw", "displayName": "Erin"})),
        )
        .await;

        // Four failures (below the cap of 5)...
        for _ in 0..4 {
            send(
                &app,
                "POST",
                "/auth/login",
                None,
                Some(json!({"username": "erin", "password": "WRONG"})),
            )
            .await;
        }
        // ...then a correct login succeeds (not yet locked) and resets the count.
        let (code, cookie, _) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "erin", "password": "erin-strong-pw"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert!(cookie.is_some());

        // Four MORE failures must again stay below the cap (counter was reset), so
        // a correct login still goes through — not a 429.
        for _ in 0..4 {
            send(
                &app,
                "POST",
                "/auth/login",
                None,
                Some(json!({"username": "erin", "password": "WRONG"})),
            )
            .await;
        }
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "erin", "password": "erin-strong-pw"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "counter reset by the earlier success");
    }

    /// MF-3: register rejects a blank username and a short password with 400, but a
    /// valid bootstrap still 201s (exercised through the full router).
    #[tokio::test]
    async fn register_validation_rejects_bad_input_400() {
        let app = core_router(mem_app_state());

        // Blank username → 400.
        let (code, _, body) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "   ", "password": "a-long-enough-pw", "displayName": "X"})),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(body["error"].is_string());

        // Short password (< 12) → 400 (table still empty, so it's a validation
        // rejection, not "registration closed").
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "frank", "password": "short", "displayName": "Frank"})),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);

        // A valid bootstrap still succeeds.
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "frank", "password": "frank-strong-pw", "displayName": "Frank"})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn me_reflects_the_session_and_logout_clears_it() {
        let app = core_router(mem_app_state());
        let (_, cookie, _) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "carol", "password": "carol-pw-1234", "displayName": "Carol"})),
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
        let app = core_router(mem_app_state());

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
        let app = core_router(mem_app_state());
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

    // --- M4 TOTP MFA tests --------------------------------------------------

    /// Compute a valid current TOTP code from a base32 secret, rebuilding the
    /// `Totp` with the SAME parameters the server uses (issuer "ChartCraft",
    /// account = username, ±1-step skew) so the code the test submits matches what
    /// the server verifies.
    fn current_totp_code(secret_b32: &str, username: &str) -> String {
        totp_code_at(secret_b32, username, 0)
    }

    /// N1: generate a TOTP code for a step `offset_steps` 30-second windows from
    /// now. With the server's ±1 skew, the code for `now + 30` (offset 1) verifies
    /// *now* and sits at a STRICTLY greater step than the current one — so a test
    /// that must verify twice in quick succession (confirm, then login/re-enroll)
    /// uses a distinct, fresh step each time and dodges N1's replay rejection.
    fn totp_code_at(secret_b32: &str, username: &str, offset_steps: i64) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        use totp_rs::{Builder as TotpBuilder, Secret};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let at = (now + offset_steps * 30).max(0) as u64;
        TotpBuilder::new()
            .with_secret(Secret::try_from_base32(secret_b32).unwrap())
            .with_issuer(Some("ChartCraft"))
            .with_account_name(username)
            .with_skew(1)
            .build()
            .unwrap()
            .generate(at)
            .to_string()
    }

    /// Register an admin and return the login/session cookie (PendingMfa).
    async fn register_admin(app: &Router, username: &str) -> String {
        let (_, cookie, _) = send(
            app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": username, "password": "a-long-enough-pw", "displayName": "Admin"})),
        )
        .await;
        cookie_pair(&cookie.expect("register sets a session cookie"))
    }

    /// A fresh register yields a PendingMfa session, and `/auth/me` reports it.
    #[tokio::test]
    async fn register_yields_pending_mfa_session() {
        let app = core_router(mem_app_state());
        let (code, _, body) = send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw", "displayName": "Admin"})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(body["mfaEnrolled"], json!(false));
        assert_eq!(body["authLevel"], json!("pending"));
    }

    /// A PendingMfa session is REFUSED (403) at a FHIR endpoint, but may reach the
    /// TOTP endpoints.
    #[tokio::test]
    async fn pending_mfa_session_is_403_on_fhir() {
        let app = core_router(mem_app_state());
        let cookie = register_admin(&app, "admin").await;

        // FHIR read is 403 (authenticated, but not MFA-cleared) with an
        // OperationOutcome — NOT a 401 (that's for no session at all).
        let (code, _, body) = send(&app, "GET", "/Patient", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        assert_eq!(body["resourceType"], "OperationOutcome");

        // /metadata is gated the same way.
        let (code, _, _) = send(&app, "GET", "/metadata", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::FORBIDDEN);

        // But /auth/me and the enroll endpoint ARE reachable for a PendingMfa session.
        let (code, _, _) = send(&app, "GET", "/auth/me", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        let (code, _, _) = send(&app, "POST", "/auth/totp/enroll", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::OK);
    }

    /// enroll → confirm promotes THIS session to Full, which can then read FHIR.
    #[tokio::test]
    async fn enroll_confirm_promotes_session_and_unlocks_fhir() {
        let app = core_router(mem_app_state());
        let cookie = register_admin(&app, "admin").await;

        // Enroll returns the otpauth URI, a base64 PNG QR, and the base32 secret.
        let (code, _, body) = send(&app, "POST", "/auth/totp/enroll", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        let secret = body["secret"].as_str().expect("enroll returns the secret").to_string();
        assert!(body["otpauthUri"].as_str().unwrap().starts_with("otpauth://totp/"));
        assert!(!body["qrPngBase64"].as_str().unwrap().is_empty(), "QR PNG base64");

        // Before confirm, the session is still PendingMfa → FHIR is 403.
        let (code, _, _) = send(&app, "GET", "/Patient", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::FORBIDDEN);

        // Confirm with a valid current code → 200, mfaEnrolled:true, authLevel:full.
        let code_val = current_totp_code(&secret, "admin");
        let (code, confirm_cookie, body) = send(
            &app,
            "POST",
            "/auth/totp/confirm",
            Some(&cookie),
            Some(json!({"code": code_val})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["mfaEnrolled"], json!(true));
        assert_eq!(body["authLevel"], json!("full"));

        // N2: confirm rotated the session token — it set a FRESH cookie, and the
        // OLD pre-MFA cookie is now dead.
        let full_cookie = cookie_pair(&confirm_cookie.expect("confirm rotates the session cookie"));
        assert_ne!(full_cookie, cookie, "a fresh token is minted at promotion");
        let (code, _, _) = send(&app, "GET", "/auth/me", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "the pre-MFA token is invalidated");

        // The NEW (rotated) session is Full and can read FHIR (empty searchset, 200).
        let (code, _, body) = send(&app, "GET", "/Patient", Some(&full_cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["resourceType"], "Bundle");

        // /auth/me now reports the promoted level.
        let (_, _, me_body) = send(&app, "GET", "/auth/me", Some(&full_cookie), None).await;
        assert_eq!(me_body["mfaEnrolled"], json!(true));
        assert_eq!(me_body["authLevel"], json!("full"));
    }

    /// Confirm with a WRONG code → generic 400, no promotion, still 403 on FHIR.
    #[tokio::test]
    async fn confirm_with_wrong_code_is_400_and_no_promotion() {
        let app = core_router(mem_app_state());
        let cookie = register_admin(&app, "admin").await;
        send(&app, "POST", "/auth/totp/enroll", Some(&cookie), None).await;

        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/totp/confirm",
            Some(&cookie),
            Some(json!({"code": "000000"})),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);

        // Session was NOT promoted — FHIR is still 403.
        let (code, _, _) = send(&app, "GET", "/Patient", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::FORBIDDEN);
    }

    /// Once TOTP is enabled, login requires a valid code: none → 401, wrong → 401,
    /// correct → Full 200.
    #[tokio::test]
    async fn login_with_totp_enabled_requires_a_valid_code() {
        let app = core_router(mem_app_state());
        let cookie = register_admin(&app, "admin").await;

        // Enroll + confirm so totp_enabled is set.
        let (_, _, body) = send(&app, "POST", "/auth/totp/enroll", Some(&cookie), None).await;
        let secret = body["secret"].as_str().unwrap().to_string();
        let good = current_totp_code(&secret, "admin");
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/totp/confirm",
            Some(&cookie),
            Some(json!({"code": good})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);

        // Login with password only (no code) → generic 401, no cookie.
        let (code, nocode_cookie, body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw"})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], json!("invalid username or password"));
        assert!(nocode_cookie.is_none(), "no session cookie on a failed login");

        // Login with a WRONG code → same generic 401.
        let (code, _, body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw", "totp": "000000"})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], json!("invalid username or password"));

        // Login with the CORRECT code → Full 200, mfaEnrolled:true. N1: confirm
        // above consumed the current step, so use the next step (+1), which is
        // still valid now under ±1 skew but is a strictly fresher step.
        let good = totp_code_at(&secret, "admin", 1);
        let (code, login_cookie, body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw", "totp": good})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["mfaEnrolled"], json!(true));
        assert_eq!(body["authLevel"], json!("full"));

        // The fresh session from that login is Full and can read FHIR.
        let login_cookie = cookie_pair(&login_cookie.unwrap());
        let (code, _, _) = send(&app, "GET", "/Patient", Some(&login_cookie), None).await;
        assert_eq!(code, StatusCode::OK);
    }

    /// Helper: register an admin and fully enroll+confirm TOTP, returning the
    /// base32 secret and the FRESH (post-N2-rotation) Full session cookie.
    async fn enroll_confirmed_admin(app: &Router, username: &str) -> (String, String) {
        let pending_cookie = register_admin(app, username).await;
        let (_, _, body) =
            send(app, "POST", "/auth/totp/enroll", Some(&pending_cookie), None).await;
        let secret = body["secret"].as_str().unwrap().to_string();
        let code = current_totp_code(&secret, username);
        let (code_status, full_cookie, _) = send(
            app,
            "POST",
            "/auth/totp/confirm",
            Some(&pending_cookie),
            Some(json!({"code": code})),
        )
        .await;
        assert_eq!(code_status, StatusCode::OK);
        (secret, cookie_pair(&full_cookie.expect("confirm sets a fresh cookie")))
    }

    /// M6: with TOTP enabled, repeated WRONG codes at login arm the lockout — the
    /// 6th attempt is 429 — proving an invalid TOTP counts toward throttling.
    #[tokio::test]
    async fn repeated_wrong_totp_codes_lock_out_then_429() {
        let app = core_router(mem_app_state());
        enroll_confirmed_admin(&app, "admin").await;

        // Five password-correct / code-wrong logins: each a plain 401 (below cap).
        for _ in 0..5 {
            let (code, _, _) = send(
                &app,
                "POST",
                "/auth/login",
                None,
                Some(json!({"username": "admin", "password": "a-long-enough-pw", "totp": "000000"})),
            )
            .await;
            assert_eq!(code, StatusCode::UNAUTHORIZED);
        }

        // The 6th — even with the right password — is refused as 429. (We don't
        // supply a valid code; the point is the lockout short-circuits first.)
        let (code, cookie, _) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw", "totp": "000000"})),
        )
        .await;
        assert_eq!(code, StatusCode::TOO_MANY_REQUESTS, "invalid TOTP counts toward the lockout");
        assert!(cookie.is_none());
    }

    /// M6: the TOTP secret must NEVER appear in a `/auth/me` body nor in a `login`
    /// response body — it's surfaced only by `enroll`.
    #[tokio::test]
    async fn totp_secret_never_leaks_in_me_or_login_bodies() {
        let app = core_router(mem_app_state());
        let (secret, full_cookie) = enroll_confirmed_admin(&app, "admin").await;

        // /auth/me (Full session) must not contain the secret anywhere in its body.
        let (code, _, me_body) = send(&app, "GET", "/auth/me", Some(&full_cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        assert!(
            !me_body.to_string().contains(&secret),
            "the TOTP secret must never appear in /auth/me"
        );

        // A successful login body must not contain the secret either. Use a fresh
        // step (+1) for the code since confirm already consumed the current one.
        let good = totp_code_at(&secret, "admin", 1);
        let (code, _, login_body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw", "totp": good})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert!(
            !login_body.to_string().contains(&secret),
            "the TOTP secret must never appear in a login response"
        );
    }

    /// M1/M2 + M6: an enabled user's re-enroll WITHOUT a current code is rejected
    /// (401), no secret is touched, and the live secret still works afterward.
    #[tokio::test]
    async fn reenroll_without_current_code_is_rejected_and_live_secret_survives() {
        let app = core_router(mem_app_state());
        let (secret, full_cookie) = enroll_confirmed_admin(&app, "admin").await;

        // Re-enroll with no body → 401 (re-authentication required).
        let (code, _, _) = send(&app, "POST", "/auth/totp/enroll", Some(&full_cookie), None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "re-key needs a current code");

        // Re-enroll with a WRONG code → also 401.
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/totp/enroll",
            Some(&full_cookie),
            Some(json!({"code": "000000"})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);

        // The ORIGINAL live secret still authenticates a fresh login (nothing was
        // swapped). Use step +1 (confirm consumed the current step).
        let good = totp_code_at(&secret, "admin", 1);
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw", "totp": good})),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "the live secret still works after a rejected re-key");
    }

    /// M1: enroll is idempotent for a not-yet-enrolled user — a reload returns the
    /// SAME pending secret/URI (so an already-scanned QR is never invalidated), and
    /// that reused secret is the one a confirm promotes.
    #[tokio::test]
    async fn enroll_reload_is_idempotent_for_pending_user() {
        let app = core_router(mem_app_state());
        let cookie = register_admin(&app, "admin").await;

        // First enroll stages a pending secret.
        let (code, _, b1) = send(&app, "POST", "/auth/totp/enroll", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        let secret1 = b1["secret"].as_str().unwrap().to_string();
        let uri1 = b1["otpauthUri"].as_str().unwrap().to_string();

        // Reloading enroll returns the SAME secret/URI — no rotation.
        let (code, _, b2) = send(&app, "POST", "/auth/totp/enroll", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(b2["secret"].as_str().unwrap(), secret1, "reload must not rotate the pending secret");
        assert_eq!(b2["otpauthUri"].as_str().unwrap(), uri1, "same provisioning URI");

        // A code from that (stable) pending secret confirms and promotes.
        let code_val = current_totp_code(&secret1, "admin");
        let (status, _, body) = send(
            &app,
            "POST",
            "/auth/totp/confirm",
            Some(&cookie),
            Some(json!({"code": code_val})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["mfaEnrolled"], json!(true));
    }

    /// N1 + M6: a replayed code (same step) is rejected. Confirm consumes step S;
    /// a login that submits the SAME step-S code is refused even with the right
    /// password, while a fresh-step code then succeeds.
    #[tokio::test]
    async fn replayed_totp_code_is_rejected() {
        let app = core_router(mem_app_state());
        let pending_cookie = register_admin(&app, "admin").await;
        let (_, _, body) =
            send(&app, "POST", "/auth/totp/enroll", Some(&pending_cookie), None).await;
        let secret = body["secret"].as_str().unwrap().to_string();

        // Confirm consumes the current step S.
        let step_s = current_totp_code(&secret, "admin");
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/totp/confirm",
            Some(&pending_cookie),
            Some(json!({"code": step_s.clone()})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);

        // Replaying the SAME step-S code at login is rejected (N1), even though the
        // password is correct and the code is otherwise still in its window.
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw", "totp": step_s})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "a replayed (already-used) step is rejected");

        // A fresh-step code (S+1) then logs in successfully.
        let fresh = totp_code_at(&secret, "admin", 1);
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "admin", "password": "a-long-enough-pw", "totp": fresh})),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "a fresh step still authenticates");
    }

    /// The TOTP endpoints reject an unauthenticated caller with 401.
    #[tokio::test]
    async fn totp_endpoints_require_a_session() {
        let app = core_router(mem_app_state());
        let (code, _, _) = send(&app, "POST", "/auth/totp/enroll", None, None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        let (code, _, _) = send(
            &app,
            "POST",
            "/auth/totp/confirm",
            None,
            Some(json!({"code": "123456"})),
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    // --- Demo mode ----------------------------------------------------------

    /// Demo seed, run on an empty store, creates the demo user and the sample
    /// patient; running it a second time (users no longer empty → caller gates on
    /// that) must not duplicate the patient.
    #[tokio::test]
    async fn demo_seed_populates_and_is_idempotent() {
        let store = mem_store();
        let auth = Arc::new(AuthState::new(Box::new(InMemoryAuthStore::default())));

        seed_demo(&store, &auth);
        // The demo user exists (registration is now closed).
        assert_eq!(auth.no_users_yet().unwrap(), false);
        // The sample patient and a couple of its clinical resources landed.
        assert!(store.get("Patient", "demo-patient-1").unwrap().is_some());
        assert!(store.get("Condition", "demo-cond-dm2").unwrap().is_some());
        assert!(store.get("MedicationRequest", "demo-med-metformin").unwrap().is_some());
        let patients = store.list("Patient").unwrap();
        assert_eq!(patients.len(), 1, "exactly one demo patient");

        // The idempotency contract is the empty-users gate in `main()`. Re-running
        // seed_demo here would fail register (users not empty) and add nothing — so
        // the patient count stays at one.
        seed_demo(&store, &auth);
        assert_eq!(store.list("Patient").unwrap().len(), 1, "no duplicate patient");
    }

    /// DEMO MODE: a password login of the seeded, non-enrolled demo user yields a
    /// FULL session that can immediately read the seeded chart over FHIR.
    #[tokio::test]
    async fn demo_login_is_full_and_reaches_the_chart() {
        let app = core_router(demo_app_state());

        let (code, cookie, body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "demo", "password": "demodemo1234"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        // Relaxed: not enrolled, yet granted Full.
        assert_eq!(body["mfaEnrolled"], json!(false));
        assert_eq!(body["authLevel"], json!("full"));
        let cookie = cookie_pair(&cookie.expect("login sets a session cookie"));

        // The Full session reads PHI: the seeded patient is present.
        let (code, _, body) = send(&app, "GET", "/Patient", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["resourceType"], "Bundle");
        assert_eq!(body["total"], json!(1));
        assert_eq!(body["entry"][0]["resource"]["id"], json!("demo-patient-1"));

        // The chart cards fetch `?patient=<id>` — the seeded conditions/meds show.
        let (code, _, conds) =
            send(&app, "GET", "/Condition?patient=demo-patient-1", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(conds["total"], json!(3), "three seeded conditions");
        let (_, _, meds) = send(
            &app,
            "GET",
            "/MedicationRequest?patient=demo-patient-1",
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(meds["total"], json!(3), "three seeded medications");
    }

    /// NON-DEMO MODE: the relaxation is strictly gated. A fresh (non-enrolled) user
    /// logs in to a PendingMfa session and is 403 on a FHIR endpoint — proving the
    /// demo relaxation does NOT leak into the default path.
    #[tokio::test]
    async fn non_demo_login_stays_pending_and_is_403_on_fhir() {
        // demo: false (the default), built explicitly so this proves the gate.
        let app = core_router(mem_app_state());

        // Bootstrap a user (register → PendingMfa), then log in fresh.
        send(
            &app,
            "POST",
            "/auth/register",
            None,
            Some(json!({"username": "doc", "password": "a-long-enough-pw", "displayName": "Doc"})),
        )
        .await;

        let (code, cookie, body) = send(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": "doc", "password": "a-long-enough-pw"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["authLevel"], json!("pending"), "no demo → still PendingMfa");
        let cookie = cookie_pair(&cookie.expect("login sets a session cookie"));

        // PendingMfa → 403 on PHI (the MFA gate is intact).
        let (code, _, oo) = send(&app, "GET", "/Patient", Some(&cookie), None).await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        assert_eq!(oo["resourceType"], "OperationOutcome");
    }
}
