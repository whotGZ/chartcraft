//! Milestone 4 — authentication: the auth store, sessions, and the axum
//! `AuthPrincipal` extractor that gates every FHIR data endpoint.
//!
//! Kept cleanly separate from the FHIR `ChartStore`: users live in their OWN
//! `users` table (never in the `resources` table, never treated as FHIR
//! resources), and `SqliteAuthStore` owns its OWN `Mutex<Connection>` on the same
//! `chartcraft.db` file — the clinical store and the auth store share a database
//! file but nothing else. An `InMemoryAuthStore` mirrors it for tests.
//!
//! Passwords are hashed with argon2id (library-default params) into PHC strings;
//! plaintext is never stored or logged. Sessions are server-side: a 256-bit
//! random token is the cookie value, and `Mutex<HashMap<token, Principal>>` maps
//! it back to the logged-in user.
//!
//! ponytail: sessions are in-memory, so a restart logs everyone out. Fine for a
//! solo single-box deploy; a persistent/redis session table is future work.
//!
//! `InMemoryAuthStore` and `open_in_memory` are exercised by the test suite, not
//! the binary's happy path, so the dead-code lint is silenced here — they're real
//! API surface (the test backend), mirroring `store.rs`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use argon2::password_hash::{
    phc::PasswordHash, PasswordHasher, PasswordVerifier,
};
use argon2::Argon2;
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    Json,
};
use rand::Rng;
use rusqlite::Connection;
use serde_json::Value;

use crate::fhir::{now_iso8601, operation_outcome};

/// A stored/authenticated user, minus the password hash. This is what rides in
/// the session map and gets threaded into Provenance/AuditEvent as the signer.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: String,
    pub username: String,
    pub display_name: String,
}

/// Registration/login request body. No `Debug` derive and no logging of these —
/// the plaintext `password` must never reach a log line or error format. Built by
/// hand from a `serde_json::Value` (no `serde` derive dep, matching the rest of
/// the codebase, which also works off `Value`).
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// Only present on register; login ignores it.
    pub display_name: String,
}

impl Credentials {
    /// Parse credentials out of a JSON object, defaulting any missing string
    /// field to empty. Missing/empty fields simply fail verification or produce a
    /// blank display name; no separate validation error shape is invented.
    pub fn from_value(body: &Value) -> Self {
        let s = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Credentials {
            username: s("username"),
            password: s("password"),
            display_name: s("displayName"),
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    Db(String),
    /// Username already taken (register) — surfaces as a 409/403 upstream.
    UsernameTaken,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Db(m) => write!(f, "auth store error: {m}"),
            AuthError::UsernameTaken => write!(f, "username already taken"),
        }
    }
}

impl From<rusqlite::Error> for AuthError {
    fn from(e: rusqlite::Error) -> Self {
        AuthError::Db(e.to_string())
    }
}

/// A persisted user row, including the argon2 PHC hash (used only for verify).
pub struct UserRecord {
    id: String,
    username: String,
    display_name: String,
    password_hash: String,
}

/// The users table: a seam with two backends, mirroring `ChartStore`. Keeps the
/// clinical store and the auth store cleanly separated.
pub trait AuthStore: Send + Sync {
    /// True when there are zero users — register is a one-shot bootstrap allowed
    /// only in that state.
    fn user_count(&self) -> Result<u64, AuthError>;

    /// Insert the FIRST user, ATOMICALLY — the insert succeeds only if the table
    /// is still empty at insert time, closing the bootstrap TOCTOU race (two
    /// concurrent first-registers with different usernames can't both win).
    /// `Err(UsernameTaken)` means the table was non-empty: registration is closed.
    ///
    /// ponytail: this is the single-admin bootstrap path. Future multi-user admin
    /// invites will need an unguarded `insert_user` that doesn't require emptiness.
    fn insert_first_user(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> Result<(), AuthError>;

    /// Fetch the full record (incl. hash) by username, for login verification.
    fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, AuthError>;
}

// --- SQLite backend ---------------------------------------------------------

/// SQLite-backed users table. Owns its OWN connection on the same db file as the
/// `ChartStore`; the two never share a connection or a lock.
pub struct SqliteAuthStore {
    conn: Mutex<Connection>,
}

impl SqliteAuthStore {
    pub fn open(path: &str) -> Result<Self, AuthError> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(SqliteAuthStore {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(SqliteAuthStore {
            conn: Mutex::new(conn),
        })
    }

    fn init(conn: &Connection) -> Result<(), AuthError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                 id            TEXT PRIMARY KEY,
                 username      TEXT NOT NULL UNIQUE,
                 display_name  TEXT NOT NULL,
                 password_hash TEXT NOT NULL,
                 created       TEXT NOT NULL
             );",
        )?;
        Ok(())
    }
}

impl AuthStore for SqliteAuthStore {
    fn user_count(&self) -> Result<u64, AuthError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    fn insert_first_user(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> Result<(), AuthError> {
        let conn = self.conn.lock().unwrap();
        // Guarded insert: the row lands ONLY if the table is still empty. Both the
        // emptiness check and the insert happen in one statement under the
        // connection lock, so concurrent first-registers can't both succeed.
        let changed = conn.execute(
            "INSERT INTO users (id, username, display_name, password_hash, created)
             SELECT ?1, ?2, ?3, ?4, ?5 WHERE NOT EXISTS (SELECT 1 FROM users)",
            rusqlite::params![id, username, display_name, password_hash, now_iso8601()],
        )?;
        if changed == 0 {
            // Table was non-empty → someone already bootstrapped.
            Err(AuthError::UsernameTaken)
        } else {
            Ok(())
        }
    }

    fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, AuthError> {
        use rusqlite::OptionalExtension;
        let conn = self.conn.lock().unwrap();
        let rec = conn
            .query_row(
                "SELECT id, username, display_name, password_hash FROM users WHERE username = ?1",
                rusqlite::params![username],
                |row| {
                    Ok(UserRecord {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        display_name: row.get(2)?,
                        password_hash: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(rec)
    }
}

// --- In-memory backend (tests) ----------------------------------------------

#[derive(Default)]
pub struct InMemoryAuthStore {
    // username -> record
    users: Mutex<HashMap<String, UserRecord>>,
}

impl AuthStore for InMemoryAuthStore {
    fn user_count(&self) -> Result<u64, AuthError> {
        Ok(self.users.lock().unwrap().len() as u64)
    }

    fn insert_first_user(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap();
        // Bootstrap guard under the same lock as the insert: refuse unless empty.
        if !users.is_empty() {
            return Err(AuthError::UsernameTaken);
        }
        users.insert(
            username.to_string(),
            UserRecord {
                id: id.to_string(),
                username: username.to_string(),
                display_name: display_name.to_string(),
                password_hash: password_hash.to_string(),
            },
        );
        Ok(())
    }

    fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, AuthError> {
        let users = self.users.lock().unwrap();
        Ok(users.get(username).map(|u| UserRecord {
            id: u.id.clone(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            password_hash: u.password_hash.clone(),
        }))
    }
}

// --- the auth runtime: store + sessions + hashing ---------------------------

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "chartcraft_session";

/// Everything auth needs at request time: the users table plus the server-side
/// session map. Lives in `AppState` behind an `Arc`.
pub struct AuthState {
    store: Box<dyn AuthStore>,
    // ponytail: in-memory sessions (token -> Principal); lost on restart.
    sessions: Mutex<HashMap<String, Principal>>,
}

impl AuthState {
    pub fn new(store: Box<dyn AuthStore>) -> Self {
        AuthState {
            store,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Register the FIRST user (bootstrap). Returns the new Principal on success.
    /// The store insert is bootstrap-GUARDED (empty-table-only, atomically), so
    /// `Err(UsernameTaken)` here means a concurrent register already bootstrapped —
    /// the handler maps that to a 403 (registration closed).
    pub fn register(&self, creds: &Credentials) -> Result<Principal, AuthError> {
        let id = uuid::Uuid::new_v4().to_string();
        let hash = hash_password(&creds.password);
        self.store
            .insert_first_user(&id, &creds.username, &creds.display_name, &hash)?;
        Ok(Principal {
            id,
            username: creds.username.clone(),
            display_name: creds.display_name.clone(),
        })
    }

    /// True when no user exists yet — register is allowed only then.
    pub fn no_users_yet(&self) -> Result<bool, AuthError> {
        Ok(self.store.user_count()? == 0)
    }

    /// Verify a username/password. Returns the Principal on success, `None` on any
    /// failure (unknown user OR wrong password — the caller must not distinguish
    /// them to the client). Runs argon2 verification even when the user is missing,
    /// against a fixed dummy hash, so login time doesn't leak username existence.
    pub fn verify(&self, username: &str, password: &str) -> Result<Option<Principal>, AuthError> {
        match self.store.find_by_username(username)? {
            Some(rec) => {
                if verify_password(password, &rec.password_hash) {
                    Ok(Some(Principal {
                        id: rec.id,
                        username: rec.username,
                        display_name: rec.display_name,
                    }))
                } else {
                    Ok(None)
                }
            }
            None => {
                // Burn the same argon2 work against a dummy hash so a missing user
                // takes the same wall-clock time as a wrong password — no timing
                // oracle for username enumeration.
                let _ = verify_password(password, dummy_hash());
                Ok(None)
            }
        }
    }

    /// Mint a fresh session for a Principal, returning the opaque cookie token.
    pub fn create_session(&self, principal: Principal) -> String {
        let token = new_session_token();
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), principal);
        token
    }

    /// Resolve a session token to its Principal, if the session exists.
    pub fn lookup_session(&self, token: &str) -> Option<Principal> {
        self.sessions.lock().unwrap().get(token).cloned()
    }

    /// Invalidate a session (logout). Idempotent.
    pub fn destroy_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

/// Hash a password into an argon2id PHC string, with a random salt (argon2's
/// `getrandom` default). The returned string embeds the salt + params, so it is
/// the whole stored value.
fn hash_password(password: &str) -> String {
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("argon2 hashing")
        .to_string()
}

/// Verify a password against a stored PHC hash. A malformed stored hash → false
/// (never a panic), so a corrupt row can't crash a login.
fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A fixed argon2 PHC hash of a throwaway password, computed once. Verified
/// against when the username is unknown, to equalize login timing. Never matches
/// a real login (callers discard its result).
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("chartcraft-dummy-password-for-timing"))
}

/// A 256-bit cryptographically-random session token, hex-encoded (URL-safe). Hex
/// reuses the codebase's existing `{b:02x}` idiom rather than adding base64.
fn new_session_token() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let mut hex = String::with_capacity(64);
    for b in buf {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

// --- cookies ----------------------------------------------------------------

/// Pull the session token out of a request's headers, if present.
pub fn session_token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = headers.get(axum::http::header::COOKIE)?;
    let raw = header.to_str().ok()?;
    cookie_value(raw, SESSION_COOKIE)
}

/// Find a cookie's value in a raw `Cookie` header (`a=1; b=2`). Minimal parse —
/// no attributes to worry about on the request side.
fn cookie_value(header: &str, name: &str) -> Option<String> {
    header.split(';').find_map(|pair| {
        let pair = pair.trim();
        let (k, v) = pair.split_once('=')?;
        if k == name {
            Some(v.to_string())
        } else {
            None
        }
    })
}

/// Build the `Set-Cookie` value that plants a session token.
///
/// Flags: `HttpOnly` (no JS access), `SameSite=Strict` (no cross-site send),
/// `Path=/` (whole app). ponytail: `Secure` is deliberately OMITTED so the cookie
/// works over http://localhost in dev. It MUST be added (`; Secure`) behind TLS in
/// production — without it the session token can ride a plaintext request.
pub fn set_session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/")
}

/// Build the `Set-Cookie` value that clears the session cookie (logout).
pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

// --- the extractor ----------------------------------------------------------

/// Axum extractor: the logged-in user. A FHIR handler that takes an
/// `AuthPrincipal` is gated — without a valid session cookie the extractor
/// rejects with 401 + an `OperationOutcome`, and the handler never runs. Auth
/// endpoints and static/`ServeDir` routes simply don't take this extractor, so
/// they stay reachable logged-out.
pub struct AuthPrincipal(pub Principal);

#[async_trait]
impl<S> FromRequestParts<S> for AuthPrincipal
where
    crate::AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = crate::AppState::from_ref(state);
        let unauthorized = || {
            (
                StatusCode::UNAUTHORIZED,
                Json(operation_outcome(
                    "error",
                    "login",
                    "authentication required",
                )),
            )
        };
        let token = session_token_from_headers(&parts.headers).ok_or_else(unauthorized)?;
        match app.auth.lookup_session(&token) {
            Some(principal) => Ok(AuthPrincipal(principal)),
            None => Err(unauthorized()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_hashed_not_stored_plaintext() {
        let store = InMemoryAuthStore::default();
        let state = AuthState::new(Box::new(store));
        let p = state
            .register(&Credentials {
                username: "alice".into(),
                password: "s3cr3t-pw".into(),
                display_name: "Dr Alice".into(),
            })
            .unwrap();
        assert_eq!(p.username, "alice");
        // The stored hash must be an argon2id PHC string, NOT the plaintext.
        let rec = state.store.find_by_username("alice").unwrap().unwrap();
        assert!(rec.password_hash.starts_with("$argon2id$"), "argon2id PHC hash");
        assert!(!rec.password_hash.contains("s3cr3t-pw"), "no plaintext");
    }

    #[test]
    fn verify_accepts_right_password_rejects_wrong_and_unknown() {
        let state = AuthState::new(Box::new(InMemoryAuthStore::default()));
        state
            .register(&Credentials {
                username: "bob".into(),
                password: "correct horse".into(),
                display_name: "Bob".into(),
            })
            .unwrap();
        assert!(state.verify("bob", "correct horse").unwrap().is_some());
        assert!(state.verify("bob", "wrong").unwrap().is_none());
        // Unknown user also → None (and burns a dummy verify, no panic).
        assert!(state.verify("nobody", "whatever").unwrap().is_none());
    }

    #[test]
    fn sessions_round_trip_and_destroy() {
        let state = AuthState::new(Box::new(InMemoryAuthStore::default()));
        let p = Principal {
            id: "u1".into(),
            username: "u".into(),
            display_name: "U".into(),
        };
        let token = state.create_session(p);
        assert!(state.lookup_session(&token).is_some());
        state.destroy_session(&token);
        assert!(state.lookup_session(&token).is_none());
    }

    #[test]
    fn session_token_is_256_bits_hex() {
        let t = new_session_token();
        assert_eq!(t.len(), 64, "32 bytes = 64 hex chars");
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(new_session_token(), new_session_token(), "random");
    }

    #[test]
    fn cookie_value_parses_the_session_token() {
        let raw = format!("other=x; {SESSION_COOKIE}=abc123; last=y");
        assert_eq!(cookie_value(&raw, SESSION_COOKIE).as_deref(), Some("abc123"));
        assert_eq!(cookie_value("nothing=here", SESSION_COOKIE), None);
    }
}
