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
use std::time::{Duration, Instant};

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
use totp_rs::{Builder as TotpBuilder, Secret, Totp, TotpError};

use crate::fhir::{now_iso8601, operation_outcome};

/// A stored/authenticated user, minus the password hash. This is what rides in
/// the session map and gets threaded into Provenance/AuditEvent as the signer.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: String,
    pub username: String,
    pub display_name: String,
}

/// How far a session has cleared authentication. A `PendingMfa` session has a
/// valid password but has NOT satisfied TOTP (either freshly registered, or
/// enrolled-but-not-yet-confirmed); it may reach ONLY the `/auth/totp/*`
/// endpoints. A `Full` session has cleared both factors and may reach PHI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthLevel {
    PendingMfa,
    Full,
}

impl AuthLevel {
    /// The wire string the frontend codes against (`authLevel` field).
    pub fn as_str(self) -> &'static str {
        match self {
            AuthLevel::PendingMfa => "pending",
            AuthLevel::Full => "full",
        }
    }
}

/// Registration/login request body. No `Debug` derive and no logging of these —
/// the plaintext `password` (and `totp` code) must never reach a log line or
/// error format. Built by hand from a `serde_json::Value` (no `serde` derive dep,
/// matching the rest of the codebase, which also works off `Value`).
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// Only present on register; login ignores it.
    pub display_name: String,
    /// Only present on login when the user has TOTP enabled. Empty when omitted.
    pub totp: String,
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
            totp: s("totp"),
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    Db(String),
    /// Username already taken (register) — surfaces as a 409/403 upstream.
    UsernameTaken,
    /// Register input failed server-side validation (blank username / weak
    /// password) — surfaces as a 400 upstream. The message is safe to show the
    /// client (it names the policy, never internal/DB detail).
    InvalidInput(&'static str),
    /// M1/M2: a re-enroll by an already-enabled user arrived without a valid current
    /// TOTP code. Surfaces as a generic 401 upstream; no secret is touched.
    ReauthRequired,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Db(m) => write!(f, "auth store error: {m}"),
            AuthError::UsernameTaken => write!(f, "username already taken"),
            AuthError::InvalidInput(m) => write!(f, "{m}"),
            AuthError::ReauthRequired => write!(f, "re-authentication required"),
        }
    }
}

impl From<rusqlite::Error> for AuthError {
    fn from(e: rusqlite::Error) -> Self {
        AuthError::Db(e.to_string())
    }
}

/// A persisted user row, including the argon2 PHC hash (used only for verify) and
/// the TOTP enrollment state. `totp_secret` is the LIVE base32 shared secret (the
/// one login verifies against, NULL until the first confirm); `totp_enabled` flips
/// true at the first confirm. `pending_totp_secret` is a STAGING slot (M1/M2): a
/// freshly enrolled or re-keyed secret lives here until a code confirms it, at
/// which point it is atomically promoted into `totp_secret`. The live secret keeps
/// working throughout, so a re-key never strands the user.
pub struct UserRecord {
    id: String,
    username: String,
    display_name: String,
    password_hash: String,
    totp_secret: Option<String>,
    totp_enabled: bool,
    pending_totp_secret: Option<String>,
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

    /// Stage a base32 TOTP secret in the PENDING slot (M1/M2) without touching the
    /// live `totp_secret` or `totp_enabled`. The enroll step writes here; a later
    /// confirm promotes it. Overwriting a pending secret is fine (a fresh enroll
    /// before confirmation).
    fn set_pending_totp_secret(&self, username: &str, secret_b32: &str) -> Result<(), AuthError>;

    /// Atomically PROMOTE the pending secret to live (M1/M2 confirm): move
    /// `pending_totp_secret` → `totp_secret`, set `totp_enabled=1`, clear the
    /// pending slot. A no-op (returns `Ok(false)`) when there is no pending secret
    /// to promote; `Ok(true)` when a row was promoted. Atomic so a re-key swaps the
    /// live secret only once the new one is proven — the old one works until then.
    fn promote_pending_totp(&self, username: &str) -> Result<bool, AuthError>;

    /// Clear ALL TOTP state (M5 break-glass): drop the live secret, the pending
    /// secret, and `totp_enabled`, so the user re-enrolls on next login. Returns
    /// `Ok(true)` if a matching user row was cleared, `Ok(false)` if the username
    /// was unknown.
    fn clear_totp(&self, username: &str) -> Result<bool, AuthError>;
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
        // N5: the clinical store and the auth store share `chartcraft.db`. Wait up
        // to 5 s for a concurrent writer's lock instead of surfacing SQLITE_BUSY as
        // a 500 the moment the two connections contend.
        conn.busy_timeout(Duration::from_millis(5000))?;
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
        // ponytail: still no migration engine — the TOTP columns are added to the
        // CREATE TABLE, not ALTER-ed onto an existing table, so a dev db created
        // before these columns existed must be recreated (delete chartcraft.db).
        // Fine for the single-box dev/bootstrap deploy; a real migration runner is
        // future work. M4 below turns the silent-mismatch failure mode into a clear
        // fatal error at boot instead of a 500 at first login.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                 id                  TEXT PRIMARY KEY,
                 username            TEXT NOT NULL UNIQUE,
                 display_name        TEXT NOT NULL,
                 password_hash       TEXT NOT NULL,
                 totp_secret         TEXT NULL,
                 totp_enabled        INTEGER NOT NULL DEFAULT 0,
                 pending_totp_secret TEXT NULL,
                 created             TEXT NOT NULL
             );",
        )?;

        // M4: fail fast on an outdated schema. `CREATE TABLE IF NOT EXISTS` is a
        // no-op against a pre-existing table, so a db made before a column was added
        // would otherwise boot and only blow up (as a 500) when a query hits the
        // missing column. Probe the live columns and demand the full expected set.
        let present: std::collections::HashSet<String> = conn
            .prepare("PRAGMA table_info(users)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;
        const EXPECTED: &[&str] = &[
            "id",
            "username",
            "display_name",
            "password_hash",
            "totp_secret",
            "totp_enabled",
            "pending_totp_secret",
            "created",
        ];
        let missing: Vec<&str> = EXPECTED
            .iter()
            .copied()
            .filter(|c| !present.contains(*c))
            .collect();
        if !missing.is_empty() {
            return Err(AuthError::Db(format!(
                "users table schema is outdated (missing column(s): {}); \
                 delete the database file and restart — no migration engine yet",
                missing.join(", ")
            )));
        }
        Ok(())
    }
}

impl AuthStore for SqliteAuthStore {
    fn user_count(&self) -> Result<u64, AuthError> {
        // N3: recover a poisoned lock rather than letting one panic permanently
        // wedge auth — a stale guard is fine here (SQLite is still consistent).
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let rec = conn
            .query_row(
                "SELECT id, username, display_name, password_hash, totp_secret,
                        totp_enabled, pending_totp_secret
                 FROM users WHERE username = ?1",
                rusqlite::params![username],
                |row| {
                    Ok(UserRecord {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        display_name: row.get(2)?,
                        password_hash: row.get(3)?,
                        totp_secret: row.get(4)?,
                        totp_enabled: row.get::<_, i64>(5)? != 0,
                        pending_totp_secret: row.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(rec)
    }

    fn set_pending_totp_secret(&self, username: &str, secret_b32: &str) -> Result<(), AuthError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE users SET pending_totp_secret = ?1 WHERE username = ?2",
            rusqlite::params![secret_b32, username],
        )?;
        Ok(())
    }

    fn promote_pending_totp(&self, username: &str) -> Result<bool, AuthError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // One atomic statement: promote the pending secret to live, enable TOTP, and
        // clear the pending slot. The `pending_totp_secret IS NOT NULL` guard makes
        // "nothing to promote" a 0-row no-op rather than wiping a live secret.
        let changed = conn.execute(
            "UPDATE users
                SET totp_secret = pending_totp_secret,
                    totp_enabled = 1,
                    pending_totp_secret = NULL
              WHERE username = ?1 AND pending_totp_secret IS NOT NULL",
            rusqlite::params![username],
        )?;
        Ok(changed > 0)
    }

    fn clear_totp(&self, username: &str) -> Result<bool, AuthError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let changed = conn.execute(
            "UPDATE users
                SET totp_secret = NULL, totp_enabled = 0, pending_totp_secret = NULL
              WHERE username = ?1",
            rusqlite::params![username],
        )?;
        Ok(changed > 0)
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
        Ok(self.users.lock().unwrap_or_else(|e| e.into_inner()).len() as u64)
    }

    fn insert_first_user(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
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
                totp_secret: None,
                totp_enabled: false,
                pending_totp_secret: None,
            },
        );
        Ok(())
    }

    fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, AuthError> {
        let users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        Ok(users.get(username).map(|u| UserRecord {
            id: u.id.clone(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            password_hash: u.password_hash.clone(),
            totp_secret: u.totp_secret.clone(),
            totp_enabled: u.totp_enabled,
            pending_totp_secret: u.pending_totp_secret.clone(),
        }))
    }

    fn set_pending_totp_secret(&self, username: &str, secret_b32: &str) -> Result<(), AuthError> {
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(u) = users.get_mut(username) {
            u.pending_totp_secret = Some(secret_b32.to_string());
        }
        Ok(())
    }

    fn promote_pending_totp(&self, username: &str) -> Result<bool, AuthError> {
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        match users.get_mut(username) {
            Some(u) => match u.pending_totp_secret.take() {
                Some(secret) => {
                    u.totp_secret = Some(secret);
                    u.totp_enabled = true;
                    Ok(true)
                }
                None => Ok(false),
            },
            None => Ok(false),
        }
    }

    fn clear_totp(&self, username: &str) -> Result<bool, AuthError> {
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        match users.get_mut(username) {
            Some(u) => {
                u.totp_secret = None;
                u.totp_enabled = false;
                u.pending_totp_secret = None;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

// --- the auth runtime: store + sessions + hashing ---------------------------

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "chartcraft_session";

// --- login lockout (MF-1) ---------------------------------------------------

/// Failed-login bookkeeping for one username. In-memory; reset on success.
struct Attempts {
    count: u32,
    locked_until: Option<Instant>,
}

/// After this many failures within the window, the username is locked out.
const MAX_FAILURES: u32 = 5;
/// How long a lockout lasts.
const LOCKOUT: Duration = Duration::from_secs(15 * 60);

// --- session expiry (MF-2) --------------------------------------------------

/// Absolute session lifetime: a session is dead this long after it was issued,
/// no matter how active.
const SESSION_ABSOLUTE: Duration = Duration::from_secs(12 * 60 * 60);
/// Idle timeout: a session is dead this long after it was last used.
const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
/// How often the background sweep reclaims expired sessions.
pub const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// A live server-side session: the Principal plus the timestamps that bound its
/// lifetime (idle + absolute).
struct Session {
    principal: Principal,
    issued_at: Instant,
    last_seen: Instant,
    // How far this session has cleared authentication. A fresh register / a
    // password-only login lands `PendingMfa`; confirming TOTP or a login that
    // satisfies both factors lands `Full`.
    auth_level: AuthLevel,
}

/// Everything auth needs at request time: the users table plus the server-side
/// session map. Lives in `AppState` behind an `Arc`.
pub struct AuthState {
    store: Box<dyn AuthStore>,
    // ponytail: in-memory sessions (token -> Session); lost on restart.
    sessions: Mutex<HashMap<String, Session>>,
    // ponytail: login lockout is username-keyed and in-memory. An attacker can
    // thus deliberately lock out the real admin (DoS), and the state is lost on
    // restart. Acceptable for a single-admin local deploy; revisit with IP-based
    // limiting + exponential backoff for a multi-user deployment.
    attempts: Mutex<HashMap<String, Attempts>>,
    // N1: the last TOTP time-step this user successfully verified, per username.
    // A verify is accepted only if its matched step is STRICTLY greater, so a code
    // can't be replayed within its ~90 s validity window. Keyed by username and
    // shared across the live and the pending secret (steps are wall-clock-derived,
    // so they're directly comparable regardless of which secret matched).
    //
    // ponytail: in-memory, so a restart forgets the high-water mark and a code
    // could be replayed once across a restart. Acceptable for a single-box deploy;
    // a persisted used-step store is future work.
    last_totp_step: Mutex<HashMap<String, u64>>,
}

impl AuthState {
    pub fn new(store: Box<dyn AuthStore>) -> Self {
        AuthState {
            store,
            sessions: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
            last_totp_step: Mutex::new(HashMap::new()),
        }
    }

    /// Register the FIRST user (bootstrap). Returns the new Principal on success.
    /// The store insert is bootstrap-GUARDED (empty-table-only, atomically), so
    /// `Err(UsernameTaken)` here means a concurrent register already bootstrapped —
    /// the handler maps that to a 403 (registration closed).
    ///
    /// MF-3: input validation is enforced HERE, at the store-facing path, not in
    /// the handler — a future caller can't bypass it. A blank username or a
    /// password under the minimum length is rejected BEFORE any hashing.
    pub fn register(&self, creds: &Credentials) -> Result<Principal, AuthError> {
        if creds.username.trim().is_empty() {
            return Err(AuthError::InvalidInput("username must not be blank"));
        }
        if creds.password.chars().count() < MIN_PASSWORD_LEN {
            return Err(AuthError::InvalidInput(
                "password must be at least 12 characters",
            ));
        }
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

    /// MF-1: is this username currently locked out? Delegates to an `at` variant
    /// so tests can drive the clock. A lockout whose deadline has passed reads as
    /// unlocked (the counter is lazily cleared on the next failure/success).
    pub fn is_locked(&self, username: &str) -> bool {
        self.is_locked_at(username, Instant::now())
    }

    fn is_locked_at(&self, username: &str, now: Instant) -> bool {
        let attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        match attempts.get(username).and_then(|a| a.locked_until) {
            Some(until) => now < until,
            None => false,
        }
    }

    /// MF-1: record a failed login. After `MAX_FAILURES`, arm the lockout.
    pub fn record_failure(&self, username: &str) {
        self.record_failure_at(username, Instant::now());
    }

    fn record_failure_at(&self, username: &str, now: Instant) {
        let mut attempts = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let entry = attempts.entry(username.to_string()).or_insert(Attempts {
            count: 0,
            locked_until: None,
        });
        // An expired lockout resets the window before counting this failure.
        if let Some(until) = entry.locked_until {
            if now >= until {
                entry.count = 0;
                entry.locked_until = None;
            }
        }
        entry.count += 1;
        if entry.count >= MAX_FAILURES {
            entry.locked_until = Some(now + LOCKOUT);
        }
    }

    /// MF-1: clear the failure counter on a successful login.
    pub fn record_success(&self, username: &str) {
        self.attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(username);
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

    /// Mint a fresh session for a Principal at a given auth level, returning the
    /// opaque cookie token.
    pub fn create_session(&self, principal: Principal, level: AuthLevel) -> String {
        let token = new_session_token();
        let now = Instant::now();
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                token.clone(),
                Session {
                    principal,
                    issued_at: now,
                    last_seen: now,
                    auth_level: level,
                },
            );
        token
    }

    /// Resolve a session token to its Principal and auth level, if the session
    /// exists AND is not expired. Delegates to an `at` variant so tests can drive
    /// the clock.
    pub fn lookup_session(&self, token: &str) -> Option<(Principal, AuthLevel)> {
        self.lookup_session_at(token, Instant::now())
    }

    /// MF-2: like `lookup_session`, but with an explicit "now". A session past its
    /// absolute lifetime (`now - issued_at > ABSOLUTE`) or idle timeout
    /// (`now - last_seen > IDLE`) is removed and treated as absent (→ 401).
    /// Otherwise `last_seen` is refreshed and the Principal + level returned.
    fn lookup_session_at(&self, token: &str, now: Instant) -> Option<(Principal, AuthLevel)> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match sessions.get_mut(token) {
            Some(s) if session_expired(s, now) => {
                sessions.remove(token);
                None
            }
            Some(s) => {
                s.last_seen = now;
                Some((s.principal.clone(), s.auth_level))
            }
            None => None,
        }
    }

    /// Whether this user has confirmed TOTP (`totp_enabled`). Drives the
    /// `mfaEnrolled` field, read fresh from the store (it flips mid-session).
    pub fn mfa_enrolled(&self, username: &str) -> Result<bool, AuthError> {
        Ok(self
            .store
            .find_by_username(username)?
            .map(|u| u.totp_enabled)
            .unwrap_or(false))
    }

    /// Enroll (M1/M2): stage a TOTP secret in the PENDING slot and return the
    /// artifacts the client needs — the `otpauth://` provisioning URI, a base64-PNG
    /// QR of it, and the base32 secret for manual entry. The secret is returned
    /// ONLY here and never logged.
    ///
    /// Behavior depends on the user's current enrollment state:
    /// - NOT yet enabled, and a pending secret already exists → return THAT SAME
    ///   secret/URI/QR (idempotent: a reload must not rotate the secret and
    ///   invalidate an already-scanned QR).
    /// - NOT yet enabled, no pending secret → generate and stage a fresh one.
    /// - ALREADY enabled (re-key) → REQUIRE re-authentication: `code` must be a
    ///   valid LIVE TOTP code. If missing/invalid, return `Err(ReauthRequired)` and
    ///   touch NO secret. On success, stage a NEW pending secret; the live secret
    ///   keeps working until a confirm promotes the new one.
    pub fn totp_enroll(&self, username: &str, code: &str) -> Result<TotpEnrollment, AuthError> {
        self.totp_enroll_at(username, code, unix_now())
    }

    /// `totp_enroll` with an explicit unix "now" (seconds), so tests can drive the
    /// clock across the TOTP window — the `_at` idiom the session/lockout code uses.
    pub fn totp_enroll_at(
        &self,
        username: &str,
        code: &str,
        now: u64,
    ) -> Result<TotpEnrollment, AuthError> {
        let rec = self.store.find_by_username(username)?;
        let (enabled, pending) = match &rec {
            Some(u) => (u.totp_enabled, u.pending_totp_secret.clone()),
            // Unknown user: no session could reach here for a missing user, but stay
            // defensive — treat as a fresh (not-enabled, no-pending) enroll.
            None => (false, None),
        };

        if enabled {
            // Re-key path: require a current valid LIVE code before staging anything.
            if !self.live_code_valid_consuming(username, code, now)? {
                return Err(AuthError::ReauthRequired);
            }
            let secret_b32 = Secret::generate().to_base32();
            self.store.set_pending_totp_secret(username, &secret_b32)?;
            return self.enrollment_artifacts(&secret_b32, username);
        }

        // Not enabled: reuse an existing pending secret (idempotent reload) or mint
        // a fresh one.
        let secret_b32 = match pending {
            Some(s) => s,
            None => {
                let s = Secret::generate().to_base32();
                self.store.set_pending_totp_secret(username, &s)?;
                s
            }
        };
        self.enrollment_artifacts(&secret_b32, username)
    }

    /// Build the enroll response (URI + QR + secret) from a base32 secret.
    fn enrollment_artifacts(
        &self,
        secret_b32: &str,
        username: &str,
    ) -> Result<TotpEnrollment, AuthError> {
        let totp = build_totp(secret_b32, username).map_err(AuthError::Db)?;
        let otpauth_uri = totp
            .to_url()
            .map_err(|e| AuthError::Db(format!("totp url: {e}")))?;
        let qr_png_base64 = totp
            .to_qr_base64()
            .map_err(|e| AuthError::Db(format!("totp qr: {e}")))?;
        Ok(TotpEnrollment {
            otpauth_uri,
            qr_png_base64,
            secret: secret_b32.to_string(),
        })
    }

    /// Confirm (M1/M2 + N2): verify `code` against the user's PENDING secret with
    /// ±1-step skew; on success ATOMICALLY promote it to the live secret (enabling
    /// TOTP) and return `true`. A missing pending secret or a wrong code returns
    /// `false` (never a hint which). N1 replay protection applies: a replayed step
    /// is rejected as `false`.
    pub fn totp_confirm(&self, username: &str, code: &str) -> Result<bool, AuthError> {
        self.totp_confirm_at(username, code, unix_now())
    }

    /// `totp_confirm` with an explicit unix "now" (seconds), for deterministic tests.
    pub fn totp_confirm_at(&self, username: &str, code: &str, now: u64) -> Result<bool, AuthError> {
        if !self.pending_code_valid_consuming(username, code, now)? {
            return Ok(false);
        }
        // Atomic promote: pending → live, enabled=1, pending cleared. The guard in
        // the store makes a vanished pending secret a safe no-op (→ false).
        self.store.promote_pending_totp(username)
    }

    /// M5 break-glass: clear ALL of a user's TOTP state so they re-enroll on next
    /// login. Returns `Ok(true)` if the user existed and was cleared.
    pub fn reset_mfa(&self, username: &str) -> Result<bool, AuthError> {
        self.store.clear_totp(username)
    }

    /// Verify a TOTP `code` against the user's LIVE secret (login + re-key gate),
    /// consuming the matched step for N1 replay protection. A user with no live
    /// secret → `false`.
    pub fn totp_code_valid(&self, username: &str, code: &str) -> Result<bool, AuthError> {
        self.live_code_valid_consuming(username, code, unix_now())
    }

    /// Verify `code` against the LIVE secret and consume its step (N1).
    fn live_code_valid_consuming(
        &self,
        username: &str,
        code: &str,
        now: u64,
    ) -> Result<bool, AuthError> {
        let secret = self.store.find_by_username(username)?.and_then(|u| u.totp_secret);
        self.code_matches_fresh_step(username, code, secret.as_deref(), now)
    }

    /// Verify `code` against the PENDING secret and consume its step (N1).
    fn pending_code_valid_consuming(
        &self,
        username: &str,
        code: &str,
        now: u64,
    ) -> Result<bool, AuthError> {
        let secret = self
            .store
            .find_by_username(username)?
            .and_then(|u| u.pending_totp_secret);
        self.code_matches_fresh_step(username, code, secret.as_deref(), now)
    }

    /// Core N1 check: does `code` verify against `secret` at a step STRICTLY newer
    /// than this user's last-accepted step? On a match at a fresh step, record it
    /// and return `true`; a replay (step ≤ last-accepted) or any non-match → `false`.
    /// A `None` secret → `false`. Never logs the secret or the code. `now` is unix
    /// seconds (driven by callers / tests via the `_at` variants).
    fn code_matches_fresh_step(
        &self,
        username: &str,
        code: &str,
        secret: Option<&str>,
        now: u64,
    ) -> Result<bool, AuthError> {
        let secret = match secret {
            Some(s) => s,
            None => return Ok(false),
        };
        let totp = match build_totp(secret, username) {
            Ok(t) => t,
            // M3: a corrupt stored secret must be DIAGNOSABLE, not look exactly like
            // a wrong code. The error is already secret-free (build_totp never
            // includes the secret), and we log neither the secret nor the code.
            Err(e) => {
                eprintln!("[chartcraft] TOTP build failed for a stored secret (user elided): {e}");
                return Ok(false);
            }
        };
        let step = match totp.check(code, now) {
            Some(s) => s,
            None => return Ok(false),
        };
        // N1: reject a step we've already accepted for this user (replay window).
        let mut steps = self.last_totp_step.lock().unwrap_or_else(|e| e.into_inner());
        match steps.get(username) {
            Some(&last) if step <= last => Ok(false),
            _ => {
                steps.insert(username.to_string(), step);
                Ok(true)
            }
        }
    }

    /// MF-2: reclaim every expired session. Called on an interval by the
    /// background sweep so abandoned tokens don't linger until a lookup clears
    /// them. Takes an explicit `now` so it can be tested directly.
    pub fn sweep_expired(&self, now: Instant) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, s| !session_expired(s, now));
    }

    /// Invalidate a session (logout). Idempotent.
    pub fn destroy_session(&self, token: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }
}

/// Minimum accepted password length (MF-3). Counts Unicode scalar values, not
/// bytes, so a 12-char passphrase of multibyte characters still passes.
const MIN_PASSWORD_LEN: usize = 12;

// --- TOTP MFA ---------------------------------------------------------------

/// The `issuer` shown in the authenticator app (and embedded in the otpauth URI).
const TOTP_ISSUER: &str = "ChartCraft";
/// Accepted clock skew in 30-second steps. 1 → the code for the previous OR next
/// step also verifies (modest tolerance for client/server clock drift), no more.
///
/// N1: single-use is now enforced by the caller — every successful verify records
/// the matched step in `last_totp_step` and rejects any step ≤ the last accepted,
/// so a code can't be replayed within its validity window.
const TOTP_SKEW: u16 = 1;

/// What `/auth/totp/enroll` hands back to the client. The `secret` (base32) is
/// returned ONLY here — it's never persisted in plaintext to a log and never
/// echoed by any other endpoint.
pub struct TotpEnrollment {
    pub otpauth_uri: String,
    pub qr_png_base64: String,
    pub secret: String,
}

/// Build a `Totp` from a base32 secret for a given account, with the fixed issuer
/// and the modest ±1-step skew. Shared by enroll (URI/QR generation) and
/// verification (confirm + login) so both sides agree on every parameter. Errors
/// stringly — a bad base32 secret or a build failure both collapse to a message
/// that never contains the secret itself.
fn build_totp(secret_b32: &str, account: &str) -> Result<Totp, String> {
    let secret = Secret::try_from_base32(secret_b32).map_err(|_| "invalid secret".to_string())?;
    TotpBuilder::new()
        .with_secret(secret)
        .with_issuer(Some(TOTP_ISSUER))
        .with_account_name(account)
        .with_skew(TOTP_SKEW)
        .build()
        .map_err(|e: TotpError| e.to_string())
}

/// True when a session has outlived its absolute lifetime OR its idle timeout.
fn session_expired(s: &Session, now: Instant) -> bool {
    now.duration_since(s.issued_at) > SESSION_ABSOLUTE
        || now.duration_since(s.last_seen) > SESSION_IDLE
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

/// Current unix time in seconds, for TOTP step derivation. Matches what totp-rs'
/// own `*_current` helpers use (`SystemTime` since the epoch).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
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

/// N1: `Secure` is config-driven. When `CHARTCRAFT_SECURE_COOKIES` is set to a
/// truthy value (`1`/`true`), the session cookie carries `; Secure` so it only
/// rides TLS. Default OFF so `http://localhost` dev still works.
fn secure_cookies_enabled() -> bool {
    matches!(
        std::env::var("CHARTCRAFT_SECURE_COOKIES").ok().as_deref(),
        Some("1") | Some("true")
    )
}

/// Build the `Set-Cookie` value that plants a session token.
///
/// Flags: `HttpOnly` (no JS access), `SameSite=Strict` (no cross-site send),
/// `Path=/` (whole app), and `Secure` when `CHARTCRAFT_SECURE_COOKIES` is set
/// (N1). Without `Secure` the token can ride a plaintext request, so production
/// behind TLS MUST set the env var.
///
/// ponytail: the `__Host-` cookie name prefix is a future hardening — it pins the
/// cookie to this exact host+path with no Domain and REQUIRES Secure, so it can't
/// be adopted until Secure is always on (i.e. not in http-localhost dev).
pub fn set_session_cookie(token: &str) -> String {
    set_session_cookie_with(token, secure_cookies_enabled())
}

/// Inner builder taking `secure` explicitly, so it's testable without mutating
/// process env (which would race parallel tests).
fn set_session_cookie_with(token: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/{secure_attr}")
}

/// Build the `Set-Cookie` value that clears the session cookie (logout).
pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

// --- the extractor ----------------------------------------------------------

/// Axum extractor: a FULLY-authenticated user (password + TOTP satisfied). A FHIR
/// handler that takes an `AuthPrincipal` is gated — without a valid session cookie
/// the extractor rejects with 401 + an `OperationOutcome`; a valid session that
/// has NOT cleared MFA (`PendingMfa`) is rejected with 403 ("multi-factor
/// enrollment required"), so PHI stays behind MFA. Auth endpoints and
/// static/`ServeDir` routes simply don't take this extractor, so they stay
/// reachable logged-out.
pub struct AuthPrincipal(pub Principal);

/// Build the 401 both extractors share for a missing/invalid session.
fn unauthorized_oo() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(operation_outcome(
            "error",
            "login",
            "authentication required",
        )),
    )
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthPrincipal
where
    crate::AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = crate::AppState::from_ref(state);
        let token = session_token_from_headers(&parts.headers).ok_or_else(unauthorized_oo)?;
        match app.auth.lookup_session(&token) {
            Some((principal, AuthLevel::Full)) => Ok(AuthPrincipal(principal)),
            // A valid session that hasn't cleared MFA is authenticated but not
            // authorized for PHI → 403, not 401.
            Some((_, AuthLevel::PendingMfa)) => Err((
                StatusCode::FORBIDDEN,
                Json(operation_outcome(
                    "error",
                    "forbidden",
                    "multi-factor enrollment required",
                )),
            )),
            None => Err(unauthorized_oo()),
        }
    }
}

/// Axum extractor: ANY valid session (PendingMfa OR Full). Used by the
/// `/auth/totp/*` endpoints and `/auth/me`, which must be reachable by a
/// not-yet-MFA'd session. Carries the level so a handler (e.g. `me`) can report
/// it. A missing/invalid session → 401, same shape as `AuthPrincipal`.
pub struct MfaPrincipal(pub Principal, pub AuthLevel);

#[async_trait]
impl<S> FromRequestParts<S> for MfaPrincipal
where
    crate::AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = crate::AppState::from_ref(state);
        let token = session_token_from_headers(&parts.headers).ok_or_else(unauthorized_oo)?;
        match app.auth.lookup_session(&token) {
            Some((principal, level)) => Ok(MfaPrincipal(principal, level)),
            None => Err(unauthorized_oo()),
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
                password: "s3cr3t-password".into(),
                display_name: "Dr Alice".into(),
                totp: String::new(),
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
                totp: String::new(),
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
        let token = state.create_session(p, AuthLevel::Full);
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

    // MF-1: lockout counter.
    #[test]
    fn lockout_arms_after_five_failures_and_success_resets() {
        let state = AuthState::new(Box::new(InMemoryAuthStore::default()));
        let now = Instant::now();
        assert!(!state.is_locked_at("admin", now), "not locked initially");

        // Four failures stay BELOW the threshold, then a success clears the count.
        for _ in 0..4 {
            state.record_failure_at("admin", now);
        }
        assert!(!state.is_locked_at("admin", now), "4 failures < 5, not yet locked");
        state.record_success("admin");

        // Now five fresh failures DO arm the lockout.
        for _ in 0..5 {
            state.record_failure_at("admin", now);
        }
        assert!(state.is_locked_at("admin", now), "5 failures → locked");

        // The lockout lifts once its window passes.
        let later = now + LOCKOUT + Duration::from_secs(1);
        assert!(!state.is_locked_at("admin", later), "lockout expires after the window");
    }

    // MF-2: a session forced past its lifetime is rejected (and removed).
    #[test]
    fn expired_session_is_rejected_by_lookup() {
        let state = AuthState::new(Box::new(InMemoryAuthStore::default()));
        let p = Principal { id: "u1".into(), username: "u".into(), display_name: "U".into() };
        let token = state.create_session(p, AuthLevel::Full);
        let base = Instant::now();

        // Idle timeout: last_seen too old → None, and the entry is purged.
        assert!(
            state.lookup_session_at(&token, base + SESSION_IDLE + Duration::from_secs(1)).is_none(),
            "idle-expired session rejected"
        );
        assert!(
            state.lookup_session_at(&token, base).is_none(),
            "a rejected session is removed, not left behind"
        );

        // Absolute lifetime: a session kept NON-idle (refreshed inside the idle
        // window the whole time) is still killed once it passes the absolute cap.
        // We step forward in 20-min hops (< the 30-min idle limit), each refreshing
        // last_seen, right up to just under 12 h — proving it stays live on idle —
        // then check at 12 h + 1 s. That final check is within one idle window of
        // the last refresh, so a None there can ONLY come from the absolute branch.
        let token2 = state.create_session(Principal {
            id: "u2".into(), username: "u2".into(), display_name: "U2".into(),
        }, AuthLevel::Full);
        let t0 = Instant::now();
        let step = Duration::from_secs(20 * 60);
        let mut t = step;
        while t < SESSION_ABSOLUTE {
            assert!(
                state.lookup_session_at(&token2, t0 + t).is_some(),
                "session stays live while actively used inside the idle window"
            );
            t += step;
        }
        let past_absolute = t0 + SESSION_ABSOLUTE + Duration::from_secs(1);
        assert!(
            state.lookup_session_at(&token2, past_absolute).is_none(),
            "absolute-expired session rejected even though never idle"
        );
    }

    // MF-2: the sweep reclaims expired sessions.
    #[test]
    fn sweep_removes_expired_sessions() {
        let state = AuthState::new(Box::new(InMemoryAuthStore::default()));
        let token = state.create_session(Principal {
            id: "u".into(), username: "u".into(), display_name: "U".into(),
        }, AuthLevel::Full);
        let now = Instant::now();
        state.sweep_expired(now + SESSION_ABSOLUTE + Duration::from_secs(1));
        assert!(
            state.lookup_session_at(&token, now).is_none(),
            "swept session no longer resolves"
        );
    }

    // MF-3: register input validation (store-facing path).
    #[test]
    fn register_rejects_blank_username_and_short_password() {
        let state = AuthState::new(Box::new(InMemoryAuthStore::default()));
        let blank = state.register(&Credentials {
            username: "   ".into(),
            password: "a-perfectly-long-password".into(),
            display_name: "X".into(),
            totp: String::new(),
        });
        assert!(matches!(blank, Err(AuthError::InvalidInput(_))), "blank username rejected");

        let short = state.register(&Credentials {
            username: "admin".into(),
            password: "short".into(), // < 12 chars
            display_name: "X".into(),
            totp: String::new(),
        });
        assert!(matches!(short, Err(AuthError::InvalidInput(_))), "short password rejected");

        // A valid bootstrap still succeeds.
        let ok = state.register(&Credentials {
            username: "admin".into(),
            password: "twelve-chars-ok".into(),
            display_name: "Admin".into(),
            totp: String::new(),
        });
        assert!(ok.is_ok(), "valid bootstrap registers");
    }

    /// Generate a code for a base32 secret at an explicit unix time, with the same
    /// parameters the server builds with (issuer/account/skew).
    fn code_at(secret_b32: &str, username: &str, at: u64) -> String {
        build_totp(secret_b32, username).unwrap().generate(at).to_string()
    }

    /// M1/M2: a re-enroll by an enabled user stages a NEW secret and a confirm
    /// atomically swaps it in — old code stops working, new code works. Driven on a
    /// FIXED unix clock (`_at` variants) so four strictly-increasing steps don't
    /// have to fit inside one real 30 s verification window.
    #[test]
    fn reenroll_confirm_atomically_swaps_secret_driven_clock() {
        let state = AuthState::new(Box::new(InMemoryAuthStore::default()));
        state
            .register(&Credentials {
                username: "admin".into(),
                password: "a-long-enough-pw".into(),
                display_name: "Admin".into(),
                totp: String::new(),
            })
            .unwrap();

        let t0: u64 = 1_700_000_000; // fixed epoch; +30 per step
        let step = 30u64;

        // Enroll (not yet enabled — no code needed) stages a pending secret...
        let enroll = state.totp_enroll_at("admin", "", t0).unwrap();
        let old_secret = enroll.secret.clone();
        // ...and confirm at t0 promotes it to live (consumes step @ t0).
        let confirm_code = code_at(&old_secret, "admin", t0);
        assert!(state.totp_confirm_at("admin", &confirm_code, t0).unwrap());
        assert!(state.mfa_enrolled("admin").unwrap());

        // Re-enroll at t0+30 with a current LIVE code → stages a NEW pending secret.
        let reauth = code_at(&old_secret, "admin", t0 + step);
        let rekey = state.totp_enroll_at("admin", &reauth, t0 + step).unwrap();
        let new_secret = rekey.secret.clone();
        assert_ne!(new_secret, old_secret, "re-key stages a fresh secret");

        // Confirm the NEW secret at t0+60 → atomic promote.
        let new_confirm = code_at(&new_secret, "admin", t0 + 2 * step);
        assert!(state.totp_confirm_at("admin", &new_confirm, t0 + 2 * step).unwrap());

        // At t0+90: the OLD secret no longer verifies (swapped out)...
        let old_code = code_at(&old_secret, "admin", t0 + 3 * step);
        assert!(
            !state.live_code_valid_consuming("admin", &old_code, t0 + 3 * step).unwrap(),
            "old secret stops working after the atomic swap"
        );
        // ...and the NEW secret does.
        let new_code = code_at(&new_secret, "admin", t0 + 3 * step);
        assert!(
            state.live_code_valid_consuming("admin", &new_code, t0 + 3 * step).unwrap(),
            "new secret works after the atomic swap"
        );
    }

    /// M4: `init` fails fast on a users table missing the expected columns, instead
    /// of booting and 500-ing at first login.
    #[test]
    fn init_rejects_outdated_schema() {
        let conn = Connection::open_in_memory().unwrap();
        // An OLD schema: no `pending_totp_secret` column.
        conn.execute_batch(
            "CREATE TABLE users (
                 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                 display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
                 totp_secret TEXT NULL, totp_enabled INTEGER NOT NULL DEFAULT 0,
                 created TEXT NOT NULL
             );",
        )
        .unwrap();
        let err = SqliteAuthStore::init(&conn).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("schema is outdated"), "clear outdated-schema error: {msg}");
        assert!(msg.contains("pending_totp_secret"), "names the missing column: {msg}");
    }

    // N1: Secure flag is config-driven, tested without touching process env.
    #[test]
    fn secure_cookie_flag_is_appended_when_enabled() {
        let off = set_session_cookie_with("tok", false);
        assert!(!off.contains("Secure"), "Secure omitted by default");
        assert!(off.contains("HttpOnly") && off.contains("SameSite=Strict") && off.contains("Path=/"));

        let on = set_session_cookie_with("tok", true);
        assert!(on.contains("; Secure"), "Secure appended when enabled");
        assert!(on.contains("HttpOnly") && on.contains("SameSite=Strict") && on.contains("Path=/"));
    }
}
