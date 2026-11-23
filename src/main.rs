//! ChartCraft binary — a thin wrapper over the `chartcraft` library crate.
//!
//! All the FHIR/auth/handler logic lives in the library (`src/lib.rs` and its
//! modules). This binary only does application wiring: parse the environment
//! (`CHARTCRAFT_BIND`, `CHARTCRAFT_DEMO`) and the `--reset-mfa` CLI, construct the
//! SQLite-backed `AppState`, run demo seeding on first boot, print the startup
//! banner, resolve the bind address, and `axum::serve` the library's
//! `core_router`.

use std::sync::Arc;

use chartcraft::auth::{self, AuthState, SqliteAuthStore};
use chartcraft::server::seed_demo;
use chartcraft::store::SqliteStore;
use chartcraft::{core_router, AppState, SharedStore};

/// Interpret an env value as a boolean flag: `"1"` or `"true"` (any case) is on,
/// everything else (including unset) is off. Pure, so it's unit-testable without
/// touching the process environment.
fn is_truthy(val: Option<String>) -> bool {
    matches!(val.as_deref(), Some("1") | Some("true") | Some("TRUE") | Some("True"))
}

/// Resolve the bind address: `CHARTCRAFT_BIND` when set and non-empty, else the
/// local-first default `127.0.0.1:8080`. Pure (takes the env value) so the default
/// and the override are unit-testable. The container sets `0.0.0.0:8080`.
fn resolve_bind(val: Option<String>) -> String {
    match val {
        Some(s) if !s.trim().is_empty() => s,
        _ => "127.0.0.1:8080".to_string(),
    }
}

/// M5 break-glass: `chartcraft --reset-mfa <username>` clears a user's TOTP state
/// (live secret, pending secret, `totp_enabled`) so they re-enroll on next login —
/// the recovery path for a lost authenticator. Handled BEFORE the server starts;
/// opens only the auth store, performs the reset, prints a confirmation, and exits.
/// Returns `true` when the flag was present (so `main` should not start the server).
fn maybe_reset_mfa() -> bool {
    let args: Vec<String> = std::env::args().collect();
    let idx = match args.iter().position(|a| a == "--reset-mfa") {
        Some(i) => i,
        None => return false,
    };
    let username = match args.get(idx + 1) {
        Some(u) if !u.is_empty() => u,
        _ => {
            eprintln!("usage: chartcraft --reset-mfa <username>");
            std::process::exit(2);
        }
    };
    let auth_store = SqliteAuthStore::open("chartcraft.db").expect("open auth store");
    let auth = AuthState::new(Box::new(auth_store));
    match auth.reset_mfa(username) {
        Ok(true) => {
            println!("MFA reset for '{username}'; they will re-enroll TOTP on next login.");
            std::process::exit(0);
        }
        Ok(false) => {
            eprintln!("no such user: '{username}'");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[chartcraft] --reset-mfa failed: {e}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    // M5: handle the break-glass CLI flag before any server setup. It exits the
    // process, so control only returns here when the flag was absent.
    maybe_reset_mfa();

    let demo = is_truthy(std::env::var("CHARTCRAFT_DEMO").ok());

    let store: SharedStore =
        Arc::new(SqliteStore::open("chartcraft.db").expect("open chartcraft.db"));
    // Auth store shares the db FILE but owns its own connection — the clinical
    // store and the auth store stay cleanly separated.
    let auth_store = SqliteAuthStore::open("chartcraft.db").expect("open auth store");
    let auth = Arc::new(AuthState::new(Box::new(auth_store)));

    // DEMO ONLY: on first boot (no users yet) seed the demo admin + sample chart.
    // The empty-users gate makes this idempotent across restarts of the same volume.
    if demo {
        match auth.no_users_yet() {
            Ok(true) => seed_demo(&store, &auth),
            Ok(false) => {}
            Err(e) => eprintln!("[chartcraft] demo seed: could not check users: {e}"),
        }
        println!(
            "============================================================\n\
             DEMO MODE: authentication is relaxed and all data is fake.\n\
             NEVER use with real patients or in production.\n\
             Demo login:  demo / demodemo1234\n\
             ============================================================"
        );
    }

    let state = AppState {
        store,
        auth,
        demo,
    };

    // MF-2: periodic sweep that reclaims expired sessions, so abandoned tokens are
    // freed even if nothing ever looks them up again. Holds its own Arc clone.
    {
        let auth = state.auth.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(auth::SESSION_SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                auth.sweep_expired(std::time::Instant::now());
            }
        });
    }

    let bind = resolve_bind(std::env::var("CHARTCRAFT_BIND").ok());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    println!(
        "ChartCraft listening on http://{bind} \
         (auth at /auth/*, POST/GET /:resource_type, GET/PUT /:resource_type/:id, \
         GET /Patient/:id/$superbill, GET /metadata, static web/ at /)"
    );
    axum::serve(listener, core_router(state)).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `resolve_bind` defaults to the local-first address when unset/blank and
    /// honors an explicit override.
    #[test]
    fn resolve_bind_default_and_override() {
        assert_eq!(resolve_bind(None), "127.0.0.1:8080");
        assert_eq!(resolve_bind(Some("".into())), "127.0.0.1:8080");
        assert_eq!(resolve_bind(Some("   ".into())), "127.0.0.1:8080");
        assert_eq!(resolve_bind(Some("0.0.0.0:8080".into())), "0.0.0.0:8080");
        assert_eq!(resolve_bind(Some("127.0.0.1:9000".into())), "127.0.0.1:9000");
    }

    /// `is_truthy` accepts only "1"/"true" (any case); everything else is off.
    #[test]
    fn is_truthy_only_1_and_true() {
        assert!(is_truthy(Some("1".into())));
        assert!(is_truthy(Some("true".into())));
        assert!(is_truthy(Some("TRUE".into())));
        assert!(!is_truthy(Some("0".into())));
        assert!(!is_truthy(Some("yes".into())));
        assert!(!is_truthy(Some("".into())));
        assert!(!is_truthy(None));
    }
}
