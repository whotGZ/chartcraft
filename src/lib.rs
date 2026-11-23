//! ChartCraft — the embeddable, FHIR-native EMR core, as a library.
//!
//! This crate is the reusable core that the `chartcraft` binary (a thin wrapper
//! in `src/main.rs`) is built on, and that a downstream crate — e.g. a private
//! billing/claims layer — can depend on to compose its OWN routes onto the core.
//!
//! Generic CRUD plus type-level search over any supported US Core resource type,
//! persisted through a [`store::ChartStore`] (SQLite for the real binary,
//! in-memory for tests), with a governance spine — a `Provenance` and an
//! `AuditEvent` on every create/update, an `AuditEvent` on every read and search —
//! plus a `/metadata` CapabilityStatement. The static web frontend is served from
//! `web/` as a fallback behind the FHIR routes.
//!
//! The store is append-only and versioned: a write never overwrites, it appends a
//! new version and retains the old (history is preserved). A single atomic
//! `commit(&[WriteOp])` is the ONE write path, so a clinical resource and its
//! Provenance + AuditEvent persist all-or-nothing. Every `AuditEvent` is linked
//! into a SHA-256 hash chain that `verify_audit_chain` can recompute end-to-end,
//! and governance records (AuditEvent/Provenance) are insert-only. Patient-scoped
//! queries go through `find_by_patient` over a promoted, indexed `patient_ref`
//! column.
//!
//! Milestone 4 adds authentication: local username/password login with argon2id
//! hashing and server-side sessions, an [`AuthPrincipal`] extractor gating every
//! FHIR data endpoint (`/auth/*`, `GET /`, and `/static/*` stay reachable
//! logged-out so the login page loads), and the authenticated user threaded into
//! the governance spine as the real Provenance/AuditEvent signer.
//!
//! # Embedding the core
//!
//! A downstream crate builds the stores, wraps them in an [`AppState`], and merges
//! its own routes onto [`core_router`] — gating them with the same [`AuthPrincipal`]
//! (Full-session) extractor, and reading FHIR resources through
//! [`store::ChartStore`]:
//!
//! ```no_run
//! use std::sync::Arc;
//! use axum::{routing::get, Router};
//! use chartcraft::{core_router, AppState, AuthPrincipal, SharedStore};
//! use chartcraft::store::{ChartStore, SqliteStore};
//! use chartcraft::auth::{AuthState, SqliteAuthStore};
//!
//! // A downstream route, gated by the core's Full-session extractor. Because the
//! // downstream router carries `AppState` as its state, axum's blanket
//! // `FromRef<T> for T` makes `AuthPrincipal` extract with no extra wiring.
//! async fn my_claims(AuthPrincipal(_who): AuthPrincipal) -> &'static str {
//!     "ok"
//! }
//!
//! # fn demo() {
//! let store: SharedStore = Arc::new(SqliteStore::open("chartcraft.db").unwrap());
//! let auth = Arc::new(AuthState::new(Box::new(
//!     SqliteAuthStore::open("chartcraft.db").unwrap(),
//! )));
//! let state = AppState { store, auth, demo: false };
//!
//! let mine: Router = Router::new()
//!     .route("/billing/claims", get(my_claims))
//!     .with_state(state.clone());
//!
//! let app: Router = core_router(state).merge(mine);
//! # let _ = app;
//! # }
//! ```

pub mod audit;
pub mod auth;
pub mod fhir;
pub mod server;
pub mod store;

pub use auth::{AuthPrincipal, MfaPrincipal};
pub use server::{core_router, AppState, SharedStore};
