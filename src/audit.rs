//! The governance spine: a `Provenance` on every write, an `AuditEvent` on
//! every read. Both are written through the same `ChartStore` so they persist,
//! and both get a fresh uuid every time — the audit log is append-only.

use serde_json::json;

use crate::fhir::now_iso8601;
use crate::store::{ChartStore, StoreError};

// ponytail: real cryptographic signing (and the signer's identity) arrives with
// auth in M4. For now every write is attributed to this fixed demo agent.
const SIGNER_LABEL: &str = "ChartCraft (unsigned demo)";

/// Record a `Provenance` resource targeting a written resource.
pub fn record_provenance(
    store: &dyn ChartStore,
    resource_type: &str,
    id: &str,
) -> Result<(), StoreError> {
    let prov_id = uuid::Uuid::new_v4().to_string();
    let provenance = json!({
        "resourceType": "Provenance",
        "id": prov_id,
        "target": [{"reference": format!("{resource_type}/{id}")}],
        "recorded": now_iso8601(),
        "agent": [{
            "who": {"display": SIGNER_LABEL},
        }],
    });
    store.put("Provenance", &prov_id, &provenance)?;
    Ok(())
}

/// Append an `AuditEvent` recording a search over a clinical resource type.
///
/// ponytail: ONE AuditEvent per search, not one per matched resource — the
/// audited event is "a query ran", and its scope is the type (+ optional patient
/// filter), not each row returned. We also don't guard against auditing searches
/// of AuditEvent/Provenance here: those types aren't in SUPPORTED_TYPES, so the
/// handler 400s before ever reaching this function, making the guard moot.
pub fn record_audit_search(
    store: &dyn ChartStore,
    resource_type: &str,
    patient: Option<&str>,
) -> Result<(), StoreError> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let query = match patient {
        Some(p) => format!("{resource_type}?patient={p}"),
        None => resource_type.to_string(),
    };
    let event = json!({
        "resourceType": "AuditEvent",
        "id": event_id,
        // "E" = execute, the FHIR AuditEvent action for a search/query.
        "action": "E",
        "recorded": now_iso8601(),
        "entity": [{"what": {"reference": query}}],
    });
    store.put("AuditEvent", &event_id, &event)?;
    Ok(())
}

/// Append an `AuditEvent` recording a write (create/update) of a clinical
/// resource. `action` is the FHIR AuditEvent code: `"C"` (create) or `"U"`
/// (update). Mirrors `record_audit_read` — a write is a PHI touch too, so it
/// must be audited, not just attributed via Provenance.
pub fn record_audit_write(
    store: &dyn ChartStore,
    resource_type: &str,
    id: &str,
    action: &str,
) -> Result<(), StoreError> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let event = json!({
        "resourceType": "AuditEvent",
        "id": event_id,
        "action": action,
        "recorded": now_iso8601(),
        "entity": [{"what": {"reference": format!("{resource_type}/{id}")}}],
    });
    store.put("AuditEvent", &event_id, &event)?;
    Ok(())
}

/// Append an `AuditEvent` recording a successful read of a clinical resource.
pub fn record_audit_read(
    store: &dyn ChartStore,
    resource_type: &str,
    id: &str,
) -> Result<(), StoreError> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let event = json!({
        "resourceType": "AuditEvent",
        "id": event_id,
        "action": "R",
        "recorded": now_iso8601(),
        "entity": [{"what": {"reference": format!("{resource_type}/{id}")}}],
    });
    store.put("AuditEvent", &event_id, &event)?;
    Ok(())
}
