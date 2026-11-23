//! The governance spine: a `Provenance` on every write, an `AuditEvent` on
//! every read/search/write. These are the BUILDERS — each returns a `WriteOp`
//! (and a fresh uuid per call, keeping the audit log append-only). The handler
//! composes them into ONE atomic `commit`, so a resource and its governance
//! records persist all-or-nothing. The hash-chaining of AuditEvents happens in
//! the store's `commit`, not here, so every path that writes an AuditEvent is
//! chained by construction.

use serde_json::json;

use crate::auth::Principal;
use crate::fhir::now_iso8601;
use crate::store::WriteOp;

/// The FHIR `agent.who` reference for the authenticated signer: the real
/// logged-in user (M4), replacing the former fixed demo label. `display` is the
/// human name shown in the chart; `identifier.value` is the stable user id so the
/// signer is answerable, not just a name.
fn agent_who(principal: &Principal) -> serde_json::Value {
    json!({
        "display": principal.display_name,
        "identifier": {"value": principal.id},
    })
}

/// Build a `Provenance` WriteOp targeting a written resource, signed by the
/// authenticated user.
pub fn provenance_op(resource_type: &str, id: &str, principal: &Principal) -> WriteOp {
    let prov_id = uuid::Uuid::new_v4().to_string();
    let provenance = json!({
        "resourceType": "Provenance",
        "id": prov_id,
        "target": [{"reference": format!("{resource_type}/{id}")}],
        "recorded": now_iso8601(),
        "agent": [{
            "who": agent_who(principal),
        }],
    });
    WriteOp::new("Provenance", &prov_id, provenance)
}

/// Build an `AuditEvent` WriteOp for a search over a clinical resource type.
///
/// ponytail: ONE AuditEvent per search, not one per matched resource — the
/// audited event is "a query ran", and its scope is the type (+ optional patient
/// filter), not each row returned.
pub fn audit_search_op(
    resource_type: &str,
    patient: Option<&str>,
    principal: &Principal,
) -> WriteOp {
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
        "agent": [{"who": agent_who(principal)}],
        "entity": [{"what": {"reference": query}}],
    });
    WriteOp::new("AuditEvent", &event_id, event)
}

/// Build an `AuditEvent` WriteOp for a write (create/update) of a clinical
/// resource. `action` is the FHIR AuditEvent code: `"C"` (create) or `"U"`
/// (update). A write is a PHI touch too, so it must be audited, not just
/// attributed via Provenance.
pub fn audit_write_op(
    resource_type: &str,
    id: &str,
    action: &str,
    principal: &Principal,
) -> WriteOp {
    let event_id = uuid::Uuid::new_v4().to_string();
    let event = json!({
        "resourceType": "AuditEvent",
        "id": event_id,
        "action": action,
        "recorded": now_iso8601(),
        "agent": [{"who": agent_who(principal)}],
        "entity": [{"what": {"reference": format!("{resource_type}/{id}")}}],
    });
    WriteOp::new("AuditEvent", &event_id, event)
}

/// Build an `AuditEvent` WriteOp recording a successful read of a clinical
/// resource.
pub fn audit_read_op(resource_type: &str, id: &str, principal: &Principal) -> WriteOp {
    let event_id = uuid::Uuid::new_v4().to_string();
    let event = json!({
        "resourceType": "AuditEvent",
        "id": event_id,
        "action": "R",
        "recorded": now_iso8601(),
        "agent": [{"who": agent_who(principal)}],
        "entity": [{"what": {"reference": format!("{resource_type}/{id}")}}],
    });
    WriteOp::new("AuditEvent", &event_id, event)
}
