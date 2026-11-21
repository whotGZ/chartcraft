//! FHIR R4 helpers: the supported resource allowlist, small builders for
//! `OperationOutcome` and `CapabilityStatement`, and an ISO-8601 timestamp.

use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// US Core clinical resource types ChartCraft exposes over the REST API.
/// Unknown types are rejected with a 400.
pub const SUPPORTED_TYPES: &[&str] = &[
    "Patient",
    "Condition",
    "MedicationRequest",
    "AllergyIntolerance",
    "Observation",
    "DocumentReference",
];

pub fn is_supported(resource_type: &str) -> bool {
    SUPPORTED_TYPES.contains(&resource_type)
}

/// Build a FHIR `OperationOutcome` with a single issue.
pub fn operation_outcome(severity: &str, code: &str, diagnostics: &str) -> Value {
    json!({
        "resourceType": "OperationOutcome",
        "issue": [{
            "severity": severity,
            "code": code,
            "diagnostics": diagnostics,
        }]
    })
}

/// Minimal FHIR R4 `CapabilityStatement` describing what this server does:
/// read / search-type / create / update on each supported resource type.
pub fn capability_statement() -> Value {
    let resources: Vec<Value> = SUPPORTED_TYPES
        .iter()
        .map(|t| {
            json!({
                "type": t,
                "interaction": [
                    {"code": "read"},
                    {"code": "search-type"},
                    {"code": "create"},
                    {"code": "update"},
                ]
            })
        })
        .collect();

    json!({
        "resourceType": "CapabilityStatement",
        "status": "active",
        "date": now_iso8601(),
        "kind": "instance",
        "software": {"name": "ChartCraft", "version": env!("CARGO_PKG_VERSION")},
        "fhirVersion": "4.0.1",
        "format": ["json"],
        "rest": [{
            "mode": "server",
            "resource": resources,
        }]
    })
}

/// Current instant as a FHIR-flavored ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// ponytail: hand-rolled civil-from-days instead of pulling in `chrono`/`time`,
/// to keep the dependency list to the five the task allows. `SystemTime::now()`
/// is good enough for M1; deterministic time can be injected later if a test
/// ever needs it.
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    unix_secs_to_iso8601(secs)
}

/// Convert a Unix timestamp (seconds since 1970-01-01T00:00:00Z) to an
/// ISO-8601 UTC string. Howard Hinnant's civil-from-days algorithm.
fn unix_secs_to_iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 -> civil (year, month, day)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hour, min, sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats_correctly() {
        assert_eq!(unix_secs_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_known_instant_formats_correctly() {
        // 2021-01-01T00:00:00Z == 1609459200
        assert_eq!(unix_secs_to_iso8601(1_609_459_200), "2021-01-01T00:00:00Z");
        // 2026-11-19T12:34:56Z == 1795091696
        assert_eq!(unix_secs_to_iso8601(1_795_091_696), "2026-11-19T12:34:56Z");
    }
}
