# ChartCraft — Architecture concept

This is a concept, written to be argued with. Most of it is not built yet.

## Milestone 1 (done)

The storage seam and governance spine from this document now exist in code:

- **SQLite `ChartStore`** (bundled `rusqlite`, so no system SQLite needed) alongside the in-memory one — the two honest backends described under *Stack*. A single `resources(resource_type, id, version, payload)` table; a `Mutex<Connection>` guards writes (a global lock for now, to be replaced by a pool).
- **Generic FHIR CRUD** over the US Core types in the MVP table below: `POST /:type` (server-assigned uuid), `GET`/`PUT /:type/:id`, with light validation (body `resourceType` must match the path; unknown types are rejected `400` with an `OperationOutcome`).
- **Governance spine:** a `Provenance` written on every create/update and an append-only `AuditEvent` on every read, both persisted through the same store. Signing is a fixed demo label until auth lands; the hash-chained tamper-evidence described below is not built yet.
- **`GET /metadata`** returns a minimal FHIR R4 `CapabilityStatement`.

Not yet built: promoted columns/indexes, the Postgres backend, auth, real signing, and everything under *AI, done responsibly*.

## The one idea

**The data model is FHIR. Everything else is a view on it.**

Most EMRs store data in a proprietary relational schema shaped by their billing module, then generate a FHIR façade on request, badly. We invert that. FHIR R4 resources (constrained to US Core / USCDI) are the source of truth. The UI, the billing export, the quality measures, and the AI tools all read and write the same resources. Interop stops being an integration project and becomes the default.

Pragmatically: we don't store raw JSON blobs and call it a day. We store FHIR resources in Postgres with the clinically-queried fields promoted to real columns/indexes (patient, encounter, code, date, status), JSONB for the rest. One mapping layer, enforced once.

## MVP scope (the smallest honest EMR)

| Capability | FHIR resources |
|---|---|
| Patient registration | `Patient` |
| Visits | `Encounter` |
| Problem list | `Condition` |
| Medications | `MedicationRequest` |
| Allergies | `AllergyIntolerance` |
| Results | `Observation`, `DiagnosticReport` |
| Notes | `DocumentReference` (US Core); `Composition` optional, internal |
| Orders (CPOE) | `ServiceRequest`, `MedicationRequest` |
| Vitals | `Observation` |

If it carries one clinician through one clinic day, it's real.

## Stack (proposed, lazy on purpose)

- **Language:** Rust. One statically-linked binary. `axum` for HTTP.
- **Storage:** a `ChartStore` trait with two backends — Postgres for clinics (JSONB + GIN on the FHIR payload, real columns on promoted fields), SQLite for the solo-physician single-box deploy. One trait, two honest implementations; they diverge exactly where Postgres and SQLite diverge (indexing, concurrency), so don't pretend a single `sqlx` path hides that.
- **API:** FHIR R4 REST. The API is the product; the UI is just its first client.
- **UI:** web front end (the clinician's browser is the thin client). Boring and fast.
- **Auth:** MVP ships minimal local auth with a seam for an external IdP. **SMART on FHIR / OAuth2 is a conformance target**, added when third-party apps need it — not a day-one dependency.
- **Audit & provenance:** an append-only `AuditEvent` log (PHI access, backed by a hash chain so tampering is detectable) plus `Provenance` on every clinical resource (who authored it, which agent drafted it, which human signed it). `Provenance` is what makes "agents draft, humans sign" enforceable, not just a slogan.
- **Deploy:** `docker compose up`, or a single binary + a database. No Kubernetes to see a patient.
- **Latency:** the speed win is local-first and few tiers (no round-trip to a vendor cloud) plus indexed promoted columns, not Rust alone. Budget: note opens in under 100ms p95.

Nothing above is chosen for cleverness. It's the shortest path to a thing a doctor can run.

## AI, done responsibly

The interesting part, and the part that has to be gotten right or it kills someone.

- Agents **draft**, humans **sign**. No AI-authored content enters the legal record unsigned.
- Every AI contribution is recorded as `Provenance` on the resource it touched: which model, which prompt, which human signed it, always answerable and reversible.
- Surfaces built *for* agents: structured write endpoints, an ambient-scribe intake that produces a draft note a clinician edits, result-summarization that links every claim back to the source `Observation`.
- No patient data leaves the deployment without an explicit, logged, consented action. Self-hosted model endpoints are a first-class config.

## What we are deliberately NOT building early

- A billing/RCM engine. But the MVP *does* ship a one-line coded-charge / superbill export — the chart already derives the codes, and a solo doctor's day ends in a claim, so an EMR they can't bill from has no adoption path. Full clearinghouse/EDI integration is a later module, not the foundation. This inversion (billing is a view, not the skeleton) is what makes ChartCraft not-hated.
- Scheduling, inventory, HR, the ERP sprawl every incumbent bolted on. Out of scope. Integrate, don't absorb.
- Our own auth/identity empire. Stand on OAuth2/OIDC when the time comes.

## Open questions for contributors (especially clinical ones)

1. Where does structured data genuinely help care, and where is it just data entry that burns the physician out? (The core UX fight.)
2. Minimum terminology set to be useful: SNOMED CT, LOINC, RxNorm, ICD-10 — how much, how early?
3. What is the smallest note that is still a *good* note across IM, critical care, and a SNF progress note?
4. How do we make the ONC certification path a community effort instead of a corporate moat?
