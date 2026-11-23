# ChartCraft

**An open-source electronic medical record, rebuilt in Rust, designed by a doctor who actually uses one.**

Status: pre-alpha. A working FHIR core, a clinician UI, an append-only hash-chained (tamper-evident) audit log, and **authentication — password login with enforced TOTP two-factor (M4)** — all exist (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)). The one remaining HIPAA technical safeguard is **encryption at rest**. **Until that lands, do not put real patient data in it** — use synthetic or de-identified data. Contributors welcome from line one.

---

## Quick start (Docker)

```sh
docker compose up
```

Then open **http://localhost:8080** and sign in with:

- **Username:** `demo`
- **Password:** `demodemo1234`

You land on a populated sample chart (Eleanor M Whitfield — hypertension, type 2 diabetes, hyperlipidemia, meds, a penicillin allergy, vitals, and a progress note). First boot takes a minute or two to compile; after that it is seconds.

> **Demo mode is for trying it out, not for care.** `docker compose up` runs with `CHARTCRAFT_DEMO=1`, which **seeds fake data** and **relaxes authentication** (the demo user reaches the chart without enrolling an authenticator app). The banner in the logs says so. **Never point demo mode at real patients or run it in production.**

### Running for real

Turn the demo off and let the real auth flow take over:

- Set `CHARTCRAFT_DEMO=0` in `docker-compose.yml` (or unset it). With demo off, the first account you register must **enroll TOTP two-factor** before it can read any PHI — the enforced-MFA flow.
- Serve it behind **TLS** and set `CHARTCRAFT_SECURE_COOKIES=1` so the session cookie is only sent over HTTPS.
- Remember the standing caveat above: **encryption at rest is not implemented yet**, so even with real auth, keep real patient data out until it lands.

(No Docker? `cargo run` builds and runs the bare binary on `127.0.0.1:8080` with demo off — register the first user and enroll TOTP.)

---

## Why

Every working physician has the same complaint: the EMR is the worst software they touch, and they touch it all day. It is slow. It buries the one number you need under forty you don't. It was built as a billing engine wearing a clinical mask, so it optimizes for the biller and punishes the clinician. And it costs a hospital tens of millions of dollars and a startup its entire runway, so there is almost no competition.

That economics just changed. [ArtCraft](https://github.com/echelon) started as one person's project and became something ~4,000 developers around the world build together, with AI coding agents collapsing the cost of software that used to take a funded company years. If that can happen to the creative suite, "an EMR is too hard to build" is no longer true. An EMR is not technically harder than a non-linear video editor. It is *regulatorily* harder, and it needs someone in the room who knows what a chart is for. ChartCraft means to start the healthcare one in that same spirit: one clinician who builds, opened up for everyone to make real.

ChartCraft is clinician-first, local-first, FHIR-native, and free.

**Who's building it:** a practicing ICU physician who also ships software — including a native macOS dictation app written in Rust. Clinical authority and the ability to write the code, in one person. See [`docs/`](docs/).

## Principles

1. **Clinician-first, not biller-first.** The chart is for taking care of a patient. Billing is a *view* on the chart, generated from it, never the thing that shapes it.
2. **FHIR-native from the first commit.** Not a proprietary schema with a FHIR export bolted on later. The data model *is* [FHIR R4](https://hl7.org/fhir/) + USCDI. Interop is the product, not a feature.
3. **Local-first and self-hostable.** A solo physician runs it on one box. A clinic runs it on a server they own. Your patients' data is not rent you pay forever. Single Rust binary + Postgres (or SQLite for solo).
4. **AI-native, clinician-in-the-loop.** The design intent: ambient scribe, structured extraction, order drafting, chart summarization — drafted by agents, *signed by a human*, with every AI action recorded as attributable, reversible `Provenance`. Human signing is now real: the authenticated (password + TOTP) user is recorded as the signer on every change. The AI-drafting surfaces are still ahead.
5. **Fast.** Rust, because a note should open in the time it takes to look up from the patient, not the time it takes to get coffee.
6. **Auditable and private.** An append-only, hash-chained audit log already exists — altered or removed entries are detectable (`verify_audit_chain`), and every write commits its resource, `Provenance`, and `AuditEvent` atomically. Authentication (password + enforced TOTP MFA) now gates every PHI endpoint, and the signer is the real logged-in user. The one remaining safeguard is encryption at rest. No telemetry home (verified: loopback-only bind, same-origin UI).

## The shape of the MVP

The smallest thing that is honestly an EMR — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md):

- Patient + encounter
- Problem list, medication list, allergy list, results
- Note authoring (structured where it helps, prose where it doesn't)
- Orders (CPOE) and results review
- A one-line coded-charge / superbill export (the chart already derives the codes)
- Everything persisted as FHIR resources, exposed over a FHIR REST API

The wedge is the **note**. The thing a clinician actually fights the EMR over is writing a good, billable note, and what a good note contains differs sharply across an ICU, a clinic, and a skilled-nursing facility. Nail the multi-setting note engine first; grow the chart around it. If ChartCraft can carry one physician through one clinic day without making them angry, it has already cleared the bar the incumbents miss.

## What this is — and isn't — yet

What it is *designed to be*: software a direct-pay physician can legally run as their own medical record. There is no federal law requiring an EMR to be *certified* for a clinician to document care in it; what applies is HIPAA and state record law. That legal path is open — but *legally permitted* is not the same as *technically ready*. The tamper-evident audit spine and authentication (password + enforced TOTP MFA) now exist; the one remaining HIPAA technical safeguard is encryption at rest. Until that lands, ChartCraft is **not ready for real patient charts**. When it does, the first real user can be a physician signing their own charts on localhost.

What it isn't: ONC-certified. That certification is **voluntary** and gates CMS/MIPS participation and hospital procurement, not patient care itself. It is a months-long public process we climb in the open. See [`docs/REGULATORY.md`](docs/REGULATORY.md) for the two tiers.

## Recovering a lost authenticator

TOTP multi-factor is enforced: once enrolled, a user needs their authenticator app to log in. If that device is lost, an operator with filesystem access to the server can break-glass reset that user's MFA so they re-enroll on next login:

```
chartcraft --reset-mfa <username>
```

This clears the user's TOTP secret and enrollment state, prints a confirmation, and exits without starting the server. The user logs in with their password alone (landing a pending-MFA session) and is walked through enrollment again.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). You do not need to be a doctor to contribute code, and you do not need to be an engineer to contribute clinical reality. We need both, and the second is rarer.

## License

[Apache-2.0](LICENSE). Patent grant included on purpose — this is healthcare; be explicit.
