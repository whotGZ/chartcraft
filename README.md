# ChartCraft

**An open-source electronic medical record, rebuilt in Rust, designed by a doctor who actually uses one.**

Status: pre-alpha. A working FHIR core, a clinician UI, and an append-only, hash-chained (tamper-evident) audit log already exist (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)). The remaining HIPAA safeguards — **authentication** and **encryption at rest** — are the *next* milestone (M4) and are **not built yet**. **Do not put real patient data in it today.** Use synthetic or de-identified data only until M4 lands. Contributors welcome from line one.

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
4. **AI-native, clinician-in-the-loop.** The design intent: ambient scribe, structured extraction, order drafting, chart summarization — drafted by agents, *signed by a human*, with every AI action recorded as attributable, reversible `Provenance`. The AI surfaces and real human signing arrive with auth (M4); today a `Provenance` is written on every change but the signer is a placeholder.
5. **Fast.** Rust, because a note should open in the time it takes to look up from the patient, not the time it takes to get coffee.
6. **Auditable and private.** An append-only, hash-chained audit log already exists — altered or removed entries are detectable (`verify_audit_chain`), and every write commits its resource, `Provenance`, and `AuditEvent` atomically. The remaining safeguards, authentication and encryption at rest, are the current build focus (M4). No telemetry home (verified: loopback-only bind, same-origin UI).

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

What it is *designed to be*: software a direct-pay physician can legally run as their own medical record. There is no federal law requiring an EMR to be *certified* for a clinician to document care in it; what applies is HIPAA and state record law. That legal path is open — but *legally permitted* is not the same as *technically ready*. The tamper-evident audit spine exists, but the remaining HIPAA technical safeguards (authentication, encryption at rest) are M4 and unbuilt, so ChartCraft is **not ready for real patient charts yet**. When those land, the first real user can be a physician signing their own charts.

What it isn't: ONC-certified. That certification is **voluntary** and gates CMS/MIPS participation and hospital procurement, not patient care itself. It is a months-long public process we climb in the open. See [`docs/REGULATORY.md`](docs/REGULATORY.md) for the two tiers.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). You do not need to be a doctor to contribute code, and you do not need to be an engineer to contribute clinical reality. We need both, and the second is rarer.

## License

[Apache-2.0](LICENSE). Patent grant included on purpose — this is healthcare; be explicit.
