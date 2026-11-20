# Contributing to ChartCraft

Two kinds of people build a good EMR, and most projects only have one of them.

## Getting started (Milestone 0)
The skeleton is in: `cargo run` starts an `axum` server exposing a FHIR `Patient` over a `ChartStore` trait, with a passing roundtrip test (`cargo test`). It's deliberately tiny. The first real issues, each a clean first commit:
1. **A SQLite `ChartStore` impl** (today's store is in-memory — this is issue #1). JSONB-style payload + promoted `id` column.
2. A `DocumentReference` (a clinical note) with a `Provenance` record on write.
3. An `AuditEvent` on read.
4. A `/metadata` FHIR CapabilityStatement.

Pick one, open an issue claiming it before you start so two people don't build it twice, and you've moved the project from manifesto to software.

## If you write code
- Rust, FHIR, web front end, DevOps, security — all welcome.
- Once Milestone 0 lands, pick up an issue tagged `good-first-issue`, or open one describing what you want to build.
- The data model is FHIR R4 / US Core. If a change doesn't map to a FHIR resource, say why in the PR.
- Every feature touching PHI writes to the audit log. No exceptions.
- AI-assisted code is fine (it's how this whole project exists) — but you own and understand what you submit.

## If you practice medicine
You are the rarer and more valuable contributor, and you do **not** need to code.
- Tell us where real EMRs waste your time. Specifics beat theory.
- Review the note templates, problem-list behavior, order flows — would this survive your actual clinic/ICU/SNF day?
- Help define the smallest *good* note for your specialty.
- Open an issue tagged `clinical`. A screenshot and a sentence of "this is wrong because" is a gift.

## Governance (early and simple)
- Decisions happen in issues and PRs, in public.
- Clinical-safety objections get veto weight over convenience. If a clinician says "this will hurt someone," that blocks until resolved.
- Be kind. Everyone here is trying to fix the worst software in medicine.

## Code of conduct
We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/), with one addition: patient safety comes before everything, including politeness about a bad idea. Report conduct issues to the maintainer listed in the repo. The spirit is binding now; the `CODE_OF_CONDUCT.md` file lands with Milestone 0.
