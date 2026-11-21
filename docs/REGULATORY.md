# ChartCraft — The regulatory picture, named honestly

An EMR is not hard to *write*. The hard part is knowing exactly which rules apply to which use. Most people assume you need federal certification to touch a patient at all. You don't. Getting this right is what separates a serious project from a toy, so here is the map, in two tiers.

This is a clinician's starting map, not legal advice. Correct it, deepen it, PR it.

## Tier 1 — Legal to use as your own chart today

A physician in a direct-pay / cash practice can keep their medical records in software they chose, including software they wrote. There is no federal law requiring an EMR to be *certified* for a clinician to document care in it. What governs Tier 1 is:

- **HIPAA Security & Privacy Rules**, if you transmit claims electronically or otherwise become a covered entity. Technical safeguards: access control, audit controls, integrity, authentication, and encryption of PHI in transit and at rest. ChartCraft is built *toward* these — a `Provenance`/`AuditEvent` spine exists today, but authentication, encryption at rest, and tamper-evident (hash-chained) audit are the M4 milestone and are **not yet implemented**. Until they are, this is not a HIPAA-ready system.
- **State medical-record law**: retention periods, amendment rights, consent, data residency. Varies by state.

So Tier 1 is *reachable* — it is the goal, not the current state. The wedge that follows: once the Tier-1 safeguards are built (M4), **the author can be ChartCraft's own first production user**, signing real charts in his own practice. That dogfooding is the one asset no engineering team can buy, and it is what makes this project credible rather than theoretical. Until M4 lands, ChartCraft runs on synthetic or de-identified data only.

Tier 1 raises the bar on us: real-chart use demands real HIPAA rigor, so real-chart use *waits* for that rigor (M4) rather than preceding it. We would rather be late to the first real patient than lie about being ready for one.

## Tier 2 — ONC certification, for CMS programs and the wider ecosystem

ONC Health IT Certification (now under ASTP/ONC; tested by an ONC-ATL, certified by an ONC-ACB) is **voluntary**. It is the gate for *specific* things, not for care itself:

- Participating in CMS incentive/quality programs (MIPS, Promoting Interoperability) that pay or penalize based on using *certified* EHR technology.
- Being procured by hospitals and groups that require certification contractually.

Certification to the 21st Century Cures Act criteria means: the USCDI data set, FHIR / US Core APIs, compliance with the information-blocking rules, safety-enhanced-design (usability) testing, and more. It is a structured, expensive, months-long process — but the criteria are **public**.

## Where FDA enters

A general-purpose EMR is largely outside device regulation. The line is clinical decision support: under the 21st Century Cures Act (§3060) CDS stays non-device only if it displays the basis for its recommendation so the clinician can **independently review** it rather than rely on the software. Cross that line and you may have a regulated device (the US statutory hook is "device"; "SaMD" is the international IMDRF term). We keep that line bright and documented.

## Why open source is the right vehicle for Tier 2

Certification has historically been a moat: only a well-funded vendor could afford it, so only vendors existed. But the *criteria* are public. A community that builds USCDI / US-Core-conformant software in the open, and shares the certification artifacts, turns the moat into a shared road. That openness applied to the regulated layer — not the Rust, not the AI — is the genuinely new thing here.
