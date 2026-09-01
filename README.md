# KSA ECC-Map

**Which of my detections give me audit evidence for which NCA ECC control?**

An open, bilingual (Arabic/English) crosswalk mapping the deployable detection
content of the [MENA Detection Library](https://github.com/DashTX707/mena-detection-library)
(44 threat-actor packs of Sigma + hunts, ATT&CK-mapped) to the control clauses
of **NCA ECC-1:2018** — Saudi Arabia's Essential Cybersecurity Controls.

Western threat-informed-defense crosswalks stop at NIST 800-53 / CIS. A Gulf GRC
team's actual question is *"my SIEM detects T1059 — which ECC control does that
evidence at a National Cybersecurity Authority assessment?"* This project answers
it, in the region's own framework and language.

> **Scope:** covers **NCA ECC-1:2018** and **CSCC-1:2019** (Critical Systems).
> OTCC-1:2022 and the SAMA CSF are later phases.
>
> **Before you use it, read [docs/USING.md](docs/USING.md)** — how to (and how NOT to)
> use this at an assessment. Coverage is not compliance.

## What's here
```
catalog/<fw>.json         canonical control lists (ecc, cscc) — source of truth, bilingual
mappings/<fw>/*.json      ATT&CK technique -> control evidence links (+ rule-file drill-down)
corroboration/            MITRE CTID ATT&CK->NIST 800-53 corroboration data
vendor/                   pinned deps so the gate is self-contained (attack_dump, library_manifest)
scripts/
  audit_eccmap.py         deterministic, fail-closed audit gate (run before every merge)
  build_site_data.py      regenerate docs/_data.js
  build_library_manifest.py  refresh vendor/library_manifest.json when the library changes
docs/DATA-MODEL.md        schema, honesty invariants, methodology limits
docs/USING.md             how to / how NOT to use it
docs/ASSESSMENT.md        independent assessment + remediation log
docs/{AUDIT,CSCC-AUDIT}-REPORT.md   per-framework governance sign-offs
```

## How it's produced & audited
Mappings run a disciplined pipeline, per framework:
**GRC extraction → classification (evidences-control vs nominal) → cross-check
against MITRE CTID ATT&CK→NIST 800-53 → adversarial refutation → governance audit →
human-approved merge.**

Every change must pass `python scripts/audit_eccmap.py` with **0 ERR**. The gate is
**self-contained and fail-closed** — its dependencies are vendored into `vendor/`, so
it runs identically on any checkout/CI, and a *missing* dependency is a hard ERR (never a
silent skip). It enforces:
- every control ID exists in that framework's catalog (no fabricated control numbers);
- every ATT&CK technique ID is valid against the vendored ATT&CK dataset;
- every `library_rule_refs` entry resolves to a real Detection-Library file **that actually
  tags/cites the technique** (the last-mile evidence link, not just a pack name);
- every mapping carries rationale, confidence, a **risk-reduction flag**, and a source;
- a `high`-confidence mapping flagged as *nominal* is surfaced (**compliant ≠ secure**).

## Sourcing & licensing
Control IDs are referenced and each control's intent is **paraphrased** (≤40 words)
with a link to the official NCA document. This repo does **not** redistribute the
NCA text verbatim.

## Not an attestation
Community guidance only. Mapping a detection to a control is **not** an
NCA-endorsed compliance attestation, and evidence of a control is not proof of
risk reduction. Read the per-row `risk_reduction_flag`.

## License
See [LICENSE](LICENSE) and [NOTICE](NOTICE). In short: original mapping data & docs
under CC BY 4.0, scripts under MIT. NCA control text/IDs remain the property of the NCA
(referenced, not relicensed); the MITRE CTID corroboration data is Apache-2.0.
