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

> **Scope:** Phase 1 covers **NCA ECC-1:2018 only.** CSCC-1:2019, OTCC-1:2022 and
> the SAMA CSF are later phases.

## What's here
```
catalog/ecc.json     canonical ECC-1:2018 control list (source of truth; bilingual)
mappings/*.json      ATT&CK technique -> ECC control evidence links
scripts/
  audit_eccmap.py    deterministic audit gate (run before every merge)
docs/DATA-MODEL.md   the schema + honesty invariants
```

## How it's produced & audited
Mappings run the same disciplined pipeline as the Detection Library:
**GRC extraction → classification (evidences-control vs nominal) → cross-check
against MITRE CTID ATT&CK→NIST 800-53 → adversarial refutation → audit gate →
human-approved merge.**

Every change must pass `python scripts/audit_eccmap.py` with **0 ERR**:
- every ECC control ID exists in the catalog (no fabricated control numbers);
- every ATT&CK technique ID is valid in the bundled ATT&CK dataset;
- every referenced Detection-Library pack exists on disk;
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
Mapping data & docs: CC BY 4.0. ECC control text/IDs are the property of the NCA
(referenced, not relicensed).
