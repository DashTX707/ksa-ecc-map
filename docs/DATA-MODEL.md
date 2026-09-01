# KSA ECC-Map — Data Model

Two machine-readable layers, both gated by `scripts/audit_eccmap.py`.

## 1. `catalog/ecc.json` — the source of truth
The canonical **NCA ECC-1:2018** control list. Every mapping validates its
`ecc_control_id` against this file; a control ID that isn't here is a hard ERR.

```jsonc
{
  "framework": "NCA ECC-1:2018",
  "publisher": "National Cybersecurity Authority (NCA), Kingdom of Saudi Arabia",
  "official_source": "<official NCA URL>",
  "sourced_on": "YYYY-MM-DD",
  "structure_note": "N domains, M subdomains, K controls (as verified)",
  "domains": [ { "domain_id": "2", "title_en": "Cybersecurity Defense", "title_ar": "…" } ],
  "controls": [
    {
      "control_id": "2-3-1",              // domain-subdomain-control; regex ^\d+-\d+-\d+$
      "domain_id": "2",
      "subdomain_id": "2-3",
      "subdomain_en": "Event Logs and Monitoring Management",
      "subdomain_ar": "…",
      "title_en": "…short paraphrased title…",
      "title_ar": "…",
      "intent": "…our 1–2 sentence paraphrase (≤40 words), NOT verbatim NCA text…",
      "source_ref": "NCA ECC-1:2018 §2-3-1 / <url>",
      "verified": true                    // false + "note" if any part is unconfirmed
    }
  ]
}
```

**Licensing rule:** we reference control IDs and *paraphrase* intent, linking to
the official NCA document. We do **not** redistribute the NCA text verbatim. The
audit flags any `intent` over 40 words for a verbatim-copy check.

## 2. `mappings/*.json` — technique → control links
One row per link between an ATT&CK technique the Detection Library covers and an
ECC control that technique's detection/hunt provides **evidence** for.

```jsonc
[
  {
    "attack_technique_id": "T1059.001",   // must exist in the bundled ATT&CK dataset
    "ecc_control_id": "2-3-1",            // must exist in catalog/ecc.json
    "evidence_type": "detect",            // detect | hunt
    "library_pack_refs": ["muddywater", "oilrig/detections/T1059.001_….yml"],
    "rationale": "why this detection evidences this control's monitoring intent",
    "mapping_confidence": "high",         // high | medium | low
    "risk_reduction_flag": true,          // does it genuinely reduce risk, or nominal/checkbox?
    "source_refs": ["MITRE CTID ATT&CK→NIST 800-53", "…"]
  }
]
```

## Honesty invariants (enforced/flagged by the audit)
- **No fabricated control IDs** — every `ecc_control_id` ∈ catalog.
- **No invalid techniques** — every `attack_technique_id` ∈ bundled ATT&CK dataset.
- **No dangling library refs** — every `library_pack_ref` exists on disk.
- **No blank claims** — rationale, confidence, `risk_reduction_flag`, source all required.
- **Compliant ≠ secure** — a `high`-confidence mapping flagged nominal/no-risk-reduction is surfaced for reconciliation.
- **Bilingual** — AR + EN titles expected; gaps flagged.

## Not an attestation
This is community guidance mapping public detection content to ECC control
*intent*. It is **not** an NCA-endorsed compliance attestation, and evidence of
a control is not proof of risk reduction. Read `risk_reduction_flag` per row.
