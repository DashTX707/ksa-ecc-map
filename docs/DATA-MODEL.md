# KSA ECC-Map — Data Model

Multi-framework. Two machine-readable layers, both gated by `scripts/audit_eccmap.py`.
Each framework has one catalog in `catalog/` and its mappings under
`mappings/<framework>/`. Today: **NCA ECC-1:2018** (`catalog/ecc.json`, `mappings/ecc/`)
and **NCA CSCC-1:2019** (`catalog/cscc.json`, `mappings/cscc/`). OTCC/SAMA later.

## 1. `catalog/*.json` — the source of truth (one per framework)
The canonical NCA control list for a framework. Every mapping validates its
`control_id` against the catalog whose `framework` it names; a control ID not in
that framework's catalog is a hard ERR.

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

## 2. `mappings/<framework>/*.json` — technique → control links
One row per link between an ATT&CK technique the Detection Library covers and a
control (of the named framework) that technique's detection/hunt gives **evidence** for.

```jsonc
[
  {
    "attack_technique_id": "T1059.001",   // must exist in the bundled ATT&CK dataset
    "framework": "NCA ECC-1:2018",        // must match a catalog's "framework"
    "control_id": "2-3-1",                // must exist in that framework's catalog
    "evidence_type": "detect",            // detect | hunt
    "library_pack_refs": ["muddywater", "oilrig/detections/T1059.001_….yml"],
    "rationale": "why this detection evidences this control's intent",
    "mapping_confidence": "high",         // high | medium | low
    "risk_reduction_flag": true,          // does it genuinely reduce risk, or nominal/checkbox?
    "source_refs": ["MITRE CTID ATT&CK→NIST 800-53", "…"]
  }
]
```
Uniqueness is per `(framework, technique, control)`. Control IDs may be any
depth (`2-3`, `2-3-1`, `2-3-1-1`).

## Honesty invariants (enforced/flagged by the audit)
- **No fabricated control IDs** — every `control_id` ∈ its framework's catalog.
- **No unknown frameworks** — every row's `framework` matches a catalog.
- **No invalid techniques** — every `attack_technique_id` ∈ bundled ATT&CK dataset.
- **No dangling library refs** — every `library_pack_ref` exists on disk.
- **No blank claims** — rationale, confidence, `risk_reduction_flag`, source all required.
- **Compliant ≠ secure** — a `high`-confidence mapping flagged nominal/no-risk-reduction is surfaced for reconciliation.
- **Bilingual** — AR + EN titles expected; gaps flagged.

## ATT&CK dataset caveat (ID numbering)
Technique IDs are validated against the **bundled pySigma ATT&CK dataset** used by
the MENA Detection Library's CI — a reorganized build that renumbers part of the
Impair-Defenses family (e.g. this dataset's **T1685** ≈ public ATT&CK **T1562**,
**T1685.005** ≈ **T1070.001**) and renames the defense-evasion tactic to `stealth`.
Consequently a few technique IDs here **will not have a CTID ATT&CK→NIST anchor**
(the CTID data uses public ATT&CK numbering), and that absence is expected — not a
gap in corroboration. Downstream consumers on public ATT&CK should translate these
IDs. `scripts/audit_eccmap.py` uses the bundled dataset as its source of truth.

## Methodology limits (disclosed, from the independent assessment)
- **The CTID corroboration axis is a permissive sanity-check, not strong triangulation.** CTID maps each technique to a *broad* set of NIST 800-53 controls (often 15-25, spanning many families). With that breadth it rarely *fails* to find an overlapping family, so it cannot by itself distinguish a strong mapping from a weak one. **Rule:** a `high` confidence requires BOTH the control's core NIST family present in the technique's CTID set AND a named control-intent element the detection hits; corroboration presence alone can never lift a row above `medium`.
- **The monitoring subdomain (ECC 2-12) is a legitimate secondary home for almost any detection.** Many network/endpoint detections are booked to both their technical-home control and 2-12. Each row is defensible, but do **not** count one Sigma rule as N controls' worth of independent evidence — a 2-12 row is the *same physical detection* as its technical-home row, credited for its monitoring value.
- **CSCC is enhanced-vs-base.** A detection firing on a critical system trivially evidences the *base ECC* capability; to earn a CSCC row it must evidence the *named enhancement* (e.g. geo-blocked remote access, application whitelisting). Rows that only credit the ECC baseline are downgraded/dropped.

## ATT&CK ID translation (bundled vs canonical)
The bundled dataset renumbers part of the Impair-Defenses family and renames the
defense-evasion tactic to `stealth`. Known translations to canonical public ATT&CK:
`T1685`≈`T1562` (Impair Defenses), `T1685.005`≈`T1070.001` (Clear Windows Event Logs).
These IDs have no CTID/NIST anchor by construction. IDs *absent* from the CTID subset
for unrelated reasons (e.g. `T1074`, `T1113`) are a coverage gap in that dataset, NOT
this renumbering — do not conflate the two.

## Not an attestation
This is community guidance mapping public detection content to ECC control
*intent*. It is **not** an NCA-endorsed compliance attestation, and evidence of
a control is not proof of risk reduction. Read `risk_reduction_flag` per row.
