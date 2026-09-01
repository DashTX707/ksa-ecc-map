# KSA ECC-Map — Independent Audit & Sign-Off

> **Post-assessment note (2026-09-01):** after this sign-off, an independent full assessment prompted further changes (confidence downgrades, dropped review-control rows, rule-file drill-down, a fail-closed gate). Current totals and the full remediation log are in [ASSESSMENT.md](ASSESSMENT.md); this report reflects the state at audit time.


**Framework audited against:** NCA ECC-1:2018 (5 domains, 29 subdomains, 114 main controls)
**Artifact audited:** 85 vetted technique→control mappings (post deterministic gate + adversarial pass: 10 rejected, 19 downgraded)
**Auditor role:** Independent final auditor, harnessed with the full ECC-1:2018 catalog as ground truth
**Audit date:** 2026-09-01
**Verdict:** **PASS** — the 3 conditions below were resolved on 2026-09-01 (see §Condition Resolution). Original verdict: CONDITIONAL PASS.

---

## 1. Scope

This audit is the final stage of the KSA ECC-Map pipeline. It covers:

- **85 surviving mapping rows** across four files: `2-12_2-13_monitoring-response.json` (32), `access-endpoint.json` (28), `data-asset-mobile-backup.json` (11), `perimeter-delivery.json` (14).
- **Ground truth:** `catalog/ecc.json` (114 ECC-1:2018 controls, paraphrased intent).
- **Corroboration:** MITRE CTID ATT&CK→NIST 800-53 (`technique_to_nist80053.json`) and the Detection Library technique index (`library_technique_index.json`).
- **Context:** the prior adversarial verdicts (`validation/verdicts.json`) and the data model / honesty invariants (`docs/DATA-MODEL.md`).

Out of scope: the correctness of the underlying Sigma/hunt content inside each library pack (assumed valid), and NCA endorsement (this artifact is explicitly **not an attestation**).

## 2. Methodology & Limits

**The approach:** each row asserts that a detection or hunt the Detection Library ships for an ATT&CK technique produces operational **evidence** for the *intent* of an ECC control. CTID's ATT&CK→NIST 800-53 mapping is used as an independent corroboration axis — if the technique's NIST anchors fall in the control families that embody the ECC control's intent (e.g. SI-4/CA-7 for monitoring, AC/IA for access, SI-3 for anti-malware, CP-9/10 for backup), the mapping is corroborated; where CTID is silent, the row must say so and drop to `medium`/`low`.

**This is defensible** because it is evidence-based (a firing detection *requires* the underlying telemetry/control to exist and operate), it is triangulated (technique intent + control intent + independent NIST crosswalk), and it is disciplined about confidence and risk-reduction honesty.

**Stated limits — plainly:**

- **Detection evidences operation, not process.** A detection can show a monitoring/anti-malware/logging capability is *operating*; it can never evidence a documentation, governance, or periodic-review control. Correctly, **no row maps to any `x-y-1` (define) or `x-y-4` (review) control** — confirmed by scan.
- **CTID carries no IR-family control.** The Incident & Threat Management subdomain (2-13) therefore cannot be corroborated by an IR-* anchor. The map corroborates 2-13 rows via SI-4 (monitoring) and CP-* (contingency) instead, and every 2-13 row discloses "no IR-* in CTID set." This is honest but means 2-13 evidence is inherently *adjacent* (detection triggers response) rather than *direct* (evidence that IR plans/classification/NCA-reporting exist).
- **Corroboration ≠ control existence.** The map evidences that a technique *would be caught*; it does not prove the organisation has implemented the full control. It is guidance for assembling an evidence package, not the evidence itself.
- **Bundled-dataset numbering diverges from canonical ATT&CK.** The bundled dataset numbers the event-log-evasion cluster as `T1685` / `T1685.001` / `T1685.005` ("Disable or Modify Tools / Windows Event Log / Clear Windows Event Logs"), which in canonical MITRE ATT&CK is the `T1562` cluster. These IDs are valid *within the bundled dataset* (satisfying the honesty invariant) but have **no CTID→NIST anchor by construction**, which is exactly why those rows sit at `medium` with an explicit "no anchor" note. Anyone cross-referencing canonical ATT&CK/CTID must translate the ID.

## 3. Findings by Dimension

### 3.1 Methodology soundness — PASS
The technique→control→CTID-corroboration method is sound and appropriately bounded. The pipeline's discipline (deterministic gate → adversarial pass → this audit) is visible in the artifact: confidence tiers track anchor strength, and the map refuses to claim process/governance coverage it cannot evidence. The CTID/IR-family limitation is disclosed at every affected row rather than hidden.

### 3.2 Residual evidence-validity — 2 rows still challenged
The adversarial pass was thorough; most surviving rows are honestly graded. Two residual **confidence overclaims** survived:

| Technique → Control | Current | Challenge | Rationale |
|---|---|---|---|
| **T1190 → 2-13-2** | high | recommend **medium** | Parallel-reasoning inconsistency. The pass downgraded `T1190 → 2-10-2` high→medium because "perimeter-exploit detection does not evidence that requirements are *implemented*; it evidences detective monitoring." The identical logic applies to 2-13-2: a detection firing evidences detection capability, not that incident *management* (plans/escalation/workflow) is implemented. The same detection is already booked at `high` to its true technical home (2-15-3), so a second `high` for incident-management double-counts one piece of evidence at full strength. CTID gives no IR-* anchor (self-conceded). |
| **T1505.003 → 2-13-2** | high | recommend **medium** | Same argument. Web-shell detection is `medium` evidence at its own web home (2-15-2, per the pass) yet `high` for incident-management — internally inconsistent. Detection-to-incident is a real but *adjacent* link; `medium` is the honest tier. |

All other surviving rows are within defensible tolerance. Noted-but-not-challenged soft spots (honestly labelled, left as-is):
- **Subdomain 2-7 (data protection)** rests *entirely* on detective-proxy evidence (T1005/T1041/T1048.003/T1567, all `medium`). None evidences the classification/labeling/ownership process that is 2-7's core; each row concedes this. Acceptable at `medium/true` because detecting exfil/collection genuinely reduces loss risk.
- **Subdomain 2-6 (mobile)** rests on actor-attribution (OilAlpha / Domestic Kitten are mobile actors) rather than technique-intrinsic mobile controls; correctly floored at `low` (T1071→2-6-2 `low/false`, T1204.002 & T1125→2-6-3 `low`). These are the thinnest anchors in the set but are labelled as such.

**Data-quality defect (not an evidence challenge):** `T1053.005 → 2-3-3` has stale rationale text ending "…hence medium," while the fields correctly read `low` / `risk_reduction_flag=false` (the pass downgraded it). The prose contradicts the graded fields and must be corrected.

### 3.3 Coverage honesty — PASS (strong)
The map **does not fake universality** and is candid about concentration:

- **20 of 114 ECC controls** carry any detection/hunt evidence (17.5%). **All 20 are in Domain 2 (Cybersecurity Defense)**, and only in its detective/technical subdomains.
- **94 of 114 controls have ZERO detection evidence.** This absence is a legitimate and important finding, not a gap to paper over: detection *cannot* evidence governance, process, or review controls.
- Evidence maps only to `implement` (`x-y-2`) and `core-set` (`x-y-3`) controls — never to `define` (`x-y-1`) or `review` (`x-y-4`). This is precisely the correct behaviour.

### 3.4 Compliant ≠ secure integrity — PASS
The `risk_reduction_flag` discipline is the strongest honesty signal in the artifact:

- **False-flags are correctly identified.** The backup subdomain (2-9-2) is the exemplar: `T1490` (Inhibit System Recovery) is the *one* `true` row — early detection preserves recoverability — while `T1485`/`T1486`/`T1561.001` are all `false` because ransomware/wiper detection does not create or test the backups the control actually requires. Likewise the three 2-13-3 threat-intel hunts (`T1583.001`/`T1588.002`/`T1587.001`) are `false` (possessing IOCs is nominal until operationalised), and `T1021.001 → 2-5-2` (RDP lateral movement) is `false` (detective-only, not the preventive segmentation 2-5 intends).
- **No true-flag found to be dishonest.** The borderline `true` rows (2-7 data detections; 2-6 mobile detections; destructive-technique 2-13-3 detections) each reflect genuine, if partial, risk reduction and are held at `medium`/`low`.

### 3.5 Licensing / no-fabrication — PASS
- **No control IDs outside the catalog.** All 20 referenced `ecc_control_id`s exist in `catalog/ecc.json`.
- **No fabricated techniques.** Every `attack_technique_id` — including the suspicious `T1685.x` — resolves in the bundled ATT&CK dataset (`library_technique_index.json`). `T1685` is a non-canonical *numbering* of the `T1562` event-log-evasion cluster, not an invention; see §2 portability caveat.
- **Intent paraphrased, not verbatim.** Catalog intents read as concise paraphrases (≤40 words) with `source_ref` links to the official NCA document; no verbatim NCA text is redistributed.

## 4. Coverage Summary (by subdomain)

Legend: ● = has detection/hunt evidence · ○ = zero detection evidence · **"detection cannot evidence this"** = governance/process/review control that is out of reach of detective evidence *by nature*.

| Domain / Subdomain | Controls | Evidenced | Note |
|---|---|---|---|
| **D1 Cybersecurity Governance** (1-1 … 1-10) | 36 | ○ 0 | **Detection cannot evidence this** — strategy, policy, risk mgmt, HR, awareness, audit are governance/process. |
| D2-1 Asset Management | 6 | ○ 0 | **Detection cannot evidence this** — inventory/ownership process (adversary-scan detection ≠ inventory upkeep; rejected in adversarial pass). |
| D2-2 Identity & Access Mgmt | 4 | ● 2 (2-2-2, 2-2-3) | Monitoring/access — strong (AC/IA anchors). Define/review absent. |
| D2-3 System/Host Protection | 4 | ● 2 (2-3-2, 2-3-3) | Anti-malware — strong (SI-3 anchors). |
| D2-4 Email Protection | 4 | ● 2 (2-4-2, 2-4-3) | Anti-phishing — strong (SI-8/SC-44). |
| D2-5 Network Security | 4 | ● 2 (2-5-2, 2-5-3) | Boundary/IPS/DNS — strong (SC-7/SC-20-22). |
| D2-6 Mobile Devices | 4 | ● 2 (2-6-2, 2-6-3) | Thin — actor-attribution, floored at `low`. |
| D2-7 Data & Information Protection | 4 | ● 1 (2-7-2) | Detective-proxy only; classification core not evidenced. |
| D2-8 Cryptography | 4 | ○ 0 | **Detection cannot evidence this** — key-mgmt/encryption process. |
| D2-9 Backup & Recovery | 4 | ● 1 (2-9-2) | Only `T1490` reduces risk; rest correctly `false`. |
| D2-10 Vulnerability Mgmt | 4 | ● 2 (2-10-2, 2-10-3) | Reactive detection ≠ scan/patch process; correctly `medium`. |
| D2-11 Penetration Testing | 4 | ○ 0 | **Detection cannot evidence this** — periodic exercise process. |
| D2-12 Event Logs & Monitoring | 4 | ● 2 (2-12-2, 2-12-3) | **Best-anchored** — detection *requires* the logging it evidences. |
| D2-13 Incident & Threat Mgmt | 4 | ● 2 (2-13-2, 2-13-3) | Adjacent evidence only (no IR-* in CTID); 2 rows over-graded (§3.2). |
| D2-14 Physical Security | 4 | ○ 0 | **Detection cannot evidence this** — physical access/CCTV/destruction. |
| D2-15 Web Application Security | 4 | ● 2 (2-15-2, 2-15-3) | WAF/web layer — strong (SC-7/SI-10/RA-5). |
| **D3 Cybersecurity Resilience** (3-1) | 4 | ○ 0 | **Detection cannot evidence this** — BCM/DR planning. |
| **D4 Third-Party & Cloud** (4-1, 4-2) | 8 | ○ 0 | **Detection cannot evidence this** — contracts, in-Kingdom hosting, supply chain (T1195 rejected in adversarial pass as SR-family/4-1). |
| **D5 ICS/OT** (5-1) | 4 | ○ 0 | **Detection cannot evidence this** — no ICS/OT detection content in library. |
| **Total** | **114** | **● 20 / ○ 94** | 17.5% control coverage, entirely Domain 2 technical subdomains. |

## 5. Residual Caveats

1. **2-13 is adjacency, not attestation.** Even after correcting §3.2, the incident subdomain's evidence is "a detection that *feeds* incident response," never proof that IR plans, classification tiers, or NCA-reporting workflows exist. Consumers must pair 2-13 rows with process artifacts.
2. **Subdomains 2-6 and 2-7** are honestly graded but weak; treat as supporting, not primary, evidence.
3. **Bundled-vs-canonical ATT&CK numbering** (T1685 ↔ T1562) will confuse anyone reconciling against live MITRE/CTID; carry a translation note.
4. **20/114 is a floor, not a ceiling of the program** — it reflects only what *detection content* can witness. The 94 zero-evidence controls are not "failing"; they are simply outside what this artifact can speak to and must be evidenced by policy, configuration, and process reviews.
5. **This is not an NCA attestation.** The map is community guidance to *assemble* an evidence package; read `risk_reduction_flag` per row before citing any row as risk reduction.

## 6. Overall Verdict

### CONDITIONAL PASS

The artifact is methodologically sound, honest about its concentration, disciplined about compliant-≠-secure, and free of fabricated controls or techniques. It does **not** enable a false "compliant *and* secure" claim: coverage is transparently 20/114, risk-reduction is flagged per row, and false-flags are correctly called. It clears the bar the project sets for itself.

The verdict is **conditional** only on three low-effort corrections; none requires re-analysis:

1. **Downgrade 2 confidence overclaims** — `T1190 → 2-13-2` and `T1505.003 → 2-13-2` from `high` to `medium`, to restore consistency with the parallel downgrade of `T1190 → 2-10-2` and to avoid double-counting the same evidence at full strength in two subdomains. (Alternatively, keep `high` only if an explicit in-row rationale defends why detection evidences incident-management *implementation* more strongly than it evidences vuln-management implementation — but `medium` is the honest default.)
2. **Fix the stale rationale** on `T1053.005 → 2-3-3` — the prose says "hence medium" while the graded fields correctly read `low` / `false`; align the text to the fields.
3. **Add the bundled-vs-canonical numbering caveat** (T1685 ↔ T1562, no CTID anchor by construction) to the data model / README so downstream consumers translate the ID.

On completion of items 1–3 this artifact merits an unconditional PASS.

## 7. Condition Resolution (2026-09-01)
All three conditions were applied and the deterministic gate re-run clean (0 ERR / 0 WARN / 0 REVIEW):
1. **Downgraded** `T1190 → 2-13-2` and `T1505.003 → 2-13-2` from `high` → `medium`, with an in-row note explaining the cross-subdomain double-count. ✅
2. **Fixed** the stale rationale on `T1053.005 → 2-3-3` — prose now matches the `low` / `false` graded fields (adjacency, not direct evidence). ✅
3. **Added** the bundled-vs-canonical ATT&CK numbering caveat (T1685 ↔ T1562, no CTID anchor by construction) to `docs/DATA-MODEL.md`. ✅

**Resulting verdict: PASS.** Final set: 85 mappings across 20 ECC controls; 40 high / 41 medium / 4 low; 94 of 114 controls carry zero detection evidence (transparent, by design).

---
*Audited independently against NCA ECC-1:2018 as ground truth. This sign-off assesses mapping evidence-validity and honesty; it is not an NCA compliance attestation.*
