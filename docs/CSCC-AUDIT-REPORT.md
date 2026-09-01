# KSA ECC-Map — Independent Audit & Sign-Off (CSCC overlay)

> **Post-assessment note (2026-09-01):** after this sign-off, an independent full assessment prompted further changes (confidence downgrades, dropped review-control rows, rule-file drill-down, a fail-closed gate). Current totals and the full remediation log are in [ASSESSMENT.md](ASSESSMENT.md); this report reflects the state at audit time.


**Framework audited against:** NCA CSCC-1:2019 (4 domains, 21 subdomains, 32 main controls, 73 subcontrols)
**Artifact audited:** 56 vetted technique→control mappings (post deterministic gate + adversarial pass: 3 rejected, 14 downgraded)
**Auditor role:** Independent final auditor, harnessed with the full CSCC-1:2019 catalog as ground truth
**Audit date:** 2026-09-01
**Verdict:** **PASS** — the conditions below were resolved on 2026-09-01 (see §7). Original verdict: CONDITIONAL PASS.

---

## 1. Scope

Final stage of the KSA ECC-Map pipeline for the **CSCC critical-systems overlay**. Covers:

- **56 surviving mapping rows** across two files: `mappings/cscc/detection-core.json` (38) and `mappings/cscc/network-data-backup.json` (18).
- **Ground truth:** `catalog/cscc.json` (32 CSCC-1:2019 controls, paraphrased intent, verified against the official NCA English + Arabic PDFs).
- **Corroboration:** MITRE CTID ATT&CK→NIST 800-53 (`corroboration/technique_to_nist80053.json`) and the Detection Library technique index (`corroboration/library_technique_index.json`).
- **Context:** the prior adversarial verdicts (`validation/cscc_verdicts.json` — 59 verdicts: 3 reject + 56 keep/downgrade) and the honesty invariants (`docs/DATA-MODEL.md`).

Out of scope: correctness of the underlying Sigma/hunt content inside each pack (assumed valid; existence of techniques and pack refs is enforced by the deterministic gate, which the artifact has passed); NCA endorsement (this artifact is explicitly **not an attestation**).

## 2. Methodology & Limits

**The approach (unchanged from the ECC sign-off):** each row asserts that a detection/hunt the Library ships for an ATT&CK technique produces operational **evidence** for the *intent* of a control. CTID's ATT&CK→NIST crosswalk is the independent corroboration axis; where the technique's NIST anchors fall in the families that embody the control's intent, the row is corroborated, and where CTID is silent the row must say so and drop to `medium`/`low`.

**The CSCC-specific test — the load-bearing addition to the method.** CSCC is a strict *"in addition to ECC"* critical-systems overlay: nearly every control is phrased "extending ECC x-y-z." A detection that fires on a critical system trivially evidences the **base ECC** capability. That is **not** what these rows must show. To survive, a row must evidence the **enhanced** element the CSCC control names — e.g. block remote access *from outside KSA* (2-2-1), *application whitelisting* on servers (2-3-1), *internet-egress-blocked, whitelist-only* segmentation (2-4-1), *monthly* remediation cadence (2-9-1). Confidence tiers must track how specifically the technique maps to a **named enhancement element**, not merely to the ECC baseline. This audit re-scored every surviving row against that bar; the map largely honours it (geo-block T1133 and default-password T1078.001 sit high because they hit named 2-2-1 elements; generic valid-account T1078 was downgraded), with the residual exceptions in §3.2.

**Stated limits — plainly:**

- **Detection evidences operation, not process.** A detection can show a monitoring/anti-malware/whitelisting/DLP capability is *operating*; it can never evidence a documentation, governance, cadence, or periodic-review control. Correctly, **no row maps to any define/review control** (2-13-1, 2-13-4), to any periodic-process control (2-8-2 quarterly restore test, 2-9-2 monthly VA, 2-10-1/2-10-2 pen-test, 2-11-2 18-month retention, 2-12-2 three-tier architecture), or to any Domain 1/3/4 governance/resilience/third-party control.
- **The CTID IR-family limit is MOOT for CSCC.** In the ECC map the Incident & Threat subdomain (2-13) could not be corroborated by an IR-* anchor. **CSCC has no incident subdomain at all** — its Domain 2 re-covers Defense with no ECC-2-13 analogue, and its own 2-13 is *Application Security*, an app-layer technical control corroborated by SC-7/SI-10/SI-4/CM-* not IR-*. So the IR-family gap that qualified the ECC sign-off simply does not arise here. (Stated for completeness, per the audit charter.)
- **Corroboration ≠ control existence.** The map evidences that a technique *would be caught*; it does not prove the organisation implemented the full stricter control. It is guidance for assembling an evidence package, not the evidence itself.
- **Bundled-vs-canonical ATT&CK numbering.** Per `DATA-MODEL.md`, the bundled dataset renumbers part of the Impair-Defenses family. **No surviving CSCC row depends on a renumbered ID** — every technique used (T1078/T1110/T1133/T1021.x/T1003.x/T1204.x/T1055/T1218.x/T1190/T1505.x/T1539/T1071.001/T1090/T1572/T1048.x/T1490/T1485/T1486/T1561/etc.) carries a canonical CTID→NIST anchor, each of which this audit sampled and confirmed transcribed accurately (e.g. T1490/T1485/T1486/T1561→CP-9/CP-10; T1572→SC-7/AC-4/SI-15; T1505.004→…/SI-14; T1539→AC-3/IA-2/IA-5/SI-4).

## 3. Findings by Dimension

### 3.1 Methodology soundness (CSCC-specific) — PASS
The overlay was mapped with the correct discipline: rows are anchored to the *enhanced* element, not the ECC base, and the adversarial pass visibly enforced this (it downgraded `T1078→2-2-1` high→medium precisely because "generic valid-account detection evidences base-ECC IAM monitoring, not the CSCC preventive enhancements," and rejected `T1078.002→2-2-2` and `T1190→2-9-2` as category errors against process controls). Confidence tiers track anchor strength and named-element specificity. The map refuses to claim any process/governance coverage it cannot witness. The one place the enhanced-vs-base bar is still not fully met is §3.2 item A.

### 3.2 Residual evidence-validity — 5 rows still challenged
The adversarial pass was thorough; most surviving rows are honestly graded and defensible. Five residual issues survive:

| # | Technique → Control | Current | Challenge | Rationale |
|---|---|---|---|---|
| A | **T1078 → 2-2-1** | medium / true | recommend **low** or drop | Base-vs-enhancement failure. The verdict itself conceded this row "evidences base-ECC IAM monitoring, not the CSCC preventive enhancements (MFA-for-all, geo-block outside KSA)" and is "better aligned to 2-11-1." The identical evidence *is* already booked at **2-11-1 high** (its true home). Keeping it at medium/true on the hardened-IAM **enhancement** control credits the ECC baseline, not the CSCC delta — exactly the error the CSCC test exists to catch. |
| B | **T1190 → 2-13-2** | high / true | recommend **medium** / re-scope | Technique-scope mismatch. 2-13 is *internal* Application Security; T1190 is **Exploit *Public-Facing* Application** — its true home is the external-web control **2-12-1**, where the same technique is already booked **high**. Booking the flagship public-facing-exploit technique at full strength again on the *internal*-app control double-counts one piece of evidence and stretches an internet-exposure technique onto an isolated-app control. (T1505.003 web-shell and T1505.004 IIS-module on 2-13-2 are genuine app-layer implants and are *not* challenged.) |
| C | **T1485 → 2-8-1** | medium / true | recommend **false** | Compliant≠secure inconsistency (see §3.4). Data-destruction detection is response/recovery evidence; it does not evidence that protected online/offline backups **exist and are protected**, which is what 2-8-1 requires. The analogous ECC row is `risk_reduction_flag=false`. |
| D | **T1486 → 2-8-1** | medium / true | recommend **false** | Same as C — ransomware detection triggers fallback but does not evidence backup scope/protection. ECC sibling is false. |
| E | **T1561 → 2-8-1** | medium / true | recommend **false** | Same as C — disk-wipe detection principally supports response; the backup-protection nexus is a downstream inference. ECC sibling is false. Only **T1490 → 2-8-1** (Inhibit System Recovery) genuinely evidences recovery-capability protection and correctly stays high/true. |

Noted-but-not-challenged soft spots (honestly labelled, left as-is):
- **2-9-1 (vuln remediation cadence)** — the four exploitation-detection rows (T1190/T1203/T1068/T1210, all medium/true) evidence that *exploitation of unpatched flaws would be caught*, not that the monthly/quarterly **cadence** is performed. The verdict conceded "being exploited is the risk, not proof of remediation." Held at medium is honest because catching exploitation does reduce risk; the rows do not overclaim the cadence.
- **2-3-1 whitelisting** — T1105 (ingress transfer) and T1027 (obfuscation) at medium are adjacency to whitelisting (they corroborate it indirectly); the verdict's medium is the honest floor.
- **T1053.005 → 2-11-1** (medium) — scheduled-task events are legitimate *telemetry* into a 24/7 monitoring control (unlike the same technique's stretched, correctly-`low` use at 2-3-1). Defensible.

### 3.3 Coverage honesty — PASS (strong)
The map does not fake universality and is candid about concentration:

- **10 of 32 CSCC controls** carry genuine (risk-reducing, `true`-flag) detection evidence — **all 10 in Domain 2 (Defense)**, all in detective/technical subdomains: 2-2-1, 2-3-1, 2-4-1, 2-6-1, 2-8-1, 2-9-1, 2-11-1, 2-12-1, 2-13-2, 2-13-3.
- **18 of 32 controls carry no mapping row at all.** A further **4 controls (2-1-1, 2-2-2, 2-5-1, 2-7-1)** carry *only* nominal rows that are explicitly `risk_reduction_flag=false` with rationale "detection cannot evidence this." **Therefore 22 of 32 CSCC controls have zero genuine detection evidence** (18 empty + 4 nominal-only).
- The 4 nominal-only controls are the exact process/config controls the audit charter names — **2-1 asset inventory** (T1046→2-1-1, discovery ≠ inventory upkeep), **2-7 cryptography** (T1048.003→2-7-1, an unencrypted-channel alert does not prove crypto is configured), plus 2-2-2 (quarterly access review) and 2-5-1 (mobile access-prohibition + FDE). They are carried *as documented "detection cannot evidence this" placeholders*, not as coverage. This is the correct, honest treatment.
- **All of Domains 1, 3 and 4 are empty (0/10 controls)** — governance, HR/vetting, project management, audit, resilience/DR, third-party and in-Kingdom/CCC cloud hosting are governance/process/contractual and out of detective reach by nature.
- Evidence lands only on `implement`/`core-set`-style controls (2-x-1 defense controls, 2-13-2/2-13-3), never on define (2-13-1), review (2-13-4), or the periodic-cadence controls (2-8-2, 2-9-2, 2-10-1/2, 2-11-2, 2-12-2). Correct.

### 3.4 Compliant ≠ secure integrity — PASS with one reconciliation (conditions C–E)
- **False-flags are all correct.** Every one of the 10 `false` rows is honestly nominal: credential-dump/account-manip → 2-2-1 hashing/service-account *config* (T1003.001/T1003.004/T1098); rogue-account/local-abuse → 2-2-2 quarterly *review* (T1078.003/T1136.001); registry-mod & scheduled-task → 2-3-1 six-monthly hardening/whitelisting *adjacency* (T1112/T1053.005); mobile screen/portal capture → 2-5-1 *access-prohibition/FDE* (T1113/T1056.003); service-discovery → 2-1-1 *inventory* (T1046); unencrypted-exfil → 2-7-1 *crypto config* (T1048.003). None dishonestly claims risk reduction it does not deliver.
- **One dishonest-leaning `true` cluster — the 2-8-1 backup rows (C/D/E).** T1485/T1486/T1561 → 2-8-1 are graded `true`, but destructive-impact detection is response evidence; it does not evidence that the control's actual requirement (protected online **and** offline backups covering all critical systems) exists or operates. The ECC sign-off set the precedent by flagging the analogous ransomware/wiper rows `false`. To keep the compliant≠secure signal consistent across frameworks, these three should flip to `false` (leaving T1490 as the single honest `true`). This is the only integrity inconsistency in the set.

### 3.5 Licensing / no-fabrication — PASS
- **No control IDs outside the catalog.** All 14 referenced control IDs (2-1-1, 2-2-1, 2-2-2, 2-3-1, 2-4-1, 2-5-1, 2-6-1, 2-7-1, 2-8-1, 2-9-1, 2-11-1, 2-12-1, 2-13-2, 2-13-3) exist in `catalog/cscc.json`. No evidence is claimed against the 18 empty controls (no invented rows for 2-8-2/2-9-2/2-10-x/2-12-2/2-13-1/2-13-4 or any Domain 1/3/4 control).
- **No fabricated techniques or corroboration.** Every technique resolves in the bundled dataset (gate-enforced); the cited CTID anchors were independently sampled and match the CTID source exactly (including the unusual-but-real T1505.004→SI-14 and the CP-9/CP-10 backup family). Cross-framework `source_refs` correctly label CSCC 2-13-2/2-13-3 as "CSCC-only, no ECC equivalent."
- **Intent paraphrased, not verbatim.** Catalog intents are concise paraphrases with `source_ref` links to the official NCA document; Arabic confirmed at domain/subdomain level per the catalog's structure note. No verbatim NCA text redistributed.

## 4. Coverage Summary (by CSCC subdomain)

Legend: ● genuine (risk-reducing) evidence · ◐ only nominal `false` rows (documented "detection cannot evidence this") · ○ no row · **DCE** = *detection cannot evidence this by nature* (process/governance/config/periodic).

| Domain / Subdomain | Controls | Status | Note |
|---|---|---|---|
| **D1-1** Cybersecurity Strategy | 1 (1-1-1) | ○ | **DCE** — strategy prioritisation. |
| **D1-2** Risk Management | 1 (1-2-1) | ○ | **DCE** — annual assessment + monthly register. |
| **D1-3** IT Project Management | 2 (1-3-1/2) | ○ | **DCE** — secure-SDLC/change process. |
| **D1-4** Periodic Review & Audit | 2 (1-4-1/2) | ○ | **DCE** — internal/independent review cadence. |
| **D1-5** Cybersecurity in HR | 1 (1-5-1) | ○ | **DCE** — vetting / Saudi-staffing. |
| **D2-1** Asset Management | 1 (2-1-1) | ◐ | **DCE** — inventory/ownership process; T1046 carried nominal `false`. |
| **D2-2** Identity & Access Mgmt | 2 (2-2-1, 2-2-2) | ● / ◐ | 2-2-1 strong (geo-block T1133, default-pw T1078.001, MFA vs brute/spray); 2-2-2 is a quarterly *review* → **DCE**, both rows nominal `false`. Row A (T1078→2-2-1) still leans base-ECC (§3.2). |
| **D2-3** System/Host Protection | 1 (2-3-1) | ● | Application-whitelisting/endpoint — strong (mshta T1218.005+CM-7, T1055, T1204.002, masquerade T1036.005). |
| **D2-4** Networks Security Mgmt | 1 (2-4-1) | ● | Isolation/egress-block/whitelist-only — strong (C2 T1071.001, proxy T1090, tunneling T1572; SMB/alt-exfil/RAT medium). |
| **D2-5** Mobile Devices Security | 1 (2-5-1) | ◐ | **DCE** — access-prohibition + FDE; T1113/T1056.003 nominal `false`. |
| **D2-6** Data & Information Protection | 1 (2-6-1) | ● | DLP/no-data-out — exfil T1041 high; collection/staging medium. |
| **D2-7** Cryptography | 1 (2-7-1) | ◐ | **DCE** — encryption is preventive/config; T1048.003 nominal `false`. |
| **D2-8** Backup & Recovery Mgmt | 2 (2-8-1, 2-8-2) | ● / ○ | 2-8-1: only T1490 honest `true`; T1485/T1486/T1561 should be `false` (§3.4 C–E). 2-8-2 quarterly restore-test → **DCE**, no row. |
| **D2-9** Vulnerabilities Mgmt | 2 (2-9-1, 2-9-2) | ● / ○ | 2-9-1 four exploitation rows medium/true (cadence not evidenced, honestly held). 2-9-2 monthly VA → **DCE**; T1190 correctly **rejected**. |
| **D2-10** Penetration Testing | 2 (2-10-1/2) | ○ | **DCE** — scope/team + six-monthly exercise. |
| **D2-11** Event Logs & Monitoring | 2 (2-11-1, 2-11-2) | ● / ○ | 2-11-1 best-anchored (24/7 monitoring *requires* the telemetry it evidences). 2-11-2 18-month retention → **DCE**, no row. |
| **D2-12** Web Application Security | 2 (2-12-1, 2-12-2) | ● / ○ | 2-12-1 strong (T1190 OWASP-exploit, T1505.003 web-shell, T1539 session-theft). 2-12-2 three-tier architecture → **DCE**, no row. |
| **D2-13** Application Security | 4 (2-13-1..4) | ○ / ● / ● / ○ | 2-13-1 define → **DCE**. 2-13-2 implement: T1505.003/T1505.004 genuine app-layer; **T1190 challenged** (§3.2 B); T1059 correctly **rejected**. 2-13-3 core-set: T1539 session-mgmt, genuine. 2-13-4 review → **DCE**. |
| **D3-1** Resilience / BCM (DR) | 1 (3-1-1) | ○ | **DCE** — DR-centre/DR-plan/annual test. |
| **D4-1** Third-Party Cybersecurity | 1 (4-1-1) | ○ | **DCE** — vetting + Saudi-provider contract terms. |
| **D4-2** Cloud & Hosting Cybersecurity | 1 (4-2-1) | ○ | **DCE** — in-Kingdom / CCC-compliant hosting. |
| **Total** | **32** | **● 10 · ◐ 4 · ○ 18** | 10/32 genuinely evidenced (all D2 technical); **22/32 zero genuine evidence** (18 empty + 4 nominal-only). |

## 5. Residual Caveats

1. **The overlay speaks only to Domain 2 technical defense.** 22 of 32 CSCC controls carry no genuine detection evidence; that is not a failing of the map but the nature of a critical-systems overlay whose Domains 1/3/4 and half of Domain 2 are governance, cadence, contract, and in-Kingdom-hosting requirements. They must be evidenced by policy, configuration, contracts, and process reviews — never by this artifact.
2. **CSCC evidences the *enhanced* element only as strongly as the technique is specific to it.** Rows anchored to named enhancements (geo-block, whitelisting, egress-block, DLP, 24/7 monitoring) are strong; rows that merely re-witness the ECC baseline on a critical system (condition A) or infer a downstream control (conditions C–E) are the weak edge and are called out.
3. **2-8-1 and 2-9-1 are recovery/remediation-adjacent.** Even after applying conditions C–E, backup and vuln-cadence evidence is "a detection that *triggers* fallback/patching," never proof that protected backups or the monthly/quarterly cadence exist. Pair with backup inventories and patch-cadence records.
4. **Not an NCA attestation.** Community guidance to *assemble* an evidence package; read `risk_reduction_flag` per row before citing any row as risk reduction.

## 6. Overall Verdict

### CONDITIONAL PASS

The CSCC overlay is methodologically sound, correctly applies the "enhanced-not-base" test that the overlay demands, is honest about its concentration (10/32 evidenced, all Domain-2 technical; 22/32 zero genuine evidence), disciplined about compliant≠secure, and free of fabricated controls, techniques, or corroboration. It does not enable a false "compliant *and* secure" claim.

The verdict is **conditional** on three low-effort corrections; none requires re-analysis:

1. **Resolve `T1078 → 2-2-1`** (condition A) — downgrade to `low`, or drop it, since the identical evidence is already carried at `2-11-1 high` and this row credits the ECC baseline rather than the CSCC IAM enhancement.
2. **Re-scope / downgrade `T1190 → 2-13-2`** (condition B) — to `medium`, or re-map, to stop double-counting the public-facing-exploit technique (already `high` at its true home 2-12-1) onto the *internal*-application control.
3. **Flip `T1485`, `T1486`, `T1561 → 2-8-1` to `risk_reduction_flag=false`** (conditions C–E) — destructive-impact detection is response/recovery evidence, not proof the backup-protection control exists; align with the ECC sign-off's precedent (only `T1490` stays `true`).

On completion of items 1–3 this artifact merits an unconditional PASS.

## 7. Condition Resolution (2026-09-01)
All conditions applied; deterministic gate re-run clean (0 ERR / 0 WARN / 0 REVIEW):
- **A** — `T1078 → 2-2-1` **dropped** (identical evidence already carried at `2-11-1 high`; the row credited the ECC baseline, not the CSCC IAM enhancement). ✅
- **B** — `T1190 → 2-13-2` downgraded `high → medium` with an in-row note (already high at its true home `2-12-1`; no full-strength double-count onto the internal-application control). ✅
- **C–E** — `T1485`, `T1486`, `T1561 → 2-8-1` flipped to `risk_reduction_flag=false` (destructive-impact detection is response/recovery evidence, not proof the backup-protection control exists; only inhibit-recovery `T1490` stays `true`). ✅

**Resulting verdict: PASS.** Final CSCC set: 55 mappings across 10 controls (all Domain 2); 22 of 32 controls carry zero risk-reducing detection evidence — transparent, by design.

---
*Audited independently against NCA CSCC-1:2019 as ground truth. This sign-off assesses mapping evidence-validity and honesty; it is not an NCA compliance attestation.*
