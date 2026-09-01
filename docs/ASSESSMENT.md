# KSA ECC-Map — Independent Assessment & Remediation Log
*2026-09-01. Four independent adversarial lenses + deterministic checks, then full remediation.*

## Verdicts (pre-remediation)
| Lens | Verdict |
|---|---|
| Methodology & mapping quality | SOUND-WITH-FIXES (catalogs independently re-verified faithful to NCA) |
| Data integrity & repo hygiene | SHIP WITH FIXES |
| Presentation & misuse-risk | SHIP WITH FIXES |
| Fitness-for-purpose (CISO view) | ADOPTABLE-WITH-GUARDRAILS |

**Convergent theme (3 of 4 lenses):** the project's own #1 risk — false-compliance misuse — was partly enabled by the presentation (green "audit PASS" badge, coverage counts up front, the zero-evidence truth absent from the page).

## Findings → remediation

| # | Finding | Lens | Status |
|---|---|---|---|
| P0 | Audit gate silently skipped technique validation when the ATT&CK dataset was absent (a machine-specific temp path) — "0 ERR" true only on the author's machine | Data-integrity | **FIXED** — vendored `vendor/attack_dump.json` + `vendor/library_manifest.json`; gate is now **fail-closed** (missing dep = ERR) and self-contained. **Negative-tested** (removed dep → exit 1). |
| P1 | Library-ref check had an `isdir` bypass (fabricated per-file ref passed) | Data-integrity | **FIXED** — refs now validated against the vendored manifest, incl. that the file actually tags/cites the technique. Negative-tested. |
| P1 | "audit PASS" badge (green, checkmark) read as a compliance pass | Presentation | **FIXED** — relabeled "mapping audit: PASS — not a compliance pass", neutral styling, + equal-weight "NOT an NCA attestation" chip. |
| P1 | The "94/114 & 22/32 controls have zero evidence" fact never appeared on the page | Presentation/Fitness | **FIXED** — leading zero-evidence stat tile; coverage reframed to "controls that HAVE detection evidence". |
| P1 | Base-vs-enhancement leakage: `T1110`/`T1110.003`/`T1133 → 2-2-1` kept HIGH by logic the audit rejected for `T1078` | Methodology | **FIXED** — downgraded to medium with notes; re-gated. |
| P2 | Accordion mapping rows not keyboard-operable (WCAG 2.1.1) | Presentation | **FIXED** — `role=button`, `tabindex`, `aria-expanded`, Enter/Space handler. |
| P2 | Invalid CSS (selector + `@media` mashup) broke dark-mode filter contrast | Presentation | **FIXED** — split into two valid rules. |
| P2 | "Nominal only" filter silently ignored in the technique tab | Presentation | **FIXED** — `rr` added to technique data; filter wired; nominal chips struck through. |
| P2 | CTID corroboration is low-specificity; 2-12 monitoring over-mapping double-counts | Methodology | **DISCLOSED** — DATA-MODEL "Methodology limits" section + a `high` requires core-family + named-element rule. |
| P2 | No LICENSE / CTID attribution | Data-integrity | **FIXED** — `LICENSE` (CC BY 4.0 data/docs, MIT code) + `NOTICE` (CTID Apache-2.0, NCA ownership, ATT&CK terms). |
| P2 | Scripts hardcoded personal Windows paths | Data-integrity | **FIXED** — repo-relative defaults; env-var overrides documented. |
| P3 | Small data corrections (T1074.001 caveat misattribution; T1113→2-5-1 phantom CTID citation; CSCC 2-2-2 review-control rows) | Methodology | **FIXED** — citations corrected; 2 review-control rows dropped. |
| P3 | Stale ECC-only `og:description` | Presentation/Data | **FIXED** — framework-agnostic. |
| P3 | `.domrow` no mobile breakpoint | Presentation | **FIXED** — stacks + `overflow-wrap` under 720px. |
| Fitness MUST | Mappings pointed to packs, not rule files (evidence chain broke at the last mile) | Fitness | **FIXED** — every row now carries `library_rule_refs` to the exact `.yml`/`.md`; the site deep-links each to the Detection Library. |
| Fitness MUST | No one-screen "how to / how NOT to use at an assessment" guide | Fitness | **FIXED** — `docs/USING.md` + a prominent on-page honesty banner. |
| Fitness MUST | No NCA-revision version-pinning | Fitness | **FIXED** — `reconciled_on` on each catalog, surfaced on the page + in USING.md. |
| Fitness SHOULD | No gap list of uncovered technical controls | Fitness | **FIXED** — a "Detection gap list" section (Domain-2 controls with zero mappings = detection backlog). |
| Fitness SHOULD | Bundled-vs-canonical ATT&CK IDs trip cross-reference | Methodology/Data | **DISCLOSED** — translation table (T1685≈T1562, etc.) in DATA-MODEL. |

## Deterministic checks (independent)
- **Gate has teeth (proven):** planted invalid technique, fabricated control ID, unknown framework, nonexistent + fabricated file refs, missing field — all caught. Missing-dependency now fails closed.
- No secrets/PII. `_data.js` byte-reproducible from source. Both audit reports' numbers match the data. No verbatim NCA text.

## What is deliberately NOT claimed
Coverage is concentrated (ECC 20/114, CSCC 13/32 controls carry any detection evidence; the rest cannot be evidenced by detection). This is community guidance, a same-pipeline self-audit (not third-party assurance), and **not an NCA attestation**. Confidence and risk-reduction are graded and honest per row; read the nominal flag.

*Final state: 138 audited mappings across 2 frameworks; self-contained fail-closed gate; full rule-file drill-down.*
