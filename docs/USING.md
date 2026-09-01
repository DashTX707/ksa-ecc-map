# How to use KSA ECC-Map at an assessment — and how NOT to

Read this first. One screen. It is the difference between using this map safely
and misusing it into a false compliance claim.

## What this is
A community crosswalk showing which deployable detections (from the MENA Detection
Library) provide **candidate evidence** toward the *intent* of NCA ECC-1:2018 and
CSCC-1:2019 control clauses — in the Kingdom's own frameworks, bilingually.

## The one mental model you must hold
A mapping means: *"a detection for this ATT&CK technique, if deployed and firing in
your environment, is evidence that the monitoring/response capability behind this
control is operating."* It does **not** mean the control is implemented, and it does
**not** mean risk is reduced. Three separate things:

| A detection evidences… | It does NOT prove… |
|---|---|
| a capability is **operating** | the control is **implemented** (policy, process, review) |
| something is **observable** | the risk is **reduced** — read the `risk_reduction_flag` |
| a citable data point | that an **NCA assessor accepts** it — they are not bound by this map |

## DO
- Use it to **organize candidate evidence** for the ~20 ECC + ~10 CSCC technical-defense
  controls it covers, then **confirm in your own environment** that the cited rule is
  actually deployed and firing before citing it.
- Follow each mapping's **rule-file drill-down** to the exact Sigma/hunt file, and verify
  that rule exists in *your* SIEM.
- Treat `risk_reduction_flag = false` ("nominal") rows as *checkbox-only* — they satisfy
  the letter of a control clause without materially reducing risk.
- Read the **coverage honesty**: most controls (94/114 ECC, 22/32 CSCC) carry **zero**
  detection evidence — because detection cannot evidence governance/policy/process/review
  controls. Those need different evidence entirely.

## DO NOT
- **Do NOT** read "20 of 114 controls covered" as "17.5% compliant." Coverage and
  compliance are unrelated numbers.
- **Do NOT** screenshot a green "mapping audit: PASS" chip as "we passed our ECC audit."
  The audit here is an evidence-validity check of the mappings — **not** a compliance
  attestation and **not** third-party assurance (it is a same-pipeline self-audit).
- **Do NOT** cite a mapping without confirming the underlying rule is deployed and firing.
- **Do NOT** use a mapping to justify *not* implementing a control (e.g. "we detect
  T1490, so we can skip backup testing") — that is the inverse harm the `risk_reduction_flag`
  exists to prevent.

## Freshness
Mappings are reconciled against NCA ECC-1:2018 and CSCC-1:2019 as published, sourced
2026-09-01. The NCA revises its frameworks; if a control is renumbered or retired
upstream, a mapping may cite a control that no longer means what you expect. Check the
`sourced_on` / `official_source` in each `catalog/*.json` and re-verify against the
current NCA text before operational reliance.
