# KSA ECC-Map — Verification Pipeline

This project does not rely on anyone (human or AI) *remembering* to check things.
Every change passes a **mechanical, fail-closed pipeline** before it ships. If a
gate cannot run its check, that is a loud failure — never a silent pass.

## Run it
```bash
npm install                 # once: installs Playwright + Chromium (for the browser gate)
python scripts/verify.py    # runs the whole pipeline; exit 0 = safe to commit
```
CI ([.github/workflows/verify.yml](../.github/workflows/verify.yml)) runs the same
`verify.py` on every push and pull request. A red check blocks the merge.

## The stages

### How content is produced (per framework)
```
GRC extraction  →  classify (evidences-control vs nominal)  →  cross-check
against MITRE CTID ATT&CK→NIST 800-53  →  adversarial refutation (independent,
default-skeptical)  →  governance full audit  →  human-approved merge
```
Analytical content (the mappings) is generated, then **independently and
adversarially verified** — never trusted single-pass. Each layer reduces error;
none eliminates it, so the final human review and the assessment pass matter.

### What `verify.py` enforces (blocking gates)
1. **Deterministic audit** — `scripts/audit_eccmap.py`, **self-contained & fail-closed**:
   - every `control_id` exists in its framework's catalog (no fabricated controls);
   - every `attack_technique_id` is valid against the **vendored** ATT&CK dataset
     (`vendor/attack_dump.json`) — a *missing* dataset is an ERR, never a skip;
   - every `library_rule_refs` entry resolves to a real Detection-Library file
     **that actually tags/cites the technique** (validated against
     `vendor/library_manifest.json` — no external live directory needed);
   - required fields present; `high` + nominal contradiction surfaced (compliant ≠ secure).
2. **Site-data reproducibility** — regenerates `docs/_data.js` from source and fails
   if it differs (the published data must be derivable, not hand-edited).
3. **Real-browser responsive check** — `scripts/check_responsive.js` loads the page
   in Chromium at 320–1280px, both tabs, both frameworks, with a control expanded,
   and fails on any horizontal overflow. **The page is not "responsive" until measured.**

## Standing rules (why the pipeline is shaped this way)
These come from real failures caught in the independent assessment
([ASSESSMENT.md](ASSESSMENT.md)):
- **Gates are fail-closed and portable.** Dependencies are vendored into `vendor/`;
  the gate runs identically on any checkout/CI. A missing input fails the run.
- **Negative-test the guardrail.** A green check only counts once you've proven it
  *catches* the failure — remove the dependency / plant bad data and confirm it fails.
  (Both `audit_eccmap.py` and `check_responsive.js` were negative-controlled.)
- **Verify in the real environment, not by reasoning.** Responsiveness is measured in
  a browser; data is validated against vendored ground truth; numbers are recomputed.
- **Label provenance honestly.** The governance "PASS" is a same-pipeline self-audit,
  **not** third-party assurance and **not** an NCA attestation.
- **View misuse-prone artifacts adversarially** before shipping (see the honesty
  banner + [USING.md](USING.md)).

## Adding a framework (OTCC / SAMA / …)
1. `catalog/<fw>.json` (official-sourced, paraphrased, bilingual, `reconciled_on`).
2. `mappings/<fw>/*.json` through the production pipeline above.
3. If the Detection Library changed: `python scripts/build_library_manifest.py` and commit `vendor/library_manifest.json`.
4. `python scripts/verify.py` must pass (0 blocking failures) before merge.
