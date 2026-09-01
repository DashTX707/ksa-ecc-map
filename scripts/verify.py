#!/usr/bin/env python3
"""
verify.py — the single command that runs the whole KSA ECC-Map pipeline gate.
Run it before every commit/merge; CI runs it on every push. Exits non-zero if
any BLOCKING stage fails, so bad data/renders cannot ship.

Stages:
  1. Deterministic audit gate      (audit_eccmap.py) ............ BLOCKING
  2. Site-data reproducibility      (build_site_data.py + diff) .. BLOCKING
  3. Real-browser responsive check  (check_responsive.js) ....... BLOCKING if runnable,
                                                                    WARN if Playwright absent
Design: fail-closed. A gate that cannot run its check is reported loudly, never
silently passed.
"""
import subprocess, sys, os, shutil, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
def run(cmd, **kw):
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", **kw)

fails, warns = [], []
def hr(t): print("\n" + "=" * 4 + " " + t + " " + "=" * 4)

# 1. deterministic audit ----------------------------------------------------
hr("1/3  deterministic audit gate")
r = run([sys.executable, "scripts/audit_eccmap.py"])
tail = "\n".join(r.stdout.strip().splitlines()[-6:])
print(tail or r.stderr[-500:])
if r.returncode != 0:
    fails.append("audit_eccmap.py returned ERR (see above)")

# 2. site-data reproducibility ---------------------------------------------
hr("2/3  site-data reproducibility")
data = os.path.join(REPO, "docs", "_data.js")
backup = None
if os.path.exists(data):
    backup = tempfile.NamedTemporaryFile(delete=False, suffix=".js").name
    shutil.copy(data, backup)
gen = run([sys.executable, "scripts/build_site_data.py"])
if gen.returncode != 0:
    fails.append("build_site_data.py failed: " + gen.stderr[-300:])
elif backup:
    same = open(backup, encoding="utf-8").read() == open(data, encoding="utf-8").read()
    print("docs/_data.js is " + ("in sync with source." if same else "STALE — regenerate & commit."))
    if not same:
        fails.append("docs/_data.js is stale (build_site_data.py produced a different file)")
if backup:
    os.remove(backup)

# 3. real-browser responsive check -----------------------------------------
hr("3/3  real-browser responsive check")
if shutil.which("node") is None:
    warns.append("node not found — responsive check SKIPPED (install Node + Playwright).")
    print("SKIP: node not found.")
else:
    r = run(["node", "scripts/check_responsive.js"])
    print((r.stdout or "").strip() or (r.stderr or "")[-500:])
    if r.returncode == 1:
        fails.append("responsive check found horizontal overflow (see table above)")
    elif r.returncode == 2:
        warns.append("Playwright not installed — responsive check SKIPPED (npm i playwright && npx playwright install chromium).")

# summary -------------------------------------------------------------------
hr("summary")
for w in warns: print("  WARN: " + w)
for f in fails: print("  FAIL: " + f)
if fails:
    print(f"\nVERIFY: FAILED ({len(fails)} blocking, {len(warns)} warn)")
    sys.exit(1)
print(f"\nVERIFY: PASSED{' with ' + str(len(warns)) + ' warning(s)' if warns else ''}")
sys.exit(0)
