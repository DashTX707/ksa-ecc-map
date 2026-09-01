#!/usr/bin/env python3
"""
KSA ECC-Map — deterministic audit gate (multi-framework).

Validates every framework catalog and all technique->control mappings against:
  1. catalog/*.json              — canonical NCA control lists (one per framework)
  2. attack_dump.json            — the bundled ATT&CK dataset (same source the
                                   MENA Detection Library CI uses)
  3. the 44-pack Detection Library on disk — for library_pack_ref join integrity

Mappings live under mappings/<framework>/*.json. Each row declares its
`framework` and a `control_id`, validated against that framework's catalog.

Exit non-zero if any ERR is found. WARN/REVIEW are advisory.
Run:  python scripts/audit_eccmap.py
"""
import json, os, re, glob, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CATALOG_DIR = os.path.join(REPO, "catalog")
MAPDIR = os.path.join(REPO, "mappings")
ATTACK_DUMP = os.environ.get(
    "ATTACK_DUMP",
    "C:/Users/IbrahimAbdlrazik/AppData/Local/Temp/attack_dump.json")
LIBRARY = os.environ.get(
    "MENA_LIBRARY",
    "C:/Users/IbrahimAbdlrazik/Desktop/mena-detection-library")

CONTROL_ID_RE = re.compile(r"^\d+(-\d+)+$")     # variable depth: 2-3 or 2-3-1 or 2-3-1-1
INTENT_MAX_WORDS = 40

problems = []
def P(sev, where, msg): problems.append((sev, where, msg))

def load_json(path, what):
    try:
        return json.load(open(path, encoding="utf-8"))
    except FileNotFoundError:
        P("ERR", what, f"missing file: {path}"); return None
    except Exception as e:
        P("ERR", what, f"parse fail: {e}"); return None

# ---------------- load ATT&CK source of truth ----------------
TECH = set()
if os.path.exists(ATTACK_DUMP):
    dump = load_json(ATTACK_DUMP, "attack_dump")
    if dump: TECH = set(dump.get("techniques", {}))
else:
    P("WARN", "attack_dump", f"ATT&CK dataset not found at {ATTACK_DUMP} — technique-id validation skipped")

# ---------------- load + validate every catalog ----------------
# framework name -> set(control_ids)
FW_CONTROLS = {}
catalog_files = sorted(glob.glob(os.path.join(CATALOG_DIR, "*.json")))
if not catalog_files:
    P("ERR", "catalog", "no catalog/*.json files found")
for cf in catalog_files:
    cat = load_json(cf, os.path.basename(cf))
    if not cat:
        continue
    fw = cat.get("framework")
    if not fw:
        P("ERR", os.path.basename(cf), "catalog missing 'framework' name"); continue
    if not cat.get("official_source"):
        P("ERR", fw, "no official_source recorded")
    domain_ids = set()
    for d in cat.get("domains", []):
        domain_ids.add(str(d.get("domain_id", "")))
        if not d.get("title_en"): P("ERR", fw, f"domain {d.get('domain_id')} missing title_en")
        if not d.get("title_ar"): P("REVIEW", fw, f"domain {d.get('domain_id')} missing title_ar")
    ctrls = cat.get("controls", [])
    if not ctrls:
        P("ERR", fw, "no controls in catalog")
    ids = set()
    for c in ctrls:
        cid = c.get("control_id", "")
        if not CONTROL_ID_RE.match(cid):
            P("ERR", fw, f"malformed control_id: {cid!r}")
        if cid in ids:
            P("ERR", fw, f"duplicate control_id: {cid}")
        ids.add(cid)
        if str(c.get("domain_id")) not in domain_ids:
            P("ERR", fw, f"{cid}: domain_id {c.get('domain_id')} not in domains[]")
        if not c.get("title_en"):
            P("ERR", fw, f"{cid}: missing title_en")
        if not c.get("source_ref"):
            P("ERR", fw, f"{cid}: missing source_ref")
        intent = (c.get("intent") or "").strip()
        if not intent:
            P("ERR", fw, f"{cid}: missing intent")
        elif len(intent.split()) > INTENT_MAX_WORDS:
            P("REVIEW", fw + "-licensing", f"{cid}: intent {len(intent.split())} words (>{INTENT_MAX_WORDS}) — check paraphrase not verbatim")
        if not c.get("verified", False):
            P("WARN", fw, f"{cid}: verified=false ({c.get('note','no note')})")
        # NCA controls have no per-control title in either language; Arabic context
        # is carried at subdomain level -> the bilingual invariant is subdomain_ar.
        if not c.get("subdomain_ar"):
            P("REVIEW", fw, f"{cid}: missing subdomain_ar (bilingual gap)")
    FW_CONTROLS[fw] = ids

# ---------------- mappings integrity ----------------
REQUIRED = ("attack_technique_id", "framework", "control_id", "evidence_type",
            "rationale", "mapping_confidence", "risk_reduction_flag", "source_refs")
seen_pairs = set()
map_files = sorted(glob.glob(os.path.join(MAPDIR, "**", "*.json"), recursive=True))
n_map = 0
for mf in map_files:
    rows = load_json(mf, os.path.relpath(mf, MAPDIR))
    if not isinstance(rows, list):
        if rows is not None:
            P("ERR", os.path.relpath(mf, MAPDIR), "mapping file is not a JSON array")
        continue
    for i, r in enumerate(rows):
        n_map += 1
        tag = f"{os.path.relpath(mf, MAPDIR)}#{i}"
        for k in REQUIRED:
            if k not in r or r[k] in ("", None, []):
                P("ERR", tag, f"missing/empty field: {k}")
        fw = r.get("framework")
        cid = r.get("control_id", "")
        if fw not in FW_CONTROLS:
            P("ERR", tag, f"unknown framework {fw!r} (no matching catalog)")
        elif cid not in FW_CONTROLS[fw]:
            P("ERR", tag, f"control_id {cid} not in {fw} catalog — fabricated/typo control")
        tid = r.get("attack_technique_id", "")
        if TECH and tid not in TECH:
            P("ERR", tag, f"invalid attack_technique_id {tid} (not in bundled ATT&CK dataset)")
        if r.get("evidence_type") not in ("detect", "hunt", None):
            P("ERR", tag, f"evidence_type must be detect|hunt, got {r.get('evidence_type')!r}")
        if r.get("mapping_confidence") not in ("high", "medium", "low", None):
            P("REVIEW", tag, f"mapping_confidence should be high|medium|low, got {r.get('mapping_confidence')!r}")
        if r.get("mapping_confidence") == "high" and r.get("risk_reduction_flag") in (False, "none", "nominal"):
            P("REVIEW", tag, "high-confidence mapping flagged nominal/no-risk-reduction — reconcile")
        for ref in (r.get("library_pack_refs") or []):
            if not (os.path.exists(os.path.join(LIBRARY, "actors", ref))
                    or os.path.isdir(os.path.join(LIBRARY, "actors", ref.split("/")[0]))):
                P("ERR", tag, f"library_pack_ref does not exist on disk: {ref}")
        pair = (fw, tid, cid)
        if pair in seen_pairs:
            P("REVIEW", tag, f"duplicate mapping {fw}:{tid}->{cid}")
        seen_pairs.add(pair)

# ---------------- report ----------------
bysev = {}
for sev, where, msg in problems:
    bysev.setdefault(sev, []).append((where, msg))
fw_summary = " | ".join(f"{fw}: {len(ids)} controls" for fw, ids in FW_CONTROLS.items())
print(f"CATALOGS: {fw_summary}")
print(f"MAPPINGS: {n_map} rows across {len(map_files)} file(s)")
for sev in ("ERR", "WARN", "REVIEW"):
    items = bysev.get(sev, [])
    print(f"\n===== {sev}: {len(items)} =====")
    for where, msg in items[:200]:
        print(f"  [{where}] {msg}")
n_err = len(bysev.get("ERR", []))
print(f"\nTOTAL: {len(problems)} ({n_err} ERR, {len(bysev.get('WARN',[]))} WARN, {len(bysev.get('REVIEW',[]))} REVIEW)")
sys.exit(1 if n_err else 0)
