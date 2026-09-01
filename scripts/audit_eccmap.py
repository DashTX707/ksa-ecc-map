#!/usr/bin/env python3
"""
KSA ECC-Map — deterministic audit gate.

Validates the ECC control catalog and (when present) the technique->control
mappings against three sources of truth:
  1. catalog/ecc.json            — the canonical NCA ECC-1:2018 control list
  2. attack_dump.json            — the bundled ATT&CK dataset (same source the
                                   MENA Detection Library CI uses)
  3. the 44-pack Detection Library on disk — for library_pack_ref join integrity

Exit non-zero if any ERR is found. WARN/REVIEW are advisory.
Run:  python scripts/audit_eccmap.py
"""
import json, os, re, glob, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CATALOG = os.path.join(REPO, "catalog", "ecc.json")
MAPDIR = os.path.join(REPO, "mappings")
# ATT&CK source of truth (bundled dataset dumped by the detection-library tooling)
ATTACK_DUMP = os.environ.get(
    "ATTACK_DUMP",
    "C:/Users/IbrahimAbdlrazik/AppData/Local/Temp/attack_dump.json")
# detection-library root, for library_pack_ref existence checks
LIBRARY = os.environ.get(
    "MENA_LIBRARY",
    "C:/Users/IbrahimAbdlrazik/Desktop/mena-detection-library")

CONTROL_ID_RE = re.compile(r"^\d+-\d+-\d+$")   # e.g. 2-3-1
INTENT_MAX_WORDS = 40                          # paraphrase, not verbatim copy

problems = []
def P(sev, where, msg): problems.append((sev, where, msg))

# ---------------- load sources ----------------
def load_json(path, what):
    try:
        return json.load(open(path, encoding="utf-8"))
    except FileNotFoundError:
        P("ERR", what, f"missing file: {path}"); return None
    except Exception as e:
        P("ERR", what, f"parse fail: {e}"); return None

catalog = load_json(CATALOG, "catalog")
TECH = set()
if os.path.exists(ATTACK_DUMP):
    dump = load_json(ATTACK_DUMP, "attack_dump")
    if dump: TECH = set(dump.get("techniques", {}))
else:
    P("WARN", "attack_dump", f"ATT&CK dataset not found at {ATTACK_DUMP} — technique-id validation skipped")

# ---------------- catalog integrity ----------------
control_ids = set()
domain_ids = set()
if catalog:
    for d in catalog.get("domains", []):
        domain_ids.add(str(d.get("domain_id", "")))
        if not d.get("title_en"): P("ERR", "catalog", f"domain {d.get('domain_id')} missing title_en")
        if not d.get("title_ar"): P("REVIEW", "catalog", f"domain {d.get('domain_id')} missing title_ar")
    if not catalog.get("official_source"):
        P("ERR", "catalog", "no official_source recorded")
    ctrls = catalog.get("controls", [])
    if not ctrls:
        P("ERR", "catalog", "no controls in catalog")
    for c in ctrls:
        cid = c.get("control_id", "")
        if not CONTROL_ID_RE.match(cid):
            P("ERR", "catalog", f"malformed control_id: {cid!r}")
        if cid in control_ids:
            P("ERR", "catalog", f"duplicate control_id: {cid}")
        control_ids.add(cid)
        if str(c.get("domain_id")) not in domain_ids:
            P("ERR", "catalog", f"{cid}: domain_id {c.get('domain_id')} not in domains[]")
        if not c.get("title_en"):
            P("ERR", "catalog", f"{cid}: missing title_en")
        if not c.get("source_ref"):
            P("ERR", "catalog", f"{cid}: missing source_ref")
        intent = (c.get("intent") or "").strip()
        if not intent:
            P("ERR", "catalog", f"{cid}: missing intent")
        elif len(intent.split()) > INTENT_MAX_WORDS:
            P("REVIEW", "catalog-licensing", f"{cid}: intent {len(intent.split())} words (>{INTENT_MAX_WORDS}) — check it is paraphrase, not verbatim NCA text")
        if not c.get("verified", False):
            note = c.get("note", "")
            P("WARN", "catalog", f"{cid}: verified=false ({note or 'no note'})")
        # ECC controls have no per-control title in EITHER language (they are clause
        # text); title_en is our paraphrase and per-control Arabic context is carried
        # at the subdomain level. So the bilingual invariant for a control is a
        # verified subdomain_ar, not a (non-existent) per-control title_ar.
        if not c.get("subdomain_ar"):
            P("REVIEW", "catalog", f"{cid}: missing subdomain_ar (bilingual gap)")

# ---------------- mappings integrity (present only after Phase 1) ----------------
REQUIRED = ("attack_technique_id", "ecc_control_id", "evidence_type",
            "rationale", "mapping_confidence", "risk_reduction_flag", "source_refs")
seen_pairs = set()
map_files = sorted(glob.glob(os.path.join(MAPDIR, "*.json")))
n_map = 0
for mf in map_files:
    rows = load_json(mf, f"mappings/{os.path.basename(mf)}")
    if not isinstance(rows, list):
        if rows is not None:
            P("ERR", os.path.basename(mf), "mapping file is not a JSON array")
        continue
    for i, r in enumerate(rows):
        n_map += 1
        tag = f"{os.path.basename(mf)}#{i}"
        for k in REQUIRED:
            if k not in r or r[k] in ("", None, []):
                P("ERR", tag, f"missing/empty field: {k}")
        tid = r.get("attack_technique_id", "")
        if TECH and tid not in TECH:
            P("ERR", tag, f"invalid attack_technique_id {tid} (not in bundled ATT&CK dataset)")
        cid = r.get("ecc_control_id", "")
        if control_ids and cid not in control_ids:
            P("ERR", tag, f"ecc_control_id {cid} not in catalog — fabricated/typo control")
        if r.get("evidence_type") not in ("detect", "hunt", None):
            P("ERR", tag, f"evidence_type must be detect|hunt, got {r.get('evidence_type')!r}")
        if r.get("mapping_confidence") not in ("high", "medium", "low", None):
            P("REVIEW", tag, f"mapping_confidence should be high|medium|low, got {r.get('mapping_confidence')!r}")
        # compliant != secure honesty gate
        if r.get("mapping_confidence") == "high" and r.get("risk_reduction_flag") in (False, "none", "nominal"):
            P("REVIEW", tag, "high-confidence mapping flagged as nominal/no-risk-reduction — reconcile the honesty flag")
        # library join integrity
        for ref in (r.get("library_pack_refs") or []):
            # ref may be 'actor-slug' or 'actor-slug/detections/FILE.yml'
            path = os.path.join(LIBRARY, "actors", ref)
            if not (os.path.exists(path) or os.path.isdir(os.path.join(LIBRARY, "actors", ref.split("/")[0]))):
                P("ERR", tag, f"library_pack_ref does not exist on disk: {ref}")
        pair = (tid, cid)
        if pair in seen_pairs:
            P("REVIEW", tag, f"duplicate mapping pair {tid}->{cid}")
        seen_pairs.add(pair)

# ---------------- report ----------------
bysev = {}
for sev, where, msg in problems:
    bysev.setdefault(sev, []).append((where, msg))
print(f"CATALOG: {len(control_ids)} controls, {len(domain_ids)} domains | MAPPINGS: {n_map} rows across {len(map_files)} file(s)")
for sev in ("ERR", "WARN", "REVIEW"):
    items = bysev.get(sev, [])
    print(f"\n===== {sev}: {len(items)} =====")
    for where, msg in items[:200]:
        print(f"  [{where}] {msg}")
n_err = len(bysev.get("ERR", []))
print(f"\nTOTAL: {len(problems)} ({n_err} ERR, {len(bysev.get('WARN',[]))} WARN, {len(bysev.get('REVIEW',[]))} REVIEW)")
sys.exit(1 if n_err else 0)
