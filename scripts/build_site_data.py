#!/usr/bin/env python3
"""Build docs/_data.js for the KSA ECC-Map site — multi-framework.

Reads every catalog/*.json and its mappings/<key>/*.json, and emits one
ECCMAP object with a `frameworks` array the page renders. Run after any
mapping/catalog change (and after the audit gate passes)."""
import json, glob, os, collections

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ATTACK_DUMP = os.environ.get("ATTACK_DUMP",
    "C:/Users/IbrahimAbdlrazik/AppData/Local/Temp/attack_dump.json")

DUMP = json.load(open(ATTACK_DUMP, encoding="utf-8"))["techniques"]
CTID = json.load(open(os.path.join(REPO, "corroboration", "technique_to_nist80053.json"), encoding="utf-8"))

# framework key (catalog basename) -> Arabic framework title + short label
AR_TITLE = {
    "ecc":  "الضوابط الأساسية للأمن السيبراني",
    "cscc": "ضوابط الأمن السيبراني للأنظمة الحساسة",
}
SHORT = {"ecc": "ECC-1:2018", "cscc": "CSCC-1:2019"}

def build_framework(key, catalog_path):
    cat = json.load(open(catalog_path, encoding="utf-8"))
    controls = {c["control_id"]: c for c in cat["controls"]}
    domains = {d["domain_id"]: d for d in cat["domains"]}
    maps = []
    for mf in glob.glob(os.path.join(REPO, "mappings", key, "*.json")):
        maps += json.load(open(mf, encoding="utf-8"))

    by_control = collections.defaultdict(list)
    for m in maps:
        by_control[m["control_id"]].append(m)

    dom_total = collections.Counter(c["domain_id"] for c in cat["controls"])
    dom_cov = collections.Counter()
    for cid in by_control:
        dom_cov[controls[cid]["domain_id"]] += 1
    domain_summary = [{"id": d, "en": domains[d]["title_en"], "ar": domains[d]["title_ar"],
                       "total": dom_total[d], "covered": dom_cov[d]}
                      for d in sorted(dom_total, key=int)]

    def keyfn(cid): return [int(p) for p in cid.split("-")]
    control_view = []
    for cid in sorted(by_control, key=keyfn):
        c = controls[cid]
        rows = sorted(by_control[cid], key=lambda r: r["mapping_confidence"])
        control_view.append({
            "id": cid, "subdomain_id": c["subdomain_id"],
            "subdomain_en": c["subdomain_en"], "subdomain_ar": c["subdomain_ar"],
            "title_en": c["title_en"], "intent": c["intent"],
            "mappings": [{"t": m["attack_technique_id"], "tn": DUMP.get(m["attack_technique_id"], ""),
                          "ev": m["evidence_type"], "cf": m["mapping_confidence"],
                          "rr": m["risk_reduction_flag"], "packs": m.get("library_pack_refs", []),
                          "why": m["rationale"]} for m in rows]})

    by_tech = collections.defaultdict(lambda: {"controls": [], "ev": set(), "packs": set()})
    for m in maps:
        t = by_tech[m["attack_technique_id"]]
        t["controls"].append({"c": m["control_id"], "cf": m["mapping_confidence"]})
        t["ev"].add(m["evidence_type"])
        for p in m.get("library_pack_refs", []):
            t["packs"].add(p)
    tech_view = [{"id": tid, "name": DUMP.get(tid, ""), "ev": sorted(v["ev"]),
                  "packs": sorted(v["packs"]), "controls": v["controls"]}
                 for tid, v in sorted(by_tech.items())]

    conf = collections.Counter(m["mapping_confidence"] for m in maps)
    ev = collections.Counter(m["evidence_type"] for m in maps)
    nominal = sum(1 for m in maps if not m["risk_reduction_flag"])
    return {
        "key": key, "name": cat["framework"], "ar": AR_TITLE.get(key, ""),
        "short": SHORT.get(key, key.upper()), "official_source": cat["official_source"],
        "stats": {"mappings": len(maps), "controls_covered": len(by_control),
                  "controls_total": len(cat["controls"]), "high": conf["high"],
                  "medium": conf["medium"], "low": conf["low"], "detect": ev["detect"],
                  "hunt": ev["hunt"], "nominal": nominal},
        "domain_summary": domain_summary, "controls": control_view, "techniques": tech_view}

# order: ecc first, then cscc, then any others alphabetically
order = {"ecc": 0, "cscc": 1}
cats = sorted(glob.glob(os.path.join(REPO, "catalog", "*.json")),
              key=lambda p: order.get(os.path.splitext(os.path.basename(p))[0], 99))
frameworks = [build_framework(os.path.splitext(os.path.basename(p))[0], p) for p in cats]
data = {"ctid_edges": sum(len(v) for v in CTID.values()), "frameworks": frameworks}
out = os.path.join(REPO, "docs", "_data.js")
open(out, "w", encoding="utf-8").write("const ECCMAP = " + json.dumps(data, ensure_ascii=False) + ";")
print("wrote", out, "-", len(frameworks), "frameworks")
for f in frameworks:
    print(f"  {f['short']}: {f['stats']['mappings']} maps / {f['stats']['controls_covered']} of {f['stats']['controls_total']} controls")
