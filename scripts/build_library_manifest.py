#!/usr/bin/env python3
"""
Maintainer tool: build vendor/library_manifest.json from the MENA Detection
Library, so the audit gate and the site are self-contained (no external live
directory needed at audit/build time).

Run this ONLY when the upstream Detection Library changes, then commit the
regenerated vendor/library_manifest.json. Requires the Detection Library on
disk (env MENA_LIBRARY or the sibling default).

Manifest shape:
{
  "source": "DashTX707/mena-detection-library",
  "generated_from": "<abs path used>",
  "actors": {
    "<slug>": {
      "detections": ["T1003.001_slug-….yml", ...],
      "hunts": ["HUNT-01_….md", ...],
      "detect_by_tech": {"T1003.001": ["T1003.001_slug-….yml"], ...},
      "hunt_by_tech":   {"T1210": ["HUNT-14_….md"], ...}
    }
  }
}
"""
import json, os, re, glob

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LIBRARY = os.environ.get("MENA_LIBRARY",
    os.path.normpath(os.path.join(REPO, "..", "mena-detection-library")))

TAG_RE = re.compile(r"attack\.t(\d{4}(?:\.\d{3})?)", re.I)       # attack.t1003.001
CITE_RE = re.compile(r"\bT(\d{4}(?:\.\d{3})?)\b")                # T1210 in hunt md

def main():
    if not os.path.isdir(LIBRARY):
        raise SystemExit(f"Detection Library not found at {LIBRARY} (set MENA_LIBRARY)")
    actors = {}
    for cti in sorted(glob.glob(os.path.join(LIBRARY, "actors", "*", "intel", "cti-pipeline.json"))):
        slug = os.path.basename(os.path.dirname(os.path.dirname(cti)))
        d = os.path.join(LIBRARY, "actors", slug)
        dets = sorted(os.path.basename(p) for p in glob.glob(os.path.join(d, "detections", "*.yml")))
        hunts = sorted(os.path.basename(p) for p in glob.glob(os.path.join(d, "hunts", "*.md")))
        detbt, huntbt = {}, {}
        for fn in dets:
            txt = open(os.path.join(d, "detections", fn), encoding="utf-8").read()
            for m in set(TAG_RE.findall(txt)):
                tid = "T" + m.upper()
                detbt.setdefault(tid, []).append(fn)
        for fn in hunts:
            txt = open(os.path.join(d, "hunts", fn), encoding="utf-8").read()
            # only the ATT&CK block cites technique ids; scan whole file (ids are distinctive)
            for m in set(CITE_RE.findall(txt)):
                tid = "T" + m
                huntbt.setdefault(tid, []).append(fn)
        actors[slug] = {"detections": dets, "hunts": hunts,
                        "detect_by_tech": {k: sorted(v) for k, v in sorted(detbt.items())},
                        "hunt_by_tech": {k: sorted(v) for k, v in sorted(huntbt.items())}}
    out = {"source": "DashTX707/mena-detection-library",
           "generated_from": LIBRARY, "actor_count": len(actors), "actors": actors}
    dst = os.path.join(REPO, "vendor", "library_manifest.json")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    json.dump(out, open(dst, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    ndet = sum(len(a["detections"]) for a in actors.values())
    nhunt = sum(len(a["hunts"]) for a in actors.values())
    print(f"wrote {dst}: {len(actors)} actors, {ndet} detections, {nhunt} hunts")

if __name__ == "__main__":
    main()
