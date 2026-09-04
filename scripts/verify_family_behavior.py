"""Family-behavior verification: score each detonated corpus sample against
three independent ground-truth layers.

Per sample (matched to reports by sha256):
  1. VERDICT  -- real malware should land >= suspicious (ideally malicious).
  2. YARA     -- does any YARA rule match (static/dump/dropped) name the
     expected family? (classification ground truth from MalwareBazaar)
  3. ATT&CK   -- overlap between the report's MITRE techniques and the
     family's documented techniques (orchestrator/data/family_ttps.json,
     extracted from MITRE ATT&CK). A short detonation shows a subset of a
     family's full repertoire, so the bar is >= MIN_TECHNIQUE_OVERLAP.
  4. (bonus) ThreatFox C2 recall where IOCs exist (see verify_c2_recall.py).

    .venv/Scripts/python.exe scripts/verify_family_behavior.py [--json out/family_verify.json]
"""

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

INCOMING = PROJECT_ROOT / "samples" / "incoming" / "malwarebazaar"
REPORTS = PROJECT_ROOT / "reports"
TTPS = PROJECT_ROOT / "orchestrator" / "data" / "family_ttps.json"

MIN_TECHNIQUE_OVERLAP = 2
FAMILY_YARA_TOKENS = {  # family -> tokens to look for in rule names
    "emotet": ["emotet", "heodo"],
    "qakbot": ["qakbot", "qbot", "quakbot"],
    "agenttesla": ["agenttesla", "agent_tesla"],
    "redline": ["redline"],
    "asyncrat": ["asyncrat"],
    "remcos": ["remcos"],
}


def report_techniques(report: dict) -> set:
    techs = set()
    for entry in (report.get("mitre_coverage") or {}).values():
        for t in (entry.get("techniques") if isinstance(entry, dict) else []) or []:
            tid = t.get("technique_id") if isinstance(t, dict) else str(t)
            if tid:
                techs.add(tid)
    return techs


def report_yara_rules(report: dict) -> set:
    rules = set()
    for m in (report.get("static_analysis") or {}).get("yara") or []:
        if "rule" in m:
            rules.add(m["rule"].lower())
    for section in ("process_dumps", "dropped_files"):
        for item in (report.get(section) or {}).get("items") or []:
            for m in item.get("yara_matches") or []:
                if "rule" in m:
                    rules.add(m["rule"].lower())
    return rules


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", default=str(PROJECT_ROOT / "out" / "family_verify.json"))
    args = ap.parse_args()

    ttps = json.loads(TTPS.read_text(encoding="utf-8"))

    manifest = {}
    for mf in sorted(INCOMING.glob("*/manifest.jsonl")):
        for line in mf.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("sha256"):
                    manifest[row["sha256"].lower()] = row.get("family") or mf.parent.name

    # latest report per sha256
    report_by_sha = {}
    for rp in sorted(REPORTS.glob("*.json")):
        if rp.stem.endswith(".summary"):
            continue
        try:
            head = json.loads(rp.read_text(encoding="utf-8", errors="replace")[:200000])
        except Exception:
            continue
        sha = (((head.get("sample") or {}).get("hashes") or {}).get("sha256") or "").lower()
        ts = head.get("timestamp") or ""
        if sha in manifest and (sha not in report_by_sha or ts > report_by_sha[sha][0]):
            report_by_sha[sha] = (ts, rp)

    rows = []
    for sha, (ts, rp) in sorted(report_by_sha.items()):
        family = manifest[sha]
        report = json.loads(rp.read_text(encoding="utf-8", errors="replace"))
        verdict = (report.get("verdict") or {})
        yara_rules = report_yara_rules(report)
        tokens = FAMILY_YARA_TOKENS.get(family, [family])
        yara_family_hits = sorted(r for r in yara_rules if any(t in r for t in tokens))
        techs = report_techniques(report)
        expected = set((ttps.get(family) or {}).get("techniques") or [])
        overlap = sorted(techs & expected)
        # sub-technique parents also count (T1055.012 observed covers T1055 expected)
        parent_overlap = sorted({t.split(".")[0] for t in techs} & {t.split(".")[0] for t in expected})
        rows.append({
            "sha256": sha, "family": family, "report_id": rp.stem,
            "verdict_level": verdict.get("level"), "verdict_score": verdict.get("score"),
            "yara_family_match": bool(yara_family_hits), "yara_family_rules": yara_family_hits[:3],
            "ttp_overlap": len(overlap), "ttp_parent_overlap": len(parent_overlap),
            "ttp_observed_expected": overlap[:10],
            "behavior_ok": len(parent_overlap) >= MIN_TECHNIQUE_OVERLAP,
        })

    print(f"{'family':<12} {'n':>3} {'>=susp':>6} {'malic.':>6} {'yara-fam':>8} {'ttp>=2':>7}")
    print("-" * 48)
    per_family = {}
    for r in rows:
        a = per_family.setdefault(r["family"], {"n": 0, "susp": 0, "mal": 0, "yara": 0, "ttp": 0})
        a["n"] += 1
        a["susp"] += r["verdict_level"] in ("suspicious", "malicious")
        a["mal"] += r["verdict_level"] == "malicious"
        a["yara"] += r["yara_family_match"]
        a["ttp"] += r["behavior_ok"]
    for fam in sorted(per_family):
        a = per_family[fam]
        print(f"{fam:<12} {a['n']:>3} {a['susp']:>6} {a['mal']:>6} {a['yara']:>8} {a['ttp']:>7}")
    tot = {"n": 0, "susp": 0, "mal": 0, "yara": 0, "ttp": 0}
    for a in per_family.values():
        for k in tot:
            tot[k] += a[k]
    print("-" * 48)
    print(f"{'TOTAL':<12} {tot['n']:>3} {tot['susp']:>6} {tot['mal']:>6} {tot['yara']:>8} {tot['ttp']:>7}")

    # worst offenders: real malware that scored clean
    bad = [r for r in rows if r["verdict_level"] not in ("suspicious", "malicious")]
    if bad:
        print(f"\n!! {len(bad)} samples scored below suspicious:")
        for r in bad[:15]:
            print(f"   {r['family']:<12} {r['sha256'][:16]} verdict={r['verdict_level']}/{r['verdict_score']} report={r['report_id'][:8]}")

    out_path = Path(args.json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"min_technique_overlap": MIN_TECHNIQUE_OVERLAP, "samples": rows}, indent=1), encoding="utf-8")
    print(f"\n{len(rows)} verified -> {out_path}")


if __name__ == "__main__":
    main()
