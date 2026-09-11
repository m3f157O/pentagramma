"""Atomic Red Team recall audit.

Compares each detonated ART sample's report against its manifest entry
(samples/atomic_redteam/manifest.json, produced by build_atomic_corpus.py):

  * verdict reached at least the manifest's expected band (default:
    suspicious -- these are attack-shaped, the sandbox stays aggressive);
  * the expected ATT&CK technique (or a parent of it) appears in the
    report's MITRE coverage -- the technique-level recall question ART is
    for.

Matches reports to samples by filename (every run of a sample matches;
latest run wins). Prints a per-atomic table plus a per-technique summary,
and appends misses to docs/detection-gap-tracker.md in the established
format when --gaps is given.

    .venv/Scripts/python.exe scripts/verify_atomic_coverage.py [--gaps]
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.config import get_config  # noqa: E402
from scripts.detection_metrics import _report_head_identity  # noqa: E402

MANIFEST = PROJECT_ROOT / "samples" / "atomic_redteam" / "manifest.json"
BAND_ORDER = {"clean": 0, "suspicious": 1, "malicious": 2}


def latest_reports_by_filename(reports_dir: Path):
    """filename -> (timestamp, path) for the latest run of each sample."""
    best = {}
    for p in reports_dir.glob("*.json"):
        if p.name.endswith(".summary.json"):
            continue
        ident = _report_head_identity(p)
        if not ident:
            continue
        fn, ts = ident.get("filename"), ident.get("timestamp") or ""
        if fn and (fn not in best or ts > best[fn][0]):
            best[fn] = (ts, p)
    return best


def technique_covered(report: dict, technique: str) -> bool:
    """True if the expected technique (exact id or a parent/child of it)
    appears in the report's mitre_coverage."""
    cov = report.get("mitre_coverage") or {}
    seen = set()
    for entry in cov.get("techniques") or cov.get("coverage") or []:
        tid = (entry.get("technique_id") or entry.get("id") or "") if isinstance(entry, dict) else str(entry)
        if tid:
            seen.add(tid)
    for tid in seen:
        # exact, parent (T1055 covers T1055.012), or child match
        if tid == technique or technique.startswith(tid + ".") or tid.startswith(technique + "."):
            return True
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gaps", action="store_true", help="print gap-tracker-ready markdown for misses")
    args = ap.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cfg = get_config()
    reports_dir = Path(cfg.paths["reports_dir"])
    latest = latest_reports_by_filename(reports_dir)

    rows = []
    tech_stats = defaultdict(lambda: {"total": 0, "verdict_ok": 0, "ttp_hit": 0})
    for item in manifest:
        fn = item["file"]
        tech = item["technique"]
        tech_stats[tech]["total"] += 1
        if fn not in latest:
            rows.append((fn, tech, item["name"], "NO-REPORT", "-", False))
            continue
        _, path = latest[fn]
        report = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        v = report.get("verdict") or {}
        level, score = v.get("level"), v.get("score")
        expected = item.get("expected_verdict_min") or "suspicious"
        verdict_ok = BAND_ORDER.get(level or "clean", 0) >= BAND_ORDER[expected]
        ttp_hit = technique_covered(report, tech)
        tech_stats[tech]["verdict_ok"] += verdict_ok
        tech_stats[tech]["ttp_hit"] += ttp_hit
        rows.append((fn, tech, item["name"], f"{level}/{score}", "yes" if verdict_ok else "NO", ttp_hit))
        del report

    print(f"\n{'sample':<52} {'technique':<11} {'verdict':<14} {'band-ok':<8} {'ttp'}")
    print("-" * 100)
    for fn, tech, name, verdict, ok, ttp in rows:
        print(f"{fn:<52} {tech:<11} {verdict:<14} {ok:<8} {'yes' if ttp else 'MISS'}")

    print(f"\n{'technique':<11} {'atomics':>7} {'verdict>=exp':>12} {'ttp-covered':>12}")
    print("-" * 46)
    for tech in sorted(tech_stats):
        st = tech_stats[tech]
        print(f"{tech:<11} {st['total']:>7} {st['verdict_ok']:>12} {st['ttp_hit']:>12}")
    total = len(rows)
    vok = sum(1 for r in rows if r[4] in ("yes",))
    thit = sum(1 for r in rows if r[5] is True)
    norep = sum(1 for r in rows if r[3] == "NO-REPORT")
    print(f"\nTOTAL: {total} atomics | verdict>=expected {vok} | ttp-covered {thit} | no-report {norep}")

    if args.gaps:
        misses = [r for r in rows if r[4] != "yes" or r[5] is not True]
        if misses:
            print("\n## Atomic Red Team gaps (verify_atomic_coverage.py)\n")
            print("| atomic | technique | verdict | issue |")
            print("|---|---|---|---|")
            for fn, tech, name, verdict, ok, ttp in misses:
                issue = []
                if ok != "yes":
                    issue.append("verdict below expected band")
                if ttp is not True:
                    issue.append("expected technique not in MITRE coverage")
                print(f"| {name} ({fn}) | {tech} | {verdict} | {'; '.join(issue)} |")


if __name__ == "__main__":
    main()
