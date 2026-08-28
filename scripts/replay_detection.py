"""Offline detection replay.

Re-runs the FULL production detection assembly (orchestrator/reporting.py::
build_report -- heuristics + Sigma + YARA-on-dumps + Defender + PID-lineage
scoping + verdict) over a *saved report's* stored telemetry, WITHOUT booting the
VM or re-detonating the sample. Every analysis persists its raw events +
static analysis into reports/<id>.json, so the detection logic can be iterated
against a frozen corpus in seconds.

Two uses:
  1. Drift check -- did a rule/weight change move the verdict on historical runs?
       python scripts/replay_detection.py --all
  2. Programmatic -- the metrics + calibration harnesses import replay_report()
     to score a labeled corpus.

The replay uses the CURRENT ruleset/weights (a freshly built SigmaEngine +
today's detectors.py constants), which is the whole point: it answers "how would
today's detection logic score yesterday's captures?"
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.config import get_config  # noqa: E402
from orchestrator.reporting import ReportGenerator, compute_detection  # noqa: E402
from orchestrator.sigma_engine import SigmaEngine  # noqa: E402


def build_sigma_engine(cfg) -> Optional[SigmaEngine]:
    sigma_cfg = cfg.sigma
    if not sigma_cfg.get("enabled", True):
        return None
    custom_dir = cfg.paths.get("sigma_custom_rules_dir")
    return SigmaEngine(
        rules_dir=Path(cfg.paths.get("sigma_rules_dir", "sigma_rules")),
        min_level=sigma_cfg.get("min_level", "medium"),
        excluded_categories=sigma_cfg.get("excluded_categories", []),
        disabled_rule_ids=sigma_cfg.get("disabled_rule_ids", []),
        custom_rules_dirs=[Path(custom_dir)] if custom_dir else None,
    )


def replay_report(
    report: Dict[str, Any],
    reporter: ReportGenerator,
    sigma_engine: Optional[SigmaEngine],
) -> Dict[str, Any]:
    """Rebuild a report's detection from its stored inputs. Returns the freshly
    built report dict. Does NOT save it -- the caller decides what to do with
    the new verdict/alerts (compare, score, etc.)."""
    sample = report.get("sample", {}) or {}
    env = report.get("environment", {}) or {}
    return reporter.build_report(
        analysis_id=report.get("analysis_id", "replay"),
        sample_metadata=sample,
        vm_name=env.get("vm_name", "replay"),
        vm_ip=env.get("vm_ip"),
        runtime_seconds=env.get("runtime_seconds", 0.0),
        telemetry_events=report.get("events", []),
        static_analysis=report.get("static_analysis"),
        network_capture=report.get("network_capture"),
        screenshots=report.get("screenshots"),
        process_dumps=report.get("process_dumps"),
        dropped_files=report.get("dropped_files"),
        execution_info=report.get("execution_info"),
        status=report.get("status", "completed"),
        error=report.get("error"),
        sigma_engine=sigma_engine,
    )


def replay_detection_only(report: Dict[str, Any], sigma_engine: Optional[SigmaEngine]) -> Dict[str, Any]:
    """Fast path: recompute only alerts + verdict from a saved report's stored
    telemetry, skipping build_report's pcap/IOC parse, process tree and
    coverage matrix (none affect the verdict). Returns the compute_detection
    dict {alerts, verdict, lineage, ...}. Used by the metrics + calibration
    harnesses, which replay the whole corpus repeatedly and only need the
    verdict/alerts."""
    return compute_detection(
        report.get("events", []),
        static_analysis=report.get("static_analysis"),
        process_dumps=report.get("process_dumps"),
        dropped_files=report.get("dropped_files"),
        execution_info=report.get("execution_info"),
        sigma_engine=sigma_engine,
    )


def load_report_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def iter_report_paths(reports_dir: Path, ids: Optional[List[str]]) -> List[Path]:
    if ids:
        return [reports_dir / f"{rid}.json" for rid in ids]
    return sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def _verdict_tuple(report: Dict[str, Any]) -> tuple:
    v = report.get("verdict", {}) or {}
    return v.get("level"), v.get("score")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ids", nargs="*", help="Report IDs to replay (default: --all)")
    parser.add_argument("--all", action="store_true", help="Replay every report in reports/")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    parser.add_argument("--changed-only", action="store_true", help="Only show reports whose verdict changed")
    args = parser.parse_args()

    if not args.ids and not args.all:
        parser.error("give report IDs or --all")

    cfg = get_config()
    reporter = ReportGenerator(cfg)
    sigma_engine = build_sigma_engine(cfg)
    reports_dir = Path(cfg.paths["reports_dir"])

    rows: List[Dict[str, Any]] = []
    for path in iter_report_paths(reports_dir, args.ids or None):
        report = load_report_file(path)
        if report is None:
            rows.append({"id": path.stem, "error": "unreadable/missing"})
            continue
        old_level, old_score = _verdict_tuple(report)
        try:
            new = replay_report(report, reporter, sigma_engine)
            new_level, new_score = _verdict_tuple(new)
            rows.append({
                "id": report.get("analysis_id", path.stem),
                "filename": (report.get("sample", {}) or {}).get("filename"),
                "old_level": old_level, "old_score": old_score,
                "new_level": new_level, "new_score": new_score,
                "changed": (old_level, old_score) != (new_level, new_score),
            })
        except Exception as exc:
            rows.append({"id": report.get("analysis_id", path.stem), "error": str(exc)})

    if args.changed_only:
        rows = [r for r in rows if r.get("changed") or r.get("error")]

    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return

    changed = sum(1 for r in rows if r.get("changed"))
    errors = sum(1 for r in rows if r.get("error"))
    print(f"{'ID':38} {'filename':28} {'old':>22} {'new':>22}")
    print("-" * 116)
    for r in rows:
        if r.get("error"):
            print(f"{r['id']:38} {'':28} ERROR: {r['error']}")
            continue
        mark = " *" if r["changed"] else ""
        old = f"{r['old_level']}/{r['old_score']}"
        new = f"{r['new_level']}/{r['new_score']}"
        print(f"{r['id']:38} {str(r.get('filename'))[:28]:28} {old:>22} {new:>22}{mark}")
    print("-" * 116)
    print(f"{len(rows)} reports | {changed} verdict changed | {errors} errors")


if __name__ == "__main__":
    main()
