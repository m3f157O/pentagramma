#!/usr/bin/env python3
"""Validate that the InjectionHarness produced the expected Sysmon signals.

Usage:
    python scripts/harness_assertions.py <report-json-path>

Exit codes:
    0 - all assertions passed
    1 - one or more assertions failed
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


# type_fragments None = any event of this EID for the pid counts; a list
# means at least one fragment must appear in data.Type. pid_field selects
# which event field carries the technique's TARGET pid (EID 10/8 attribute
# the target under TargetProcessId; EID 25/7 under ProcessId).
EXPECTED_TECHNIQUES = {
    "hollowing": {
        "log_pattern": re.compile(r"Hollowing target pid=(\d+)"),
        "alert_event_type": "ApitraceInjectionChain",
        "alert_fragment": "hollowing into {pid}",
    },
    "pe_replacement": {
        "log_pattern": re.compile(r"PE-replacement target pid=(\d+)"),
        "alert_event_type": "ApitraceInjectionChain",
        "alert_fragment": "hollowing into {pid}",
    },
    "herpaderping": {
        "log_pattern": re.compile(r"Herpaderping target pid=(\d+)"),
        "event_id": 25,
        "type_fragments": ["replaced"],
        "pid_field": "ProcessId",
    },
    "ghosting": {
        "log_pattern": re.compile(r"Ghosting target pid=(\d+)"),
        "event_id": 25,
        "type_fragments": ["locked", "replaced"],  # documented timing race
        "pid_field": "ProcessId",
    },
    # PLAN.md Phase 2 additions (mirror orchestrator/harness_validation.py).
    "atombombing": {
        "log_pattern": re.compile(r"AtomBombing target pid=(\d+)"),
        "event_id": 10,
        "type_fragments": None,
        "pid_field": "TargetProcessId",
    },
    "module_overloading": {
        "log_pattern": re.compile(r"ModuleOverloading target pid=(\d+)"),
        "event_id": 7,
        "type_fragments": None,
        "pid_field": "ProcessId",
    },
    "setwindowshookex": {
        "log_pattern": re.compile(r"SetWindowsHookEx target pid=(\d+)"),
        "event_id": 7,
        "type_fragments": None,
        "pid_field": "ProcessId",
    },
    "apc_ex": {
        "log_pattern": re.compile(r"ApcEx target pid=(\d+)"),
        "event_id": 10,
        "type_fragments": None,
        "pid_field": "TargetProcessId",
    },
    "mapview": {
        "log_pattern": re.compile(r"MapView target pid=(\d+)"),
        "event_id": 8,
        "type_fragments": None,
        "pid_field": "TargetProcessId",
    },
    # NOTE: #13 thread-pool injection intentionally absent -- needs PoolParty-
    # style undocumented primitives; the harness logs an explicit SKIPPED line.
}


def _pid_from_stdout(stdout: str, pattern: re.Pattern[str]) -> Optional[int]:
    for line in stdout.splitlines():
        match = pattern.search(line)
        if match:
            return int(match.group(1))
    return None


def _events_for_pid(events: List[Dict[str, Any]], pid: int, event_id: int, pid_field: str = "ProcessId") -> List[Dict[str, Any]]:
    matched: List[Dict[str, Any]] = []
    for event in events:
        if event.get("event_id") != event_id:
            continue
        data = event.get("data") or {}
        try:
            event_pid = int(data.get(pid_field, -1))
        except (TypeError, ValueError):
            continue
        if event_pid == pid:
            matched.append(event)
    return matched


def _event_type_text(event: Dict[str, Any]) -> str:
    data = event.get("data") or {}
    return (data.get("Type") or "").lower()


def validate_report(report_path: Path) -> Dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    stdout: str = (report.get("execution_info") or {}).get("Stdout", "")
    events: List[Dict[str, Any]] = report.get("events", [])
    alerts: List[Dict[str, Any]] = report.get("alerts", [])

    results: Dict[str, Any] = {
        "report_path": str(report_path),
        "analysis_id": report.get("analysis_id"),
        "techniques": {},
        "summary": {"passed": 0, "failed": 0, "missing_pids": 0},
    }

    for name, spec in EXPECTED_TECHNIQUES.items():
        pid = _pid_from_stdout(stdout, spec["log_pattern"])
        technique_result: Dict[str, Any] = {"pid": pid}
        if "alert_event_type" in spec:
            technique_result["expected_alert"] = spec["alert_event_type"]
        else:
            technique_result["expected_event_id"] = spec["event_id"]
            technique_result["expected_type_fragments"] = spec["type_fragments"]
            technique_result["pid_field"] = spec["pid_field"]

        if pid is None:
            technique_result["status"] = "MISSING_PID"
            technique_result["error"] = "Could not extract target PID from harness stdout"
            results["summary"]["missing_pids"] += 1
            results["summary"]["failed"] += 1
            results["techniques"][name] = technique_result
            continue

        if "alert_event_type" in spec:
            # Behavioral assertion: the technique's expected detector is the
            # apitrace injection chain (in-memory hollowing is invisible to
            # Sysmon's create-time image check).
            fragment = spec["alert_fragment"].format(pid=pid).lower()
            matched_alerts = [
                a
                for a in alerts
                if a.get("event_type") == spec["alert_event_type"]
                and fragment in str((a.get("data") or {}).get("Type") or "").lower()
            ]
            technique_result["expected_alert"] = f"{spec['alert_event_type']} containing '{fragment}'"
            technique_result["matched_events"] = len(matched_alerts)
            if matched_alerts:
                technique_result["status"] = "PASS"
                results["summary"]["passed"] += 1
            else:
                technique_result["status"] = "FAIL"
                technique_result["error"] = f"No {spec['alert_event_type']} alert matching '{fragment}'"
                results["summary"]["failed"] += 1
            results["techniques"][name] = technique_result
            continue

        matched = _events_for_pid(events, pid, spec["event_id"], spec["pid_field"])
        technique_result["matched_events"] = len(matched)

        if not matched:
            technique_result["status"] = "FAIL"
            technique_result["error"] = f"No EID {spec['event_id']} events found for PID {pid} (field {spec['pid_field']})"
            results["summary"]["failed"] += 1
        elif spec["type_fragments"] is not None and not any(
            frag in _event_type_text(ev) for ev in matched for frag in spec["type_fragments"]
        ):
            technique_result["status"] = "FAIL"
            types = [_event_type_text(ev) for ev in matched]
            technique_result["error"] = (
                f"EID {spec['event_id']} events found for PID {pid}, "
                f"but none contained any of {spec['type_fragments']} (got {types})"
            )
            results["summary"]["failed"] += 1
        else:
            technique_result["status"] = "PASS"
            results["summary"]["passed"] += 1

        results["techniques"][name] = technique_result

    return results


def build_baselines(report: Dict[str, Any]) -> Dict[str, Any]:
    """Return event-count baselines from a report."""
    baselines: Dict[str, Any] = {
        "total_events": report.get("summary", {}).get("total_events", 0),
        "alert_count": report.get("summary", {}).get("alert_count", 0),
        "event_counts": report.get("summary", {}).get("event_counts", {}),
    }
    return baselines


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <report-json-path>", file=sys.stderr)
        return 2

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print(f"Report not found: {report_path}", file=sys.stderr)
        return 2

    results = validate_report(report_path)
    print(json.dumps(results, indent=2))

    # Optionally emit baselines next to the report if --save-baseline is passed.
    if "--save-baseline" in sys.argv:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        baselines = build_baselines(report)
        baseline_path = Path("tests/harness_baselines.json")
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(baselines, indent=2) + "\n", encoding="utf-8")
        print(f"[+] Baselines written to {baseline_path}")

    summary = results["summary"]
    if summary["failed"] or summary["missing_pids"]:
        print(
            f"\n[-] Assertions failed: {summary['failed']} missing PIDs: {summary['missing_pids']} passed: {summary['passed']}"
        )
        return 1

    print(f"\n[+] All assertions passed ({summary['passed']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
