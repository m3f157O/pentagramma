"""Validate that an InjectionHarness.exe run produced the expected Sysmon
signals for each technique. Mirrors scripts/harness_assertions.py; shared by
the REST API, the MCP server, and (indirectly) the PowerShell test runner.

Spec schema per technique (dict):
    log_pattern       regex with one capture group = target pid, from stdout
    -- Sysmon specs --
    event_id          expected Sysmon EID
    type_fragments    list of acceptable data.Type fragments, or None for any
    pid_field         event data field holding the TARGET pid (EID 10/8 use
                      TargetProcessId; EID 25/7 use ProcessId)
    -- behavioral specs --
    alert_event_type  behavioral alert event_type (e.g. ApitraceInjectionChain)
    alert_fragment    substring expected in data.Type, "{pid}" = target pid

EID 25 only fires for FILE-based techniques (herpaderping/ghosting). In-memory
hollowing is invisible to Sysmon's create-time image check -- its detector is
the apitrace injection chain, hence the behavioral specs.
"""

import re
from typing import Any, Dict, List, Optional


TECHNIQUE_SPECS = {
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
        # documented timing race: sometimes resolves as "replaced"
        "type_fragments": ["locked", "replaced"],
        "pid_field": "ProcessId",
    },
    # PLAN.md Phase 2 additions (mirror scripts/harness_assertions.py -- keep
    # in sync). type_fragments None = any alert of this EID for the target pid.
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
    # #13 thread-pool injection intentionally absent (PoolParty-only, no public API).
}


def _pid_from_stdout(stdout: str, pattern: "re.Pattern[str]") -> Optional[int]:
    for line in stdout.splitlines():
        match = pattern.search(line)
        if match:
            return int(match.group(1))
    return None


def validate_harness_alerts(execution_stdout: str, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    results: Dict[str, Any] = {"techniques": {}, "summary": {"passed": 0, "failed": 0, "missing_pids": 0}}
    for name, spec in TECHNIQUE_SPECS.items():
        pid = _pid_from_stdout(execution_stdout, spec["log_pattern"])

        entry: Dict[str, Any] = {"pid": pid}
        if pid is None:
            entry["status"] = "MISSING_PID"
            entry["error"] = "Could not extract target PID from harness stdout"
            results["summary"]["missing_pids"] += 1
            results["summary"]["failed"] += 1
            results["techniques"][name] = entry
            continue

        if "alert_event_type" in spec:
            fragment = spec["alert_fragment"].format(pid=pid).lower()
            matched = [
                a
                for a in alerts
                if a.get("event_type") == spec["alert_event_type"]
                and fragment in str((a.get("data") or {}).get("Type") or "").lower()
            ]
            entry["expected_alert"] = f"{spec['alert_event_type']} containing '{fragment}'"
            entry["matched_events"] = len(matched)
            if matched:
                entry["status"] = "PASS"
                results["summary"]["passed"] += 1
            else:
                entry["status"] = "FAIL"
                entry["error"] = f"No {spec['alert_event_type']} alert matching '{fragment}'"
                results["summary"]["failed"] += 1
            results["techniques"][name] = entry
            continue

        event_id = spec["event_id"]
        fragments = spec["type_fragments"]
        pid_field = spec["pid_field"]
        entry["expected_event_id"] = event_id
        entry["expected_type_fragments"] = fragments
        entry["pid_field"] = pid_field

        matched = [
            a
            for a in alerts
            if a.get("event_id") == event_id
            and str((a.get("data") or {}).get(pid_field, "")) == str(pid)
        ]
        entry["matched_events"] = len(matched)

        if not matched:
            entry["status"] = "FAIL"
            entry["error"] = f"No EID {event_id} alerts found for PID {pid} (field {pid_field})"
            results["summary"]["failed"] += 1
        elif fragments is not None and not any(
            frag in ((a.get("data") or {}).get("Type") or "").lower()
            for a in matched
            for frag in fragments
        ):
            entry["status"] = "FAIL"
            entry["error"] = f"EID {event_id} alerts found for PID {pid}, but none matched type in {fragments}"
            results["summary"]["failed"] += 1
        else:
            entry["status"] = "PASS"
            results["summary"]["passed"] += 1

        results["techniques"][name] = entry
    return results
