"""Builds the apitrace<->Sysmon coverage table (WS-B workstream).

Three inputs, two outputs:
  - agent/windows/monitor_src/monitor/monitor.cpp  (kHooks[] hook table)
  - agent/windows/sysmonconfig.xml                 (which Sysmon EIDs are on)
  - orchestrator/data/coverage_map.yaml            (curated semantic mapping)

Outputs:
  - docs/coverage-table.md          -- human matrix (API x Sysmon coverage)
  - orchestrator/data/coverage_map.json -- machine form consumed by the
    runtime blind-spot detectors in orchestrator/behavioral_signatures.py

The script VALIDATES the curated YAML against both ground truths: every hook
in kHooks[] must have an entry, every entry must name a real hook, and every
counterpart EID must actually be enabled in the deployed sysmonconfig.xml.
tests/test_coverage_map.py re-runs the same checks as a drift guard.

Usage:
    .venv\\Scripts\\python.exe scripts\\build_coverage_table.py
"""

import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MONITOR_CPP = PROJECT_ROOT / "agent" / "windows" / "monitor_src" / "monitor" / "monitor.cpp"
SYSMONCONFIG = PROJECT_ROOT / "agent" / "windows" / "sysmonconfig.xml"
COVERAGE_YAML = PROJECT_ROOT / "orchestrator" / "data" / "coverage_map.yaml"
COVERAGE_JSON = PROJECT_ROOT / "orchestrator" / "data" / "coverage_map.json"
COVERAGE_MD = PROJECT_ROOT / "docs" / "coverage-table.md"

# Sysmon config filter tag -> event ID(s). Several EIDs share one filter tag
# (RegistryEvent covers 12/13/14, PipeEvent 17/18, WmiEvent 19-21) -- see the
# CORRECTED comments in sysmonconfig.xml.
_TAG_TO_EIDS = {
    "ProcessCreate": [1],
    "FileCreateTime": [2],
    "NetworkConnect": [3],
    "ProcessTerminate": [5],
    "DriverLoad": [6],
    "ImageLoad": [7],
    "CreateRemoteThread": [8],
    "RawAccessRead": [9],
    "ProcessAccess": [10],
    "FileCreate": [11],
    "RegistryEvent": [12, 13, 14],
    "FileCreateStreamHash": [15],
    "PipeEvent": [17, 18],
    "WmiEvent": [19, 20, 21],
    "DnsQuery": [22],
    "FileDelete": [23],
    "ClipboardChange": [24],
    "ProcessTampering": [25],
    "FileDeleteDetected": [26],
}

# One kHooks[] row: { "module", nullptr|"alt", "proc", (LPVOID)&h_..., ... }
_HOOK_ROW_RE = re.compile(
    r'\{\s*"(?P<module>[^"]+)"\s*,\s*(?:nullptr|"[^"]+")\s*,\s*"(?P<proc>[^"]+)"\s*,'
)


def parse_hooks(monitor_cpp: Path) -> List[Dict[str, str]]:
    """Extract (module, proc) pairs from the kHooks[] table in monitor.cpp."""
    text = monitor_cpp.read_text(encoding="utf-8")
    start = text.index("kHooks[]")
    end = text.index("};", start)
    hooks = []
    for match in _HOOK_ROW_RE.finditer(text[start:end]):
        hooks.append({"hook_module": match.group("module"), "api": match.group("proc")})
    return hooks


def parse_enabled_eids(sysmonconfig: Path) -> Set[int]:
    """EIDs actually collected by the deployed Sysmon config."""
    tree = ET.parse(str(sysmonconfig))
    enabled: Set[int] = set()
    for rule_group in tree.getroot().iter("RuleGroup"):
        for child in rule_group:
            for eid in _TAG_TO_EIDS.get(child.tag, []):
                enabled.add(eid)
    return enabled


def load_coverage_map(coverage_yaml: Path) -> List[Dict[str, Any]]:
    entries = yaml.safe_load(coverage_yaml.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError(f"{coverage_yaml} must hold a list of entries")
    return entries


def validate(hooks: List[Dict[str, str]], entries: List[Dict[str, Any]], enabled_eids: Set[int]) -> List[str]:
    """Cross-check the curated map against both ground truths. Returns errors."""
    errors: List[str] = []
    hook_apis = [h["api"] for h in hooks]
    entry_apis = [e.get("api") for e in entries]

    for api in hook_apis:
        if api not in entry_apis:
            errors.append(f"hook {api} has no coverage_map.yaml entry")
    for api in entry_apis:
        if api not in hook_apis:
            errors.append(f"coverage_map.yaml entry {api} names no real hook")

    module_by_api = {h["api"]: h["hook_module"] for h in hooks}
    for entry in entries:
        api = entry.get("api")
        if api in module_by_api and entry.get("hook_module") != module_by_api[api]:
            errors.append(
                f"{api}: hook_module {entry.get('hook_module')} != kHooks {module_by_api[api]}"
            )
        coverage = entry.get("coverage")
        if coverage not in ("both", "hook_only"):
            errors.append(f"{api}: coverage must be both|hook_only, got {coverage!r}")
        counterparts = entry.get("sysmon_counterparts") or []
        if coverage == "both" and not counterparts:
            errors.append(f"{api}: coverage=both but no sysmon_counterparts")
        if coverage == "hook_only" and counterparts:
            errors.append(f"{api}: coverage=hook_only but has sysmon_counterparts")
        for eid in counterparts:
            if eid not in enabled_eids:
                errors.append(f"{api}: counterpart EID {eid} is not enabled in sysmonconfig.xml")
    return errors


def build_machine_map(entries: List[Dict[str, Any]], enabled_eids: Set[int]) -> Dict[str, Any]:
    """Machine form consumed by the blind-spot detectors."""
    hooks = []
    eid_to_apis: Dict[str, List[str]] = {}
    for entry in entries:
        hooks.append({
            "api": entry["api"],
            "hook_module": entry["hook_module"],
            "category": entry["category"],
            "coverage": entry["coverage"],
            "sysmon_counterparts": list(entry.get("sysmon_counterparts") or []),
            "join_artifact": entry.get("join_artifact"),
            "blind_spot": list(entry.get("blind_spot") or []),
        })
        if entry["coverage"] == "both":
            for eid in entry.get("sysmon_counterparts") or []:
                eid_to_apis.setdefault(str(eid), []).append(entry["api"])
    counterpart_eids = {int(eid) for eid in eid_to_apis}
    return {
        "generated_by": "scripts/build_coverage_table.py",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hooks": hooks,
        "eid_to_apis": {eid: eid_to_apis[eid] for eid in sorted(eid_to_apis, key=int)},
        "sysmon_only_eids": sorted(enabled_eids - counterpart_eids),
    }


def render_markdown(machine: Dict[str, Any]) -> str:
    lines = [
        "# Apitrace <-> Sysmon coverage table",
        "",
        f"Generated by `scripts/build_coverage_table.py` from `orchestrator/data/coverage_map.yaml` "
        f"on {machine['generated_at']} -- do not edit by hand.",
        "",
        "| API | Module | Category | Sysmon EIDs | Coverage | Blind spots |",
        "|-----|--------|----------|-------------|----------|-------------|",
    ]
    for hook in machine["hooks"]:
        eids = ", ".join(str(e) for e in hook["sysmon_counterparts"]) or "-"
        blind = ", ".join(hook["blind_spot"]) or "-"
        lines.append(
            f"| {hook['api']} | {hook['hook_module']} | {hook['category']} "
            f"| {eids} | {hook['coverage']} | {blind} |"
        )
    lines += [
        "",
        "## Sysmon-only EIDs (no hook counterpart)",
        "",
        "These Sysmon events have no apitrace hook watching the same behavior:",
        "",
        "- " + ", ".join(str(e) for e in machine["sysmon_only_eids"]),
        "",
        "## Gap class (visible to neither source)",
        "",
        "- **direct syscalls** with a spoofed or freshly remapped ntdll copy",
        "- **KnownDlls remapping** (a remapped clean ntdll defeats hook placement)",
        "- **in-process memory writes via plain memcpy** (no API call at all)",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    hooks = parse_hooks(MONITOR_CPP)
    enabled_eids = parse_enabled_eids(SYSMONCONFIG)
    entries = load_coverage_map(COVERAGE_YAML)

    errors = validate(hooks, entries, enabled_eids)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    machine = build_machine_map(entries, enabled_eids)
    COVERAGE_JSON.write_text(json.dumps(machine, indent=2) + "\n", encoding="utf-8")
    COVERAGE_MD.write_text(render_markdown(machine), encoding="utf-8")
    print(f"{len(hooks)} hooks, {len(machine['eid_to_apis'])} counterpart EIDs, "
          f"{len(machine['sysmon_only_eids'])} sysmon-only EIDs")
    print(f"wrote {COVERAGE_JSON.relative_to(PROJECT_ROOT)} and {COVERAGE_MD.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
