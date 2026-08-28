"""Drift guard for the apitrace<->Sysmon coverage map (WS-B).

Re-runs the same parsing/validation as scripts/build_coverage_table.py so the
curated orchestrator/data/coverage_map.yaml can't silently drift away from
kHooks[] (monitor.cpp) or the enabled EIDs (sysmonconfig.xml), and the checked
in coverage_map.json can't drift away from the YAML.

Plain asserts, no pytest: .venv\\Scripts\\python.exe tests\\test_coverage_map.py
"""

import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

_SPEC = importlib.util.spec_from_file_location(
    "build_coverage_table", PROJECT_ROOT / "scripts" / "build_coverage_table.py"
)
bct = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bct)


def _inputs():
    hooks = bct.parse_hooks(bct.MONITOR_CPP)
    enabled_eids = bct.parse_enabled_eids(bct.SYSMONCONFIG)
    entries = bct.load_coverage_map(bct.COVERAGE_YAML)
    return hooks, enabled_eids, entries


def test_every_hook_has_yaml_entry():
    hooks, _, entries = _inputs()
    entry_apis = {e["api"] for e in entries}
    missing = [h["api"] for h in hooks if h["api"] not in entry_apis]
    assert not missing, f"hooks without coverage_map.yaml entry: {missing}"


def test_every_yaml_entry_names_a_real_hook():
    hooks, _, entries = _inputs()
    hook_apis = {h["api"] for h in hooks}
    extra = [e["api"] for e in entries if e["api"] not in hook_apis]
    assert not extra, f"coverage_map.yaml entries naming no real hook: {extra}"


def test_every_counterpart_eid_is_enabled():
    _, enabled_eids, entries = _inputs()
    bad = [
        (e["api"], eid)
        for e in entries
        for eid in (e.get("sysmon_counterparts") or [])
        if eid not in enabled_eids
    ]
    assert not bad, f"counterpart EIDs not enabled in sysmonconfig.xml: {bad}"


def test_validate_reports_no_errors():
    hooks, enabled_eids, entries = _inputs()
    errors = bct.validate(hooks, entries, enabled_eids)
    assert not errors, f"coverage map validation errors: {errors}"


def test_json_in_sync_with_yaml():
    """coverage_map.json must equal a fresh in-memory regeneration (modulo
    the generated_at timestamp)."""
    _, enabled_eids, entries = _inputs()
    fresh = bct.build_machine_map(entries, enabled_eids)
    checked_in = json.loads(bct.COVERAGE_JSON.read_text(encoding="utf-8"))
    fresh.pop("generated_at", None)
    checked_in.pop("generated_at", None)
    assert checked_in == fresh, (
        "orchestrator/data/coverage_map.json is stale -- "
        "re-run scripts/build_coverage_table.py"
    )


def test_category_descriptions_cover_all_categories():
    """hookset_categories.json (served by GET /api/hookset) must describe
    exactly the categories used in the YAML -- no orphan descriptions, no
    undescribed category."""
    _, _, entries = _inputs()
    cats_json = PROJECT_ROOT / "orchestrator" / "data" / "hookset_categories.json"
    described = set(json.loads(cats_json.read_text(encoding="utf-8")).keys())
    used = {e.get("category") for e in entries}
    assert described == used, (
        f"category drift: described-only={sorted(described - used)}, "
        f"undescribed={sorted(used - described)}"
    )


def main() -> None:
    test_every_hook_has_yaml_entry()
    test_every_yaml_entry_names_a_real_hook()
    test_every_counterpart_eid_is_enabled()
    test_validate_reports_no_errors()
    test_json_in_sync_with_yaml()
    test_category_descriptions_cover_all_categories()
    print("ALL COVERAGE-MAP TESTS PASSED")


if __name__ == "__main__":
    main()
