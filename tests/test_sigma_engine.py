"""Standalone assert-based test for orchestrator/sigma_engine.py.

This project has no pytest/unittest suite (only ad-hoc scripts under
tests/local/) -- this follows that same plain-script convention rather
than introducing a new test-framework dependency. Run directly:

    .venv/Scripts/python.exe tests/test_sigma_engine.py

Exercises the real fixture rules under tests/fixtures/sigma_rules/
(including the actual SigmaHQ proc_creation_win_susp_execution_path.yml
rule, verified against upstream during development) against synthetic
telemetry events shaped like this project's real Sysmon JSONL output.
"""

import gc
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.sigma_engine import SigmaEngine  # noqa: E402

FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "sigma_rules"


def main() -> None:
    engine = SigmaEngine(FIXTURES_DIR, min_level="low")
    assert engine.rule_count == 5, f"expected 5 fixture rules, got {engine.rule_count}"
    assert not engine.load_errors, engine.load_errors

    # --- SigmaString: contains/startswith/endswith + "1 of x*" quantifier ---
    matching_event = {
        "event_type": "ProcessCreate",
        "event_id": 1,
        "timestamp": "2026-07-02T10:00:00Z",
        "data": {"Image": r"C:\Perflogs\evil.exe", "ProcessId": "1234"},
    }
    alerts = engine.evaluate([matching_event])
    assert len(alerts) == 1, alerts
    assert alerts[0]["sigma"]["id"] == "3dfd06d2-eaf4-4532-9555-68aca59f57c4"
    assert alerts[0]["event_id"] == 1  # real event_id preserved, not a synthetic one
    assert alerts[0]["source"] == "sigma"
    mitre_ids = {c["technique_id"] for c in ([alerts[0]["mitre"]["primary"]] + alerts[0]["mitre"]["candidates"]) if c}
    assert "T1036" in mitre_ids, mitre_ids  # rule's own tag, merged in by mitre_mapping.enrich_alert
    print("PASS: SigmaString contains-match + MITRE tag merge")

    suppressed_event = {
        "event_type": "ProcessCreate",
        "event_id": 1,
        "timestamp": "2026-07-02T10:00:00Z",
        "data": {"Image": r"C:\Users\Public\IBM\ClientSolutions\Start_Programs\updater.exe", "ProcessId": "1235"},
    }
    assert engine.evaluate([suppressed_event]) == [], "filter_optional_ibm should have suppressed this match"
    print("PASS: '1 of filter_optional_*' quantifier correctly suppresses the match")

    ordinary_event = {
        "event_type": "ProcessCreate",
        "event_id": 1,
        "timestamp": "2026-07-02T10:00:00Z",
        "data": {"Image": r"C:\Program Files\Notepad++\notepad++.exe", "ProcessId": "1236"},
    }
    assert engine.evaluate([ordinary_event]) == []
    print("PASS: ordinary non-matching path produces no alert")

    # --- SigmaCIDRExpression + SigmaNumber ---
    net_events = [
        {"event_type": "NetworkConnect", "event_id": 3, "timestamp": "t", "data": {"DestinationIp": "10.1.2.3", "DestinationPort": "4444"}},
        {"event_type": "NetworkConnect", "event_id": 3, "timestamp": "t", "data": {"DestinationIp": "192.168.1.3", "DestinationPort": "4444"}},
        {"event_type": "NetworkConnect", "event_id": 3, "timestamp": "t", "data": {"DestinationIp": "10.1.2.3", "DestinationPort": "80"}},
    ]
    net_alerts = engine.evaluate(net_events)
    assert len(net_alerts) == 1, net_alerts
    assert net_alerts[0]["sigma"]["title"] == "Test CIDR Rule"
    print("PASS: CIDR + numeric-equality AND condition")

    # --- EventID field special case (top-level event_id, not data.EventID) ---
    # Real parsers (agent/windows/sysmon_parser.py etc.) always stamp
    # "source" -- required for the two-level service dispatch below to
    # route these events at all.
    sysmon_events = [
        {"event_type": "SysmonEvent16", "event_id": 16, "source": "sysmon", "timestamp": "t", "data": {}},
        {"event_type": "SysmonEvent255", "event_id": 255, "source": "sysmon", "timestamp": "t", "data": {}},
    ]
    sysmon_alerts = engine.evaluate(sysmon_events)
    assert len(sysmon_alerts) == 1, sysmon_alerts
    assert sysmon_alerts[0]["event_id"] == 16
    print("PASS: logsource.service=='sysmon' rule + top-level EventID field resolution")

    # --- Two-level service dispatch: source-bucket isolation + EventID sub-index ---
    security_match = {"event_type": "SecurityEvent4697", "event_id": 4697, "source": "security", "timestamp": "t", "data": {}}
    security_alerts = engine.evaluate([security_match])
    assert len(security_alerts) == 1, security_alerts
    assert security_alerts[0]["sigma"]["id"] == "44444444-4444-4444-4444-444444444444"
    print("PASS: service=='security' rule matched via EventID sub-index")

    # Same numeric EventID (16) as the sysmon config-tamper rule, but wrong
    # source -- must NOT cross-fire. Proves the source-bucket is a real
    # isolation boundary, not just an optimization.
    cross_service_event = {"event_type": "SecurityEvent16", "event_id": 16, "source": "security", "timestamp": "t", "data": {}}
    assert engine.evaluate([cross_service_event]) == [], "EventID 16 from source=='security' must not match the sysmon-service rule"
    print("PASS: service buckets are isolated by source, not just EventID")

    # Rule with no statically-resolvable EventID (selection keys off Image,
    # not EventID) must still fire via the per-service fallback list.
    fallback_match = {
        "event_type": "SysmonEvent1",
        "event_id": 1,
        "source": "sysmon",
        "timestamp": "t",
        "data": {"Image": r"C:\temp\FallbackMarker.exe"},
    }
    fallback_alerts = engine.evaluate([fallback_match])
    assert len(fallback_alerts) == 1, fallback_alerts
    assert fallback_alerts[0]["sigma"]["id"] == "33333333-3333-3333-3333-333333333333"
    print("PASS: service rule with no static EventID still matches via fallback list")

    # --- Regression: compiled-pattern caches must be per-SigmaEngine
    # instance attributes (engine._match_caches), not module-level globals.
    # A module-level cache -- even correctly value-keyed -- either (a) keyed
    # by id(value): outlives any single engine, so once an engine's rule
    # objects are garbage collected, Python can reuse that memory address
    # for a completely unrelated pattern in the NEXT engine instance, and
    # the cache silently serves the wrong compiled regex for it; or (b)
    # keyed by pattern value: correct, but forces recomputing the pattern's
    # string form on every match attempt just to check the cache, which is
    # a severe perf regression across tens of thousands of events. Both were
    # confirmed live (2026-07-03): (a) as unrelated Sigma rules ("Renamed
    # AdFind Execution", "Potential SMB Relay Attack Tool Execution") firing
    # on a plain notepad.exe invocation; (b) as the orchestrator becoming
    # unresponsive under the new job queue (CPU climbing continuously,
    # consistent with slow-but-real progress rather than a deadlock).
    assert hasattr(engine, "_match_caches"), "SigmaEngine must own its pattern caches as an instance attribute"
    assert engine._match_caches.string, "cache should be populated after the evaluations above"
    for key in engine._match_caches.string:
        assert isinstance(key, int), f"cache key {key!r} should be id(value) -- an int -- not something else"
    print("PASS: pattern caches are per-engine-instance attributes, keyed by id() for O(1) lookup")

    # Behavioral check: an engine whose rule objects have been garbage
    # collected must not leak stale matches into a freshly-loaded engine
    # evaluating unrelated content, even if Python reuses the freed
    # addresses (which it commonly does for same-size short-lived objects) --
    # this is now structurally impossible (each engine owns its own cache
    # dict, never shared), but kept as a live behavioral guard.
    engine1 = SigmaEngine(FIXTURES_DIR, min_level="low")
    engine1.evaluate([matching_event])  # populates engine1's own instance cache
    del engine1
    gc.collect()

    engine2 = SigmaEngine(FIXTURES_DIR, min_level="low")
    assert engine2.evaluate([ordinary_event]) == [], (
        "a fresh engine must not inherit a stale cache hit from a garbage-collected engine's rules"
    )
    print("PASS: fresh engine after a prior engine's garbage collection evaluates independently")

    print("\nALL SIGMA ENGINE TESTS PASSED")


if __name__ == "__main__":
    main()
