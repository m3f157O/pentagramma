"""Standalone assert-based test for orchestrator/pid_lineage.py.

Same plain-script convention as tests/test_sigma_engine.py (this project
has no pytest/unittest suite). Run directly:

    .venv/Scripts/python.exe tests/test_pid_lineage.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.pid_lineage import build_pid_lineage, classify_alert_scope  # noqa: E402


def main() -> None:
    events = [
        {"event_type": "ProcessCreate", "data": {"ProcessId": "100", "ParentProcessId": "1"}},  # sample
        {"event_type": "ProcessCreate", "data": {"ProcessId": "200", "ParentProcessId": "100"}},  # sample's child
        {"event_type": "ProcessCreate", "data": {"ProcessId": "300", "ParentProcessId": "200"}},  # grandchild
        {"event_type": "ProcessCreate", "data": {"ProcessId": "999", "ParentProcessId": "1"}},  # unrelated
    ]

    # --- build_pid_lineage ---
    lineage = build_pid_lineage(events, 100)
    assert lineage.pids == {100, 200, 300}, lineage.pids
    print("PASS: build_pid_lineage includes root + all descendants, excludes unrelated PIDs")

    empty = build_pid_lineage(events, None)
    assert empty.pids == set() and empty.guids == set() and not empty
    print("PASS: build_pid_lineage(root_pid=None) returns an empty PidLineage")

    assert build_pid_lineage(events, 999).pids == {999}, "PID with no children should be a lineage of just itself"
    print("PASS: build_pid_lineage handles a leaf PID with no children")

    # --- classify_alert_scope ---
    alerts = [
        {"event_type": "ProcessCreate", "data": {"ProcessId": "200"}},  # descendant -> in scope
        {"event_type": "NetworkConnect", "data": {"ProcessId": "999"}},  # unrelated -> out of scope
        {"event_type": "ProcessAccess", "data": {"SourceProcessId": "300"}},  # descendant via SourceProcessId
        {"event_type": "SysmonEvent16", "data": {}},  # no PID at all -> defaults to out of scope
        {"event_type": "DmpYaraMatch", "in_sample_scope": True, "data": {"Rule": "test"}},  # pre-tagged, left untouched
    ]
    classified = classify_alert_scope(alerts, lineage)

    assert classified[0]["in_sample_scope"] is True, classified[0]
    print("PASS: alert with ProcessId in lineage -> in_sample_scope=True")

    assert classified[1]["in_sample_scope"] is False, classified[1]
    print("PASS: alert with ProcessId NOT in lineage -> in_sample_scope=False")

    assert classified[2]["in_sample_scope"] is True, classified[2]
    print("PASS: alert using SourceProcessId (not ProcessId) resolved correctly")

    assert classified[3]["in_sample_scope"] is False, classified[3]
    print("PASS: alert with no resolvable PID defaults to in_sample_scope=False")

    assert classified[4]["in_sample_scope"] is True, classified[4]
    assert classified[4] is not alerts[4] or classified[4]["in_sample_scope"] is True
    print("PASS: pre-tagged alert (e.g. DmpYaraMatch) is left untouched, not overwritten by inference")

    # classify_alert_scope must not mutate the caller's original alert dicts
    assert alerts[0].get("in_sample_scope") is None, "original alert dict was mutated in place"
    print("PASS: classify_alert_scope does not mutate input alerts")

    # --- Regression: PID reuse must not leak an unrelated later process's
    # activity into the sample's scope just because Windows recycled the
    # same PID number. Confirmed live (2026-07-03): a `timeout /t 3` child
    # (PID 9832) exited and Windows handed that PID to an unrelated
    # wermgr.exe milliseconds later; PID-only lineage scored wermgr.exe's own
    # bulk file writes as sample activity, since 9832 had ever been in-lineage. ---
    reuse_events = [
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "100", "ParentProcessId": "1", "ProcessGuid": "guid-root", "ParentProcessGuid": "guid-launcher",
        }},
        # The sample's own genuine child -- PID 9832, first incarnation.
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "9832", "ParentProcessId": "100", "ProcessGuid": "guid-timeout-1", "ParentProcessGuid": "guid-root",
        }},
        # An UNRELATED process, spawned by something else entirely, that
        # happens to reuse PID 9832 after the first incarnation exits --
        # NOT a child of the sample (ParentProcessGuid points elsewhere).
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "9832", "ParentProcessId": "1", "ProcessGuid": "guid-wermgr-2", "ParentProcessGuid": "guid-unrelated-parent",
        }},
    ]
    reuse_lineage = build_pid_lineage(reuse_events, 100)
    assert reuse_lineage.pids == {100, 9832}, reuse_lineage.pids  # PID-only view still can't tell the two apart
    assert reuse_lineage.guids == {"guid-root", "guid-timeout-1"}, reuse_lineage.guids  # guid view correctly excludes the reused PID's second incarnation
    print("PASS: build_pid_lineage's guid lineage excludes a reused PID's unrelated later incarnation")

    reuse_alerts = [
        # Same recycled PID, but the SECOND (unrelated) incarnation's guid -- must be OUT of scope.
        {"event_type": "FileCreate", "data": {"ProcessId": "9832", "ProcessGuid": "guid-wermgr-2"}},
        # First (genuine) incarnation's guid -- must be IN scope.
        {"event_type": "FileCreate", "data": {"ProcessId": "9832", "ProcessGuid": "guid-timeout-1"}},
        # No ProcessGuid at all (e.g. an older alert shape) -- falls back to
        # PID-only, which still (correctly, if conservatively) says in-scope
        # since 9832 really was in the sample's lineage at some point.
        {"event_type": "FileCreate", "data": {"ProcessId": "9832"}},
    ]
    reuse_classified = classify_alert_scope(reuse_alerts, reuse_lineage)
    assert reuse_classified[0]["in_sample_scope"] is False, reuse_classified[0]
    assert reuse_classified[1]["in_sample_scope"] is True, reuse_classified[1]
    assert reuse_classified[2]["in_sample_scope"] is True, reuse_classified[2]
    print("PASS: classify_alert_scope prefers ProcessGuid over a reused ProcessId, falls back when no guid is present")

    # --- Regression: ROOT PID reuse. Distinct from the descendant case above.
    # Confirmed live (2026-07-04): a throwaway conhost.exe transiently held the
    # PID the sample's own powershell.exe would later be assigned (~4s apart).
    # Resolving root_pid->root_guid by "first ProcessGuid seen for that PID"
    # picked the CONHOST's guid, so the guid lineage started from the wrong
    # incarnation and never included the real root -- silently dropping every
    # genuine root event (the Run-key persistence write scored out-of-scope).
    # The fix seeds root guids from the ParentProcessGuid root's own children
    # declare; a PID-reuse predecessor never parents the sample's children. ---
    root_reuse_events = [
        # Throwaway conhost that grabbed PID 100 FIRST (listed first on purpose
        # -- this is exactly what defeated the old first-seen resolution).
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "100", "ParentProcessId": "50", "ProcessGuid": "guid-conhost", "ParentProcessGuid": "guid-other",
        }},
        # The real sample process, later assigned the same PID 100.
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "100", "ParentProcessId": "60", "ProcessGuid": "guid-sample", "ParentProcessGuid": "guid-launcher",
        }},
        # The sample's genuine child -- points at the SAMPLE's guid as parent.
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "200", "ParentProcessId": "100", "ProcessGuid": "guid-child", "ParentProcessGuid": "guid-sample",
        }},
    ]
    rr = build_pid_lineage(root_reuse_events, 100)
    assert rr.pids == {100, 200}, rr.pids
    assert rr.guids == {"guid-sample", "guid-child"}, rr.guids  # NOT guid-conhost
    assert rr.contains_event({"ProcessId": "100", "ProcessGuid": "guid-sample"}) is True  # genuine root event
    assert rr.contains_event({"ProcessId": "100", "ProcessGuid": "guid-conhost"}) is False  # throwaway predecessor excluded
    assert rr.contains_event({"ProcessId": "100"}) is True  # no guid -> pid fallback
    print("PASS: build_pid_lineage resolves the correct root guid when a throwaway process reused root_pid first")

    # --- Regression: the HARDER root-PID-reuse variant, where the sample is
    # the CHILDLESS incarnation and an unrelated PID-reuse SUCCESSOR is the one
    # with children. Confirmed live (2026-07-04, c2_named_pipe): the sample
    # powershell.exe (which just opens a named pipe, no child processes) had
    # its PID grabbed ~3s later by an unrelated wuauclt.exe that spawned
    # AM_Delta.exe / MpSigStub.exe (Defender signature-update helpers). The
    # "seed from root's children's ParentProcessGuid" heuristic then resolves
    # to the WRONG (wuauclt) incarnation, so only the launcher-image signal
    # (execution_info.LauncherPath) can pick the real sample. ---
    successor_events = [
        # The sample -- a childless powershell.exe, listed first.
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "100", "ParentProcessId": "10", "ProcessGuid": "guid-sample",
            "ParentProcessGuid": "guid-launcher", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        }},
        # Unrelated Windows Update process that reused PID 100 after the sample.
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "100", "ParentProcessId": "20", "ProcessGuid": "guid-wuauclt",
            "ParentProcessGuid": "guid-svchost", "Image": "C:\\Windows\\System32\\wuauclt.exe",
        }},
        # wuauclt's child -- points at wuauclt's guid, NOT the sample's.
        {"event_type": "ProcessCreate", "data": {
            "ProcessId": "200", "ParentProcessId": "100", "ProcessGuid": "guid-amdelta",
            "ParentProcessGuid": "guid-wuauclt", "Image": "C:\\Windows\\...\\AM_Delta.exe",
        }},
    ]
    launcher = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    # Without the launcher image, the children heuristic mis-resolves to the
    # unrelated successor -- the exact bug the image signal fixes.
    no_img = build_pid_lineage(successor_events, 100)
    assert "guid-sample" not in no_img.guids, no_img.guids
    assert no_img.guids == {"guid-wuauclt", "guid-amdelta"}, no_img.guids
    # With it, root resolves to the real sample; the successor's subtree, though
    # still in the PID lineage, is guid-excluded from scope.
    with_img = build_pid_lineage(successor_events, 100, root_image=launcher)
    assert with_img.guids == {"guid-sample"}, with_img.guids
    assert with_img.pids == {100, 200}, with_img.pids  # PID view can't tell them apart...
    assert with_img.contains_event({"ProcessId": "100", "ProcessGuid": "guid-sample"}) is True
    assert with_img.contains_event({"ProcessId": "100", "ProcessGuid": "guid-wuauclt"}) is False  # unrelated successor
    assert with_img.contains_event({"ProcessId": "200", "ProcessGuid": "guid-amdelta"}) is False  # ...but guid view excludes its child
    print("PASS: launcher-image resolves the real sample when a childless sample's PID is reused by a child-ful unrelated process")

    # --- PidLineage.contains_event: the shared guid-preferred-then-pid
    # predicate that both classify_alert_scope and ioc_summary now route
    # through. Direct coverage of the precedence itself. ---
    ce_lineage = build_pid_lineage(reuse_events, 100)  # pids {100,9832}, guids {guid-root, guid-timeout-1}
    assert ce_lineage.contains_event({"ProcessGuid": "guid-timeout-1", "ProcessId": "9832"}) is True
    assert ce_lineage.contains_event({"ProcessGuid": "guid-wermgr-2", "ProcessId": "9832"}) is False  # guid wins over reused pid
    assert ce_lineage.contains_event({"ProcessId": "9832"}) is True  # no guid -> pid fallback
    assert ce_lineage.contains_event({"ProcessId": "4567"}) is False  # unrelated pid
    assert ce_lineage.contains_event({"SourceProcessId": "100"}) is True  # SourceProcessId alias
    assert ce_lineage.contains_event({}) is False  # no resolvable identifier
    print("PASS: PidLineage.contains_event encodes guid-preferred-then-pid precedence, no-id -> out of scope")

    # --- Regression: a real PidLineage object must flow through every
    # downstream consumer without a raw membership test blowing up.
    # build_ioc_summary._extract_network_connections did `pid in lineage`,
    # which crashed ("argument of type 'PidLineage' is not iterable") on EVERY
    # report the moment build_pid_lineage stopped returning a bare set -- the
    # offline suite never exercised the ioc path, so it shipped. This calls the
    # real build_ioc_summary with a PidLineage, so the same class of bug can't
    # slip through unnoticed again. ---
    from orchestrator.ioc_summary import build_ioc_summary  # noqa: E402

    ioc_events = [
        # in-scope connection (sample's own guid)
        {"event_type": "NetworkConnect", "data": {
            "ProcessId": "100", "ProcessGuid": "guid-root", "DestinationIp": "203.0.113.5", "DestinationPort": 443,
        }},
        # out-of-scope connection (unrelated process reusing PID 9832's number)
        {"event_type": "NetworkConnect", "data": {
            "ProcessId": "9832", "ProcessGuid": "guid-wermgr-2", "DestinationIp": "198.51.100.9", "DestinationPort": 80,
        }},
    ]
    ioc = build_ioc_summary(ioc_events, None, None, None, [], ce_lineage)
    conns = {c["destination_ip"]: c["in_sample_scope"] for c in ioc["network_connections"]}
    assert conns == {"203.0.113.5": True, "198.51.100.9": False}, conns
    print("PASS: build_ioc_summary consumes a PidLineage without crashing and scopes connections via contains_event")

    print("\nALL PID LINEAGE TESTS PASSED")


if __name__ == "__main__":
    main()
