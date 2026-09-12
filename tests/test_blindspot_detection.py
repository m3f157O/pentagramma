"""Unit tests for the WS-B runtime blind-spot detectors.

Detectors under test (orchestrator/behavioral_signatures.py):
  - _detect_counterpart_misses -> ApitraceBlindSpot (Sysmon saw a behavior a
    `both`-class hook should also have seen, but no same-pid apitrace
    counterpart exists within +/-2s)
  - _detect_telemetry_silence  -> ApitraceSilence (a traced pid stops producing
    dual-covered API events while Sysmon still sees it active)

Runs offline against synthetic apitrace/sysmon event lists. Plain asserts, no
pytest: .venv\\Scripts\\python.exe tests\\test_blindspot_detection.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.behavioral_signatures import detect_behavioral_signatures

_BASE = datetime(2026, 7, 19, 18, 0, 0, tzinfo=timezone.utc)


def _ts(seconds):
    return (_BASE + timedelta(seconds=seconds)).isoformat()


def _api(api, pid, seconds, arg0="", category="memory", tid=1):
    return {
        "source": "apitrace",
        "event_id": 9200,
        "event_type": "ApiCall",
        "timestamp": _ts(seconds),
        "data": {"Api": api, "Category": category, "ProcessId": pid, "ThreadId": tid, "Arg0": arg0},
    }


def _meta(api, pid, seconds):
    return _api(api, pid, seconds, category="meta")


def _sysmon(eid, pid, seconds, **data):
    fields = {"ProcessId": pid, "Image": "C:\\Windows\\sample.exe"}
    fields.update(data)
    return {
        "source": "sysmon",
        "event_id": eid,
        "event_type": "SysmonEvent",
        "timestamp": _ts(seconds),
        "data": fields,
    }


def _blindspot_or_silence(alerts):
    # __event_cap_reached__ fixtures legitimately add an ApiTraceTruncated
    # transparency alert; these tests only care about the WS-B pair.
    return [a for a in alerts if a["event_type"] in ("ApitraceBlindSpot", "ApitraceSilence")]


def test_blinded_hook_fires():
    # Traced pid, Sysmon logs a registry set-value (EID 13 <-> NtSetValueKey)
    # with no apitrace counterpart in the +/-2s window -> hook suspected blind.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _sysmon(13, 4000, 10, TargetObject="HKCU\\Software\\Run\\x"),
        # The second miss for the same (pid, api) takes it over the 2-miss
        # threshold -- one alert, first miss cited (one-off misses are
        # collector artifacts and never alert).
        _sysmon(13, 4000, 40, TargetObject="HKCU\\Software\\Run\\y"),
    ]
    alerts = detect_behavioral_signatures(events)
    blind = [a for a in alerts if a["event_type"] == "ApitraceBlindSpot"]
    assert len(blind) == 1, alerts
    assert "2 Sysmon EID 13" in blind[0]["data"]["Type"]
    assert "hook NtSetValueKey blind" in blind[0]["data"]["Type"], blind[0]
    assert "Sysmon EID 13" in blind[0]["data"]["Type"], blind[0]
    assert blind[0]["data"]["ProcessId"] == 4000


def test_capped_pid_suppressed():
    # Volume cap hit -> trace is lossy, absence proves nothing.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _meta("__event_cap_reached__", 4000, 5),
        _sysmon(13, 4000, 10, TargetObject="HKCU\\Software\\Run\\x"),
    ]
    assert not _blindspot_or_silence(detect_behavioral_signatures(events))


def test_pre_handshake_sysmon_suppressed():
    # Sysmon event predates __monitor_attached__ (hooks not yet placed), even
    # though the pid has an apitrace event before the Sysmon one.
    events = [
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _sysmon(13, 4000, 2, TargetObject="HKCU\\Software\\Run\\x"),
        _meta("__monitor_attached__", 4000, 5),
    ]
    assert not detect_behavioral_signatures(events)


def test_untraced_pid_suppressed():
    # No apitrace at all for the pid -> outside the traced tree.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _sysmon(13, 9999, 10, TargetObject="HKCU\\Software\\Run\\x"),
    ]
    assert not detect_behavioral_signatures(events)

    # First apitrace event comes AFTER the Sysmon event -> not (yet) traced.
    events = [
        _meta("__monitor_attached__", 5000, 15),
        _sysmon(13, 5000, 10, TargetObject="HKCU\\Software\\Run\\x"),
        _api("NtCreateFile", 5000, 20, "C:\\Windows\\Temp\\a.bin", category="file"),
    ]
    assert not detect_behavioral_signatures(events)


def test_wow64_gap_suppressed():
    # __wow64_follow__ marks the re-injection gap; suppress misses within +/-5s.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _meta("__wow64_follow__", 4000, 8),
        _sysmon(13, 4000, 10, TargetObject="HKCU\\Software\\Run\\x"),
    ]
    assert not detect_behavioral_signatures(events)


def test_healthy_counterparts_no_alert():
    # Counterpart API present in-window -> no blind spot, no silence.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtSetValueKey", 4000, 9, "HKCU\\Software\\Run\\x", category="registry"),
        _sysmon(13, 4000, 10, TargetObject="HKCU\\Software\\Run\\x"),
    ]
    assert not detect_behavioral_signatures(events)


def test_silence_fires():
    # Traced pid produces both-class events early, then goes quiet for the
    # rest of the run while Sysmon (EID 3, sysmon-only -> no blind-spot noise)
    # keeps seeing it active.
    events = [_meta("__monitor_attached__", 4000, 0)]
    events += [
        _api("NtCreateFile", 4000, sec, f"C:\\Windows\\Temp\\f{sec}.bin", category="file")
        for sec in range(1, 6)
    ]
    events += [_sysmon(3, 4000, 20 + i, DestinationIp="10.0.0.1") for i in range(8)]
    alerts = detect_behavioral_signatures(events)
    silence = [a for a in alerts if a["event_type"] == "ApitraceSilence"]
    assert len(silence) == 1, alerts
    assert silence[0]["data"]["ProcessId"] == 4000
    assert "mid-run unhooking" in silence[0]["data"]["Type"], silence[0]
    assert not [a for a in alerts if a["event_type"] == "ApitraceBlindSpot"]


def test_silence_capped_pid_suppressed():
    events = [_meta("__monitor_attached__", 4000, 0)]
    events += [
        _api("NtCreateFile", 4000, sec, f"C:\\Windows\\Temp\\f{sec}.bin", category="file")
        for sec in range(1, 6)
    ]
    events.append(_meta("__event_cap_reached__", 4000, 6))
    events += [_sysmon(3, 4000, 20 + i, DestinationIp="10.0.0.1") for i in range(8)]
    assert not _blindspot_or_silence(detect_behavioral_signatures(events))


def test_hook_only_heavy_pid_no_silence():
    # Pid traced with hook-only APIs only (timing): it never produced
    # dual-covered telemetry, so quiet is its baseline, not an anomaly.
    events = [_meta("__monitor_attached__", 4000, 0)]
    events += [_api("GetTickCount64", 4000, sec, category="timing") for sec in range(1, 4)]
    events += [_api("NtDelayExecution", 4000, sec, category="timing") for sec in range(4, 7)]
    events += [_sysmon(3, 4000, 20 + i, DestinationIp="10.0.0.1") for i in range(8)]
    assert not detect_behavioral_signatures(events)


def test_kernel_bam_registry_write_suppressed():
    # BAM/DAM records are written by the kernel at process exit and attributed
    # to the dying process -- no user-mode NtSetValueKey ever happens.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _sysmon(5, 4000, 10),
        _sysmon(13, 4000, 10,
                TargetObject="HKLM\\System\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-x\\cmd.exe"),
    ]
    assert not detect_behavioral_signatures(events)
    # A non-BAM EID 13 at the same moment still fires (twice -- one-off
    # misses are collector-artifact suppressed).
    events[-1] = _sysmon(13, 4000, 10, TargetObject="HKCU\\Software\\Run\\x")
    events.append(_sysmon(13, 4000, 11, TargetObject="HKCU\\Software\\Run\\y"))
    assert [a["event_type"] for a in detect_behavioral_signatures(events)] == ["ApitraceBlindSpot"]


def test_startup_image_load_grace_suppressed():
    # Process-init image loads bypass LdrLoadDll and straddle hook placement.
    events = [
        _meta("__monitor_attached__", 4000, 10),
        _api("NtCreateFile", 4000, 9, "C:\\Windows\\Temp\\a.bin", category="file"),
        _sysmon(7, 4000, 12, ImageLoaded="C:\\Windows\\System32\\msvcrt.dll"),
    ]
    assert not detect_behavioral_signatures(events)
    # Long after the handshake a missing LdrLoadDll counterpart still fires
    # (repeated miss, not a one-off).
    events[-1] = _sysmon(7, 4000, 30, ImageLoaded="C:\\Windows\\System32\\msvcrt.dll")
    events.append(_sysmon(7, 4000, 31, ImageLoaded="C:\\Windows\\System32\\msi.dll"))
    alerts = detect_behavioral_signatures(events)
    assert [a["event_type"] for a in alerts] == ["ApitraceBlindSpot"]
    assert "hook LdrLoadDll blind" in alerts[0]["data"]["Type"]


def test_own_child_injection_suppressed():
    # The monitor's child-following injection (and kernel32's spawn writes)
    # hit every just-created child from the parent's context, monitor-side
    # suppressed -> no apitrace counterpart for EID 8/10 on that target.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateUserProcess", 4000, 1, "child_pid=5000 suspended=0 wow64=0", category="process"),
        _sysmon(8, 4000, 2, SourceProcessId=4000, TargetProcessId=5000),
        _sysmon(10, 4000, 2, SourceProcessId=4000, TargetProcessId=5000),
    ]
    assert not detect_behavioral_signatures(events)
    # The same EIDs targeting an UNRELATED process still fire (twice each --
    # one-off misses are suppressed as collector artifacts).
    events[1] = _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file")
    events.append(_sysmon(8, 4000, 5, SourceProcessId=4000, TargetProcessId=5000))
    events.append(_sysmon(10, 4000, 6, SourceProcessId=4000, TargetProcessId=5000))
    alerts = detect_behavioral_signatures(events)
    blind = [a for a in alerts if a["event_type"] == "ApitraceBlindSpot"]
    assert len(blind) == 2, alerts  # EID 8 (NtCreateThreadEx) + EID 10 (NtAllocateVirtualMemory)


def test_kernel_bam_registry_write_suppressed():
    # EID 13 under \\Services\\bam\\ is kernel-side bookkeeping at process exit
    # (measured on the benign bat canary); a user-mode NtSetValueKey never ran.
    # The same EID on a normal key still fires.
    bam_key = "HKLM\\System\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-x\\\\Device\\HarddiskVolume3\\cmd.exe"
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _sysmon(13, 4000, 10, TargetObject=bam_key),
    ]
    assert not _blindspot_or_silence(detect_behavioral_signatures(events))
    events.append(_sysmon(13, 4000, 20, TargetObject="HKCU\\Software\\Run\\x"))
    events.append(_sysmon(13, 4000, 21, TargetObject="HKCU\\Software\\Run\\y"))
    blind = [a for a in detect_behavioral_signatures(events) if a["event_type"] == "ApitraceBlindSpot"]
    assert len(blind) == 1
    assert "EID 13" in blind[0]["data"]["Type"]


def test_image_load_startup_grace_suppressed():
    # EID 7 right after the handshake: process-init loads bypass LdrLoadDll.
    # An ImageLoad well past the grace window with no LdrLoadDll still fires.
    events = [
        _meta("__monitor_attached__", 4000, 10),
        _api("NtCreateFile", 4000, 9, "C:\\Windows\\Temp\\a.bin", category="file"),
        _sysmon(7, 4000, 11, ImageLoaded="C:\\Windows\\System32\\kernel32.dll"),
    ]
    assert not _blindspot_or_silence(detect_behavioral_signatures(events))
    events.append(_sysmon(7, 4000, 60, ImageLoaded="C:\\Windows\\System32\\wininet.dll"))
    events.append(_sysmon(7, 4000, 61, ImageLoaded="C:\\Windows\\System32\\winhttp.dll"))
    blind = [a for a in detect_behavioral_signatures(events) if a["event_type"] == "ApitraceBlindSpot"]
    assert len(blind) == 1
    assert "hook LdrLoadDll blind" in blind[0]["data"]["Type"]


def test_own_child_remote_thread_suppressed():
    # EID 8/10 sourced from a traced pid into its OWN just-created child is the
    # monitor's child-following injection (plus kernel32's spawn writes), both
    # suppressed monitor-side. The same EID 8 into an unrelated pid still fires.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _api("NtCreateUserProcess", 4000, 2, "child_pid=5000 suspended=0 wow64=0", category="process"),
        _sysmon(8, 4000, 3, SourceProcessId=4000, TargetProcessId=5000, TargetImage="C:\\Windows\\System32\\certutil.exe"),
        _sysmon(10, 4000, 4, SourceProcessId=4000, TargetProcessId=5000, TargetImage="C:\\Windows\\System32\\certutil.exe"),
    ]
    assert not _blindspot_or_silence(detect_behavioral_signatures(events))
    events.append(_sysmon(8, 4000, 30, SourceProcessId=4000, TargetProcessId=7777, TargetImage="C:\\Windows\\System32\\lsass.exe"))
    events.append(_sysmon(8, 4000, 31, SourceProcessId=4000, TargetProcessId=7777, TargetImage="C:\\Windows\\System32\\lsass.exe"))
    blind = [a for a in detect_behavioral_signatures(events) if a["event_type"] == "ApitraceBlindSpot"]
    assert len(blind) == 1
    assert "hook NtCreateThreadEx blind" in blind[0]["data"]["Type"]


def test_pid_reuse_suppressed():
    # Monitor attaches to a short-lived process (pid 4000). The OS then
    # REUSES pid 4000 for an unrelated, untracked process (Sysmon EID 1 at
    # t=30). The new incarnation's image loads (EID 7) must NOT count as
    # hook-blind misses against the old process's apitrace slot -- observed
    # live 2026-09-12: certutil exited, its pid was reused by powershell,
    # and the benign canary scored 15 on 82 phantom misses.
    events = [
        _meta("__monitor_attached__", 4000, 0),
        _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
        _sysmon(1, 4000, 30, Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        _sysmon(7, 4000, 31, ImageLoaded="C:\\Windows\\System32\\a.dll"),
        _sysmon(7, 4000, 32, ImageLoaded="C:\\Windows\\System32\\b.dll"),
        _sysmon(7, 4000, 33, ImageLoaded="C:\\Windows\\System32\\c.dll"),
    ]
    assert not _blindspot_or_silence(detect_behavioral_signatures(events))
    # Sanity: without the EID-1 reuse marker the same loads DO alert.
    events = events[:2] + events[3:]
    blind = [a for a in detect_behavioral_signatures(events) if a["event_type"] == "ApitraceBlindSpot"]
    assert len(blind) == 1, blind
    assert "hook LdrLoadDll blind" in blind[0]["data"]["Type"], blind[0]


def test_missing_coverage_map_noop():
    # Offline-replay robustness: no machine map -> detectors no-op, not crash.
    from orchestrator import behavioral_signatures as bs

    original = bs._COVERAGE_MAP_CACHE
    try:
        bs._COVERAGE_MAP_CACHE = {}
        events = [
            _meta("__monitor_attached__", 4000, 0),
            _api("NtCreateFile", 4000, 1, "C:\\Windows\\Temp\\a.bin", category="file"),
            _sysmon(13, 4000, 10, TargetObject="HKCU\\Software\\Run\\x"),
        ]
        assert not _blindspot_or_silence(detect_behavioral_signatures(events))
    finally:
        bs._COVERAGE_MAP_CACHE = original


def main() -> None:
    test_blinded_hook_fires()
    test_capped_pid_suppressed()
    test_pre_handshake_sysmon_suppressed()
    test_untraced_pid_suppressed()
    test_wow64_gap_suppressed()
    test_healthy_counterparts_no_alert()
    test_silence_fires()
    test_silence_capped_pid_suppressed()
    test_hook_only_heavy_pid_no_silence()
    test_kernel_bam_registry_write_suppressed()
    test_startup_image_load_grace_suppressed()
    test_own_child_injection_suppressed()
    test_pid_reuse_suppressed()
    test_missing_coverage_map_noop()
    print("ALL BLIND-SPOT DETECTION TESTS PASSED")


if __name__ == "__main__":
    main()
