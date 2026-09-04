"""Regression tests for the A4 tooling-attribution fixes (2026-09-03):

1. The monitor's child-following injection is CreateRemoteThread(LoadLibraryW)
   fired from the sample's own context, so Sysmon EID 8 attributes it to the
   sample and it lands in_sample_scope=True -- flapping benign_control.bat
   between 37/suspicious and 45/malicious depending on whether Sysmon caught
   the event. Fix: reporting._suppress_tooling_remote_thread_alerts marks EID
   8 alerts whose StartAddress equals the per-boot kernel32!LoadLibraryW VA
   (emitted by guardian_agent in the GuardianRegistered meta event) as
   tooling.

2. The defender readiness probe fires Virus:Win32/MpTest!amsi (the canonical
   AMSI test string) on every run; detect_defender_threats used to surface it
   as an in-scope sample detection (+25 verdict weight on every benign run).
   Fix: MpTest threats are filtered out of the alerts entirely.
"""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator import heuristics, reporting  # noqa: E402


def _guardian_meta(va_x64=0x7FF90EA8FEE0, va_x86=0x7611D820):
    return {
        "source": "guardian",
        "event_type": "GuardianRegistered",
        "data": {"Text": f"protected_pids=[1] sysmon_pids=[2] target=monitor_loader.exe "
                         f"loadlibrary_x64=0x{va_x64:x} loadlibrary_x86=0x{va_x86:x}"},
    }


def _crt_alert(start_address, in_scope=True):
    return {
        "event_type": "CreateRemoteThread",
        "in_sample_scope": in_scope,
        "data": {"SourceImage": "C:\\Windows\\System32\\cmd.exe",
                 "TargetImage": "C:\\Windows\\System32\\notepad.exe",
                 "StartAddress": start_address},
    }


def test_tooling_eid8_suppressed_by_loadlibrary_va():
    events = [_guardian_meta()]
    tooling = _crt_alert("0x00007FF90EA8FEE0")          # == loadlibrary_x64
    sample_crt = _crt_alert("0x0000021F3C400000")       # shellcode-style alloc
    out = reporting._suppress_tooling_remote_thread_alerts([tooling, sample_crt], events)
    assert out[0]["in_sample_scope"] is False
    assert "tooling" in out[0]["scope_reason"]
    assert out[1]["in_sample_scope"] is True            # real injection untouched


def test_tooling_eid8_suppressed_x86_va():
    events = [_guardian_meta()]
    wow64_tooling = _crt_alert("0x7611D820")            # == loadlibrary_x86
    out = reporting._suppress_tooling_remote_thread_alerts([wow64_tooling], events)
    assert out[0]["in_sample_scope"] is False


def test_tooling_eid8_filter_noop_without_guardian_meta():
    out = reporting._suppress_tooling_remote_thread_alerts([_crt_alert("0x00007FF90EA8FEE0")], [])
    assert out[0]["in_sample_scope"] is True            # fail-open: no VA source


def test_tooling_eid8_suppresses_sigma_variant_too():
    events = [_guardian_meta()]
    sigma_alert = _crt_alert("0x00007FF90EA8FEE0")
    sigma_alert["sigma"] = {"title": "Remote Thread Creation In Uncommon Target Image"}
    out = reporting._suppress_tooling_remote_thread_alerts([sigma_alert], events)
    assert out[0]["in_sample_scope"] is False


def _defender_event(threat_name):
    return {
        "source": "windefend",
        "event_type": "DefenderThreatDetected",
        "event_id": 1116,
        "timestamp": "2026-09-03T00:00:00Z",
        "data": {"Threat Name": threat_name, "Path": "C:\\Sandbox\\sample.ps1"},
    }


def test_mptest_readiness_probe_filtered():
    # No sample start known -> all MpTest dropped (conservative FP direction).
    alerts = heuristics.detect_defender_threats([_defender_event("Virus:Win32/MpTest!amsi")])
    assert alerts == []
    # Detection BEFORE the sample started -> tooling probe, dropped.
    ev = _defender_event("Virus:Win32/MpTest!amsi")
    ev["data"]["Detection Time"] = "2026-09-03T18:04:39.596Z"
    alerts = heuristics.detect_defender_threats([ev], sample_start=datetime(2026, 9, 3, 18, 5, 0))
    assert alerts == []


def test_mptest_during_sample_kept():
    # amsi_detection.ps1 deliberately prints the AMSI test string DURING its
    # run -- that detection is the sample's own behavior and must score.
    ev = _defender_event("Virus:Win32/MpTest!amsi")
    ev["data"]["Detection Time"] = "2026-09-03T18:05:30.000Z"
    alerts = heuristics.detect_defender_threats([ev], sample_start=datetime(2026, 9, 3, 18, 5, 0))
    assert len(alerts) == 1 and alerts[0]["in_sample_scope"] is True


def test_real_defender_threat_kept():
    alerts = heuristics.detect_defender_threats([_defender_event("Trojan:Win32/Ceprolad.A")])
    assert len(alerts) == 1
    assert alerts[0]["in_sample_scope"] is True
