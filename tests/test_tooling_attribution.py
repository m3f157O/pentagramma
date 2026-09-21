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


def test_mptest_pathless_always_dropped():
    # 2026-09-21 MachineGUID regression: the readiness probe's MpTest detection
    # landed LATE (after the init log clear) with no Path, and the sample's
    # stale-stamped ProcessCreate made the time comparison invert -- it scored
    # +25 on a benign atomic. Path-less MpTest is our probe by construction,
    # regardless of timestamps.
    ev = _defender_event("Virus:Win32/MpTest!amsi")
    ev["data"]["Path"] = None
    ev["data"]["Detection Time"] = "2026-09-03T18:05:30.000Z"  # AFTER sample start
    alerts = heuristics.detect_defender_threats([ev], sample_start=datetime(2026, 9, 3, 18, 5, 0))
    assert alerts == []


def test_real_defender_threat_kept():
    alerts = heuristics.detect_defender_threats([_defender_event("Trojan:Win32/Ceprolad.A")])
    assert len(alerts) == 1
    assert alerts[0]["in_sample_scope"] is True


def test_mptest_agent_dir_path_always_dropped():
    # 2026-09-18 regression: Defender engine 4.18.26080 flagged our own
    # defender_manager.cpython-311.pyc (constant-folding put the AMSI test
    # string in the .pyc despite source fragmentation). Any MpTest detection
    # under the agent dir is our tooling by construction, at ANY timestamp.
    ev = _defender_event("Virus:Win32/MpTest!amsi")
    ev["data"]["Path"] = r"file:_C:\SandboxAgent\__pycache__\defender_manager.cpython-311.pyc"
    ev["data"]["Detection Time"] = "2026-09-03T18:05:30.000Z"  # AFTER sample start
    alerts = heuristics.detect_defender_threats([ev], sample_start=datetime(2026, 9, 3, 18, 5, 0))
    assert alerts == []


# ---------------------------------------------------------------------------
# OS-noise scope-leak suppression (2026-09-05): the benign canary's entire
# 12-point score was these artifacts (monitor-DLL ImageLoad + apitrace pipe
# genuinely in-lineage; EdgeUpdate/WMI health-probe adopted via recycled PID).
# ---------------------------------------------------------------------------

def _alert(source, event_type, data, in_scope=True):
    return {"source": source, "event_type": event_type,
            "in_sample_scope": in_scope, "data": data}


def test_own_monitor_dll_imageload_suppressed():
    a = _alert("sysmon", "ImageLoad", {
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ImageLoaded": "C:\\SandboxAgent\\monitor_x64.dll",
        "ProcessId": "3396", "ProcessGuid": "{9ff8e9dc-66de-6aa1-5001-000000003400}"})
    out = reporting._suppress_os_noise_scope_leaks([a])
    assert out[0]["in_sample_scope"] is False
    assert "tooling" in out[0]["scope_reason"]


def test_apitrace_pipe_suppressed():
    a = _alert("sysmon", "PipeConnected", {
        "Image": "C:\\Windows\\System32\\cmd.exe", "PipeName": "\\sandbox_apitrace",
        "ProcessId": "3396", "ProcessGuid": "{9ff8e9dc-66de-6aa1-5001-000000003400}"})
    out = reporting._suppress_os_noise_scope_leaks([a])
    assert out[0]["in_sample_scope"] is False


def test_os_noise_image_pid_adoption_suppressed():
    # GUID-less EID 10 from a recycled pid now held by the Edge updater.
    a = _alert("sysmon", "ProcessAccess", {
        "SourceImage": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        "TargetImage": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        "SourceProcessId": "9152", "GrantedAccess": "0x1410"})
    out = reporting._suppress_os_noise_scope_leaks([a])
    assert out[0]["in_sample_scope"] is False
    assert "os-noise" in out[0]["scope_reason"]


def test_wmi_health_probe_suppressed():
    a = _alert("wmi_etw", "WmiTemporaryConsumer", {
        "ProcessId": 3972, "User": "NT AUTHORITY\\LOCAL SERVICE",
        "Query": "SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'AntiVirusProduct'"})
    out = reporting._suppress_os_noise_scope_leaks([a])
    assert out[0]["in_sample_scope"] is False
    assert "health-probe" in out[0]["scope_reason"]


def test_real_sample_activity_untouched():
    # Malware loading its own DLL from TEMP: same event type as the tooling
    # case but not our artifact -> stays in scope.
    a = _alert("sysmon", "ImageLoad", {
        "Image": "C:\\Sandbox\\sample.exe",
        "ImageLoaded": "C:\\Users\\gigi\\AppData\\Local\\Temp\\evil.dll",
        "ProcessId": "3396"})
    # Malware AV-discovery query (plain SELECT, user context): stays in scope.
    b = _alert("wmi_etw", "WmiTemporaryConsumer", {
        "ProcessId": 3396, "User": "DESKTOP-RO2VL5M\\gigi",
        "Query": "SELECT * FROM AntiVirusProduct"})
    # GUID-carrying alert from a noise image: the guid path is trusted by
    # construction, the pass only touches GUID-less pid adoption.
    c = _alert("sysmon", "ProcessAccess", {
        "SourceImage": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        "SourceProcessId": "9152",
        "SourceProcessGuid": "{9ff8e9dc-66de-6aa1-5001-000000009999}"})
    out = reporting._suppress_os_noise_scope_leaks([a, b, c])
    assert all(x["in_sample_scope"] is True for x in out)
    assert all("scope_reason" not in x for x in out)


# ---------------------------------------------------------------------------
# Monitor-injection / staging artifact suppression (2026-09-11): the goodware
# FP hunt found a trivial hello-world exe scoring malicious/42 purely on the
# loader's own hook injection (EID 10 + ApitraceInjectionChain) and a Sigma
# "suspicious extension" rule firing on our extensionless staged filename.
# ---------------------------------------------------------------------------

_LOADER_PROCCREATE = {
    "event_type": "ProcessCreate",
    "data": {"Image": "C:\\SandboxAgent\\monitor_loader_x86.exe", "ProcessId": "10628"},
}


def test_loader_processaccess_suppressed():
    a = _alert("sysmon", "ProcessAccess", {
        "SourceImage": "C:\\SandboxAgent\\monitor_loader_x86.exe",
        "TargetImage": "C:\\Sandbox\\9b3f1e32",
        "SourceProcessId": "10628", "TargetProcessId": "7520",
        "GrantedAccess": "0x1fffff"})
    out = reporting._suppress_monitor_injection_artifacts([a], [], None)
    assert out[0]["in_sample_scope"] is False
    assert "tooling" in out[0]["scope_reason"]


def test_loader_apitrace_injection_chain_suppressed():
    # Behavioral signature synthesized from the loader pid's own API calls.
    a = _alert("apitrace", "ApitraceInjectionChain", {
        "ProcessId": 10628, "TargetProcessId": 7520,
        "Type": "Write into remote process 7520 followed by thread start/resume"})
    out = reporting._suppress_monitor_injection_artifacts([a], [_LOADER_PROCCREATE], None)
    assert out[0]["in_sample_scope"] is False


def test_sample_apitrace_injection_chain_kept():
    # Same signature, but attributed to a NON-tooling pid: real injection.
    a = _alert("apitrace", "ApitraceInjectionChain", {
        "ProcessId": 7520, "TargetProcessId": 9000,
        "Type": "Write into remote process 9000 followed by thread start/resume"})
    out = reporting._suppress_monitor_injection_artifacts([a], [_LOADER_PROCCREATE], None)
    assert out[0]["in_sample_scope"] is True


def test_child_injection_eid10_pair_suppressed():
    # Monitor child-following: hooked cmd.exe opens its new child (EID 10) and
    # fires the tooling EID 8 (LoadLibraryW VA) into the same child. The EID 10
    # is the same injection's process-open sibling.
    events = [_guardian_meta()]
    eid8 = {
        "event_type": "CreateRemoteThread", "in_sample_scope": False,
        "data": {"SourceProcessId": "7108", "TargetProcessId": "9112",
                 "StartAddress": "0x00007FF90EA8FEE0"},
    }
    eid10 = _alert("sysmon", "ProcessAccess", {
        "SourceImage": "C:\\Windows\\System32\\cmd.exe",
        "TargetImage": "C:\\Windows\\system32\\certutil.exe",
        "SourceProcessId": "7108", "TargetProcessId": "9112",
        "GrantedAccess": "0x1fffff"})
    out = reporting._suppress_monitor_injection_artifacts([eid8, eid10], events, None)
    assert out[0]["in_sample_scope"] is False  # unchanged (already flipped)
    assert out[1]["in_sample_scope"] is False
    assert "child-following" in out[1]["scope_reason"]


def test_unpaired_processaccess_kept():
    # EID 10 with no matching tooling EID 8: real cross-process access.
    events = [_guardian_meta()]
    a = _alert("sysmon", "ProcessAccess", {
        "SourceImage": "C:\\Sandbox\\sample.exe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "SourceProcessId": "7108", "TargetProcessId": "700",
        "GrantedAccess": "0x1fffff"})
    out = reporting._suppress_monitor_injection_artifacts([a], events, None)
    assert out[0]["in_sample_scope"] is True


def test_staging_extension_sigma_suppressed_on_staged_path():
    a = _alert("sigma", "ProcessCreate", {
        "Image": "C:\\Sandbox\\9b3f1e32e9ba2728b53fe615a49540734fa7c95b8d98ead7e1b99952d6c28c7a"})
    a["sigma"] = {"id": "c09dad97-1c78-4f71-b127-7edb2b8e491a",
                  "title": "Execution of Suspicious File Type Extension"}
    ei = {"Path": "C:\\Sandbox\\9b3f1e32e9ba2728b53fe615a49540734fa7c95b8d98ead7e1b99952d6c28c7a"}
    out = reporting._suppress_monitor_injection_artifacts([a], [], ei)
    assert out[0]["in_sample_scope"] is False
    assert "staging" in out[0]["scope_reason"]


def test_staging_extension_sigma_kept_on_other_path():
    # Same rule firing on a DIFFERENT image (e.g. a dropped extensionless
    # payload the sample itself launched): not our staging, stays in scope.
    a = _alert("sigma", "ProcessCreate", {
        "Image": "C:\\Users\\gigi\\AppData\\Local\\Temp\\payload"})
    a["sigma"] = {"id": "c09dad97-1c78-4f71-b127-7edb2b8e491a",
                  "title": "Execution of Suspicious File Type Extension"}
    ei = {"Path": "C:\\Sandbox\\9b3f1e32"}
    out = reporting._suppress_monitor_injection_artifacts([a], [], ei)
    assert out[0]["in_sample_scope"] is True


# ---------------------------------------------------------------------------
# Guardian-marked loader-injection suppression (2026-09-21): after a snapshot
# revert the guest clock boots at the snapshot's save time, so the earliest
# ProcessCreate events (the loader's and the sample's own launch) can fall
# outside the telemetry window -- _tooling_pids() then has nothing to work
# with and the loader's own injection scores as sample behavior (rg.exe
# malicious/45). The guardian/apitrace markers (trace root = first
# __monitor_attached__, GuardianInjectionPlaced targets) identify the same
# injection without any Sysmon ProcessCreate.
# ---------------------------------------------------------------------------

_GUARDIAN_MARK_EVENTS = [
    {"source": "guardian", "event_type": "GuardianInjectionPlaced",
     "data": {"ProcessId": 0, "TargetProcessId": 10764}},
    {"source": "guardian", "event_type": "GuardianInjectionPlaced",
     "data": {"ProcessId": 0, "TargetProcessId": 9180}},
    {"source": "apitrace", "event_type": "ApiCall",
     "data": {"Api": "__monitor_attached__", "ProcessId": 10764}},
    {"source": "apitrace", "event_type": "ApiCall",
     "data": {"Api": "__monitor_attached__", "ProcessId": 9180}},
]


def test_loader_chain_suppressed_without_proccreate():
    # rg.exe regression: no ProcessCreate events at all; actor = trace root
    # (loader), target = guardian-placed pid (the sample child).
    a = _alert("apitrace", "ApitraceInjectionChain", {
        "ProcessId": 10764, "TargetProcessId": 9180,
        "Type": "Write into remote process 9180 followed by thread start/resume"})
    out = reporting._suppress_monitor_injection_artifacts([a], _GUARDIAN_MARK_EVENTS, None)
    assert out[0]["in_sample_scope"] is False
    assert "guardian-marked" in out[0]["scope_reason"]


def test_loader_resume_only_suppressed_without_proccreate():
    # 7za/curl/plink variant: NtResumeThread-only alert carries no start VA,
    # so the LoadLibrary-VA pass cannot catch it -- the markers must.
    a = _alert("apitrace", "ApitraceRemoteThread", {
        "ProcessId": 10764, "TargetProcessId": 9180,
        "Type": "Remote thread resume via NtResumeThread on process 9180"})
    out = reporting._suppress_monitor_injection_artifacts([a], _GUARDIAN_MARK_EVENTS, None)
    assert out[0]["in_sample_scope"] is False


def test_sample_injection_kept_when_actor_not_trace_root():
    # InjectionHarness class: the SAMPLE (a monitored pid, itself placed) is
    # the actor, not the trace root -> real injection, must keep scoring.
    a = _alert("apitrace", "ApitraceInjectionChain", {
        "ProcessId": 9180, "TargetProcessId": 5000,
        "Type": "Write into remote process 5000 followed by thread start/resume"})
    out = reporting._suppress_monitor_injection_artifacts([a], _GUARDIAN_MARK_EVENTS, None)
    assert out[0]["in_sample_scope"] is True


def test_loader_action_on_unplaced_target_kept():
    # Fail-open: trace-root actor but target was never guardian-placed (no
    # marker proof this is our own injection) -> do not suppress.
    a = _alert("apitrace", "ApitraceInjectionChain", {
        "ProcessId": 10764, "TargetProcessId": 4242,
        "Type": "Write into remote process 4242 followed by thread start/resume"})
    out = reporting._suppress_monitor_injection_artifacts([a], _GUARDIAN_MARK_EVENTS, None)
    assert out[0]["in_sample_scope"] is True


def test_dump_yara_interpreter_rules_excluded():
    dumps = {"enabled": True, "items": [{
        "filename": "sample_0000.dmp",
        "yara_matches": [
            {"rule": "suspicious_powershell_download", "tags": []},
            {"rule": "suspicious_cmd_commands", "tags": []},
            {"rule": "suspicious_urls", "tags": []},
        ]}]}
    alerts = heuristics.detect_dump_yara_matches(dumps)
    rules = [a["data"]["Rule"] for a in alerts]
    assert rules == ["suspicious_urls"]  # only the dump-meaningful rule survives
