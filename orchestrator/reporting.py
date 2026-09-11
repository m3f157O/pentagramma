"""Structured JSON report generation."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from orchestrator import behavioral_signatures, cape_engine as cape_engine_mod, heuristics
from orchestrator.config import SandboxConfig
from orchestrator.ioc_summary import build_ioc_summary
from orchestrator.mitre_mapping import enrich_alert, compute_coverage
from orchestrator.pid_lineage import _basename, _parse_sysmon_time, build_pid_lineage, classify_alert_scope
from orchestrator.proctree import build_process_tree
from orchestrator.sigma_engine import SigmaEngine
from orchestrator.verdict import compute_verdict


# Script samples are launched by an interpreter with harness-fixed flags, e.g.
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Sandbox\sample.ps1"
# The root process's ENTIRE command line is therefore the sandbox's, not the
# sample's. So a Sigma rule matching it -- classically "Change PowerShell
# Policies to an Insecure Level" on the -ExecutionPolicy Bypass flag -- is a
# harness artifact that fires on EVERY script sample (benign and malicious
# alike, adding a constant ~medium signal that inflates benign verdicts). We
# drop Sigma matches whose triggering event is that root-launcher process
# creation. Detections on the script's *content* (PowerShell 4104 script-block /
# AMSI) or on any CHILD process the sample spawns keep firing -- a sample that
# itself relaunches with -ExecutionPolicy Bypass is a different (child) PID and
# is still detected.
_LAUNCH_INTERPRETERS = ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "cmd.exe", "mshta.exe")


def _is_root_launcher_proccreate(alert: Dict[str, Any], sample_pid: int) -> bool:
    eid = alert.get("event_id")
    etype = str(alert.get("event_type") or "").lower()
    if not (str(eid) == "1" or etype in ("processcreate", "process_creation")):
        return False
    pid = (alert.get("data") or {}).get("ProcessId", alert.get("ProcessId"))
    try:
        return int(pid) == int(sample_pid)
    except (TypeError, ValueError):
        return False


def _suppress_launcher_artifact_alerts(
    alerts: List[Dict[str, Any]],
    sample_pid: Optional[int],
    execution_info: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Drop Sigma alerts that fire only on the sandbox's own interpreter-launch
    command line (see the note above). No-op for exe/dll samples, whose root
    process IS the sample and whose command line can carry real signal."""
    if sample_pid is None:
        return alerts
    launcher = ((execution_info or {}).get("LauncherPath") or "").lower()
    if not launcher.endswith(_LAUNCH_INTERPRETERS):
        return alerts
    return [a for a in alerts if not (a.get("sigma") and _is_root_launcher_proccreate(a, sample_pid))]


def _tooling_loadlibrary_vas(telemetry_events: List[Dict[str, Any]]) -> set:
    """LoadLibraryW VAs the guardian agent resolved this run (GuardianRegistered
    meta event). The monitor's child-following injects via
    CreateRemoteThread(LoadLibraryW) from the sample's own context (see
    monitor.cpp h_NtCreateUserProcess), so any Sysmon EID 8 whose StartAddress
    equals one of these VAs is sandbox tooling, not sample behavior -- it
    fired from our own DLL inside the sample, into the sample's own child.
    Detection coverage is unaffected: every CreateRemoteThread in the
    detection corpus/harness uses shellcode or ExitProcess start addresses,
    never LoadLibraryW."""
    vas = set()
    for event in telemetry_events:
        if event.get("event_type") != "GuardianRegistered":
            continue
        text = ((event.get("data") or {}).get("Text")) or ""
        for m in re.finditer(r"loadlibrary_(?:x64|x86)=0x([0-9a-fA-F]+)", text):
            va = int(m.group(1), 16)
            if va:
                vas.add(va)
    return vas


# ---------------------------------------------------------------------------
# OS-noise / own-tooling scope-leak suppression
#
# Three observed false-attribution classes (confirmed on benign canary
# d89f08b6, whose ENTIRE 12-point score was these artifacts):
#
#  A. Our own tooling, genuinely in-lineage: the monitor DLL is injected into
#     the sample and its children, so ImageLoad of \SandboxAgent\monitor_*.dll
#     and PipeConnected to \sandbox_apitrace are legitimately in the sample's
#     lineage -- but they are OUR instrumentation, not sample behavior.
#  B. GUID-less alerts pid-adopted from a recycled PID now held by a known OS
#     updater/noise process (e.g. MicrosoftEdgeUpdate.exe self-opens, EID 10
#     carries SourceImage but no SourceProcessGuid).
#  C. GUID-less WMI-ETW alerts from Windows' own Security Center health-probe
#     subscription (LOCAL SERVICE querying AntiVirusProduct/FirewallProduct/
#     AntiSpywareProduct via __InstanceOperationEvent) adopted from a recycled
#     PID. Malware AV-discovery uses `SELECT ... FROM AntiVirusProduct`, not a
#     subscription on instance operations -- the ISA-subscription form is the
#     OS's own.
#
# All flips are scope-only (in_sample_scope=False + scope_reason), never
# deletion -- same "classify, don't hide" contract as the other passes.
# ---------------------------------------------------------------------------

# Known OS updater/noise images whose GUID-less events must never be adopted
# into sample scope (full-path masquerade outside these dirs still scores).
_OS_NOISE_IMAGE_BASENAMES = frozenset({
    "microsoftedgeupdate.exe",
    "onedrivesetup.exe",
    "onedrivestandaloneupdater.exe",
    "compattelrunner.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "tiworker.exe",
    "mousocoreworker.exe",
})

_WMI_HEALTH_PROBE_RE = re.compile(
    r"ISA\s+'(AntiVirusProduct|FirewallProduct|AntiSpywareProduct)'", re.IGNORECASE
)


def _suppress_os_noise_scope_leaks(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for alert in alerts:
        if not alert.get("in_sample_scope"):
            out.append(alert)
            continue
        data = alert.get("data") or {}
        etype = str(alert.get("event_type") or "")
        reason = None

        # A. our own monitor DLL / apitrace pipe inside sample processes
        loaded = str(data.get("ImageLoaded") or "").lower()
        if etype == "ImageLoad" and "\\sandboxagent\\" in loaded:
            reason = "tooling: sandbox monitor DLL loaded into sample process"
        elif etype == "PipeConnected" and str(data.get("PipeName") or "").lower() in (
            "\\sandbox_apitrace", "\\sandbox_guardian",
        ):
            reason = "tooling: sandbox apitrace/guardian pipe"

        # B/C only apply to GUID-less alerts (pid-fallback adoption; the guid
        # path is immune to this class of error by construction).
        elif not (data.get("ProcessGuid") or data.get("SourceProcessGuid")):
            # B. known OS updater/noise image holding a recycled pid
            image = _basename(data.get("SourceImage") or data.get("Image") or data.get("ProcessName"))
            if image and image in _OS_NOISE_IMAGE_BASENAMES:
                reason = f"os-noise: {image} adopted via recycled pid"
            # C. Windows Security Center health-probe WMI subscription
            elif (
                alert.get("source") == "wmi_etw"
                and str(data.get("User") or "").upper().startswith("NT AUTHORITY\\")
                and _WMI_HEALTH_PROBE_RE.search(str(data.get("Query") or ""))
            ):
                reason = "os-noise: Windows Security Center health-probe WMI subscription"

        if reason:
            alert = dict(alert)
            alert["in_sample_scope"] = False
            alert["scope_reason"] = reason
        out.append(alert)
    return out


# ---------------------------------------------------------------------------
# Monitor-injection / staging artifact suppression
#
# Two more tooling classes, confirmed 2026-09-11 by the goodware FP hunt
# (a trivial unsigned hello-world exe scored malicious/42 purely on these):
#
#  D. The monitor loader (C:\SandboxAgent\monitor_loader_x86/x64.exe) launches
#     the sample and injects the hook DLL into it: Sysmon sees EID 10
#     ProcessAccess (0x1fffff) loader->sample, and the behavioral-signature
#     engine synthesizes an ApitraceInjectionChain ("write into remote process
#     + thread start", critical/25) attributed to the LOADER's pid. Both are
#     instrumentation, not sample behavior -- and they fire on EVERY exe/dll
#     sample, padding every verdict. The monitor's child-following injection
#     from a hooked parent's context (cmd.exe -> certutil.exe EID 10) is the
#     same class; it pairs 1:1 with the tooling EID 8 (LoadLibraryW VA)
#     already suppressed by _suppress_tooling_remote_thread_alerts.
#  E. Samples are staged as C:\Sandbox\<sha256> with NO extension, so Sigma
#     rules about suspicious/absent extensions (e.g. "Execution of Suspicious
#     File Type Extension") fire on the root sample process regardless of
#     what the sample is. The extension choice is ours, not the sample's.
#
# Same contract as the other passes: flip in_sample_scope + scope_reason,
# never delete.
# ---------------------------------------------------------------------------

_TOOLING_IMAGE_DIR = "\\sandboxagent\\"

# Sigma rule ids that fire purely on our extensionless staging path. Add ids
# here only with a live-report link proving the match is on the staged name.
_STAGING_ARTIFACT_SIGMA_IDS = frozenset({
    "c09dad97-1c78-4f71-b127-7edb2b8e491a",  # Execution of Suspicious File Type Extension
})


def _tooling_pids(telemetry_events: List[Dict[str, Any]]) -> set:
    """Pids whose ProcessCreate image lives under C:\\SandboxAgent\\ (the
    monitor loaders and any other sandbox tooling)."""
    pids = set()
    for event in telemetry_events:
        if (event.get("event_type") or event.get("EventType")) != "ProcessCreate":
            continue
        data = event.get("data") or {}
        if _TOOLING_IMAGE_DIR not in str(data.get("Image") or "").lower():
            continue
        try:
            pids.add(int(data.get("ProcessId")))
        except (TypeError, ValueError):
            continue
    return pids


def _suppress_monitor_injection_artifacts(
    alerts: List[Dict[str, Any]],
    telemetry_events: List[Dict[str, Any]],
    execution_info: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    tooling_pids = _tooling_pids(telemetry_events)
    vas = _tooling_loadlibrary_vas(telemetry_events)
    # (SourcePid, TargetPid) pairs of the monitor's child-following EID 8s,
    # used to catch the sibling EID 10 (process open) of the same injection.
    tooling_pairs = set()
    if vas:
        for alert in alerts:
            if alert.get("event_type") != "CreateRemoteThread":
                continue
            data = alert.get("data") or {}
            try:
                start = int(str(data.get("StartAddress") or "0"), 16)
            except ValueError:
                continue
            if start not in vas:
                continue
            try:
                tooling_pairs.add((int(data.get("SourceProcessId")), int(data.get("TargetProcessId"))))
            except (TypeError, ValueError):
                continue
    staged_path = str((execution_info or {}).get("Path") or "").lower()

    out = []
    for alert in alerts:
        if not alert.get("in_sample_scope"):
            out.append(alert)
            continue
        data = alert.get("data") or {}
        reason = None

        actor = str(data.get("SourceImage") or "").lower()
        if actor and _TOOLING_IMAGE_DIR in actor:
            # D. action performed BY a sandbox tooling binary (loader -> sample)
            reason = "tooling: monitor loader action on sample"
        elif alert.get("source") == "apitrace" and tooling_pids:
            # D. behavioral signature synthesized from the loader's own
            #    injection API calls
            try:
                _pid = int(data.get("ProcessId"))
            except (TypeError, ValueError):
                _pid = None
            if _pid is not None and _pid in tooling_pids:
                reason = "tooling: monitor loader injection (apitrace)"
        elif alert.get("event_type") == "ProcessAccess" and tooling_pairs:
            # D. EID 10 sibling of a tooling EID 8 child-following injection
            try:
                pair = (int(data.get("SourceProcessId")), int(data.get("TargetProcessId")))
            except (TypeError, ValueError):
                pair = None
            if pair and pair in tooling_pairs:
                reason = "tooling: monitor child-following injection (process open)"

        # E. staging-artifact Sigma rules on the staged sample path
        if reason is None and staged_path:
            sigma = alert.get("sigma") or {}
            if (
                sigma.get("id") in _STAGING_ARTIFACT_SIGMA_IDS
                and str(data.get("Image") or "").lower() == staged_path
            ):
                reason = "tooling: sandbox staging artifact (extensionless hash-named path)"

        if reason:
            alert = dict(alert)
            alert["in_sample_scope"] = False
            alert["scope_reason"] = reason
        out.append(alert)
    return out


def _suppress_tooling_remote_thread_alerts(
    alerts: List[Dict[str, Any]],
    telemetry_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Mark EID 8 CreateRemoteThread alerts whose StartAddress is the per-boot
    kernel32!LoadLibraryW VA as out-of-sample-scope (they are the monitor's
    child-following injections). Keeps the alerts in the report for forensic
    visibility, just unscored. No-op when the guardian agent did not run or
    emitted no VAs (fail-open: filter simply doesn't apply)."""
    vas = _tooling_loadlibrary_vas(telemetry_events)
    if not vas:
        return alerts
    out = []
    for alert in alerts:
        if alert.get("in_sample_scope") and (alert.get("event_type")) == "CreateRemoteThread":
            try:
                start = int(str((alert.get("data") or {}).get("StartAddress") or "0"), 16)
            except ValueError:
                start = 0
            if start in vas:
                alert = dict(alert)
                alert["in_sample_scope"] = False
                alert["scope_reason"] = "tooling: monitor child-following injection (LoadLibraryW StartAddress)"
        out.append(alert)
    return out


def _apitrace_summary(telemetry_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Small monitor/child-following summary for the dashboard: which pids
    had a monitor attached (each `__monitor_attached__` meta event), how many
    API calls each traced pid produced, and whether any volume cap truncated
    the trace. Cheap single pass; reports without apitrace events get
    {"enabled": False} so the UI can hide the feature for older runs.
    """
    attached: List[int] = []
    calls_per_pid: Dict[int, int] = {}
    truncated: List[Dict[str, Any]] = []
    for event in telemetry_events:
        if event.get("source") != "apitrace":
            continue
        data = event.get("data") or {}
        api = data.get("Api")
        pid = data.get("ProcessId")
        if api == "__monitor_attached__":
            if pid is not None and pid not in attached:
                attached.append(pid)
        elif api == "__event_cap_reached__":
            truncated.append({"pid": pid, "api": data.get("Arg0") or "global"})
        elif api and pid is not None:
            calls_per_pid[pid] = calls_per_pid.get(pid, 0) + 1
    if not attached and not calls_per_pid:
        return {"enabled": False}
    return {
        "enabled": True,
        "attached_pids": attached,
        "calls_per_pid": calls_per_pid,
        "truncated": truncated,
    }


_CONFIG_CACHE = None


def _get_config_cached():
    """Module-level config for the detection core (which has no cfg param).
    Same default-path load as everything else; cached so compute_detection
    doesn't re-read YAML per replay."""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is None:
        from orchestrator.config import SandboxConfig
        _CONFIG_CACHE = SandboxConfig()
    return _CONFIG_CACHE


def compute_detection(
    telemetry_events: List[Dict[str, Any]],
    static_analysis: Optional[Dict[str, Any]] = None,
    process_dumps: Optional[Dict[str, Any]] = None,
    dropped_files: Optional[Dict[str, Any]] = None,
    execution_info: Optional[Dict[str, Any]] = None,
    sigma_engine: Optional[SigmaEngine] = None,
) -> Dict[str, Any]:
    """The detection core: telemetry -> alerts (+MITRE, +priority, +scope) ->
    verdict. Extracted from build_report so the offline replay/metrics/
    calibration tooling (scripts/replay_detection.py, detection_metrics.py,
    calibrate_verdict.py) can recompute detections against a saved report's
    telemetry WITHOUT the expensive report-assembly extras that don't affect
    the verdict (pcap/IOC parsing, process tree, coverage matrix). build_report
    calls this too, so there is exactly one alert-assembly path.

    Returns {alerts, verdict, lineage, sample_alert_count, environment_alert_count}.
    """
    alerts = [enrich_alert(event) for event in heuristics.select_alert_events(telemetry_events)]
    alerts += [enrich_alert(burst) for burst in heuristics.detect_bursts(telemetry_events)]
    alerts += [enrich_alert(match) for match in heuristics.detect_dump_yara_matches(process_dumps)]
    alerts += [enrich_alert(match) for match in heuristics.detect_dropped_file_yara_matches(dropped_files)]
    alerts += [enrich_alert(hit) for hit in heuristics.detect_dropped_file_capa_hits(dropped_files)]
    # Sample start time: lets detect_defender_threats tell our own pre-sample
    # AMSI readiness probe (MpTest) apart from a sample that prints the AMSI
    # test string during its run.
    try:
        _dd_sample_pid = int(execution_info.get("ProcessId")) if execution_info else None
    except (TypeError, ValueError):
        _dd_sample_pid = None
    _dd_sample_start = None
    if _dd_sample_pid is not None:
        _dd_launcher = _basename((execution_info or {}).get("LauncherPath"))
        for _ev in telemetry_events:
            if (_ev.get("event_type") or _ev.get("EventType")) != "ProcessCreate":
                continue
            _d = _ev.get("data") or {}
            try:
                if int(_d.get("ProcessId")) != _dd_sample_pid:
                    continue
            except (TypeError, ValueError):
                continue
            if _dd_launcher and _basename(_d.get("Image")) != _dd_launcher:
                continue  # recycled-pid predecessor/successor incarnation
            _ts = _parse_sysmon_time(_d.get("UtcTime") or _ev.get("timestamp"))
            if _ts and (_dd_sample_start is None or _ts < _dd_sample_start):
                _dd_sample_start = _ts
    alerts += [enrich_alert(a) for a in heuristics.detect_defender_threats(telemetry_events, _dd_sample_start)]
    alerts += [enrich_alert(a) for a in behavioral_signatures.detect_behavioral_signatures(telemetry_events)]
    # Sigma matches -- a parallel alert source, already MITRE-enriched internally.
    alerts += sigma_engine.evaluate(telemetry_events) if sigma_engine else []
    # CAPE community signatures over the apitrace stream -- already
    # MITRE/severity-enriched internally (do NOT run through enrich_alert,
    # which would overwrite the per-signature TTP mapping). Lineage is
    # computed here because the engine scopes its behavior summaries to it.
    try:
        _cape_sample_pid = int(execution_info.get("ProcessId")) if execution_info else None
    except (TypeError, ValueError):
        _cape_sample_pid = None
    cape_engine = cape_engine_mod.get_engine(_get_config_cached())
    if cape_engine:
        cape_lineage = build_pid_lineage(telemetry_events, _cape_sample_pid, (execution_info or {}).get("LauncherPath"))
        alerts += cape_engine.evaluate(telemetry_events, cape_lineage)
    # Non-filtering triage hints (adds priority/priority_reason to a subset).
    alerts = heuristics.annotate_priority(alerts)

    # Scope each alert to the sample's own process lineage vs. environment noise.
    try:
        sample_pid = int(execution_info.get("ProcessId")) if execution_info else None
    except (TypeError, ValueError):
        sample_pid = None
    # Strip harness-launch-artifact Sigma matches before scoping/scoring.
    alerts = _suppress_launcher_artifact_alerts(alerts, sample_pid, execution_info)
    lineage = build_pid_lineage(telemetry_events, sample_pid, (execution_info or {}).get("LauncherPath"))
    alerts = classify_alert_scope(alerts, lineage)
    alerts = _suppress_tooling_remote_thread_alerts(alerts, telemetry_events)
    alerts = _suppress_os_noise_scope_leaks(alerts)
    alerts = _suppress_monitor_injection_artifacts(alerts, telemetry_events, execution_info)
    sample_alert_count = sum(1 for a in alerts if a.get("in_sample_scope"))

    verdict = compute_verdict(alerts, static_analysis)
    return {
        "alerts": alerts,
        "verdict": verdict,
        "lineage": lineage,
        "sample_alert_count": sample_alert_count,
        "environment_alert_count": len(alerts) - sample_alert_count,
    }


class ReportGenerator:
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.reports_dir = Path(config.paths["reports_dir"])
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def build_report(
        self,
        analysis_id: str,
        sample_metadata: Dict[str, Any],
        vm_name: str,
        vm_ip: Optional[str],
        runtime_seconds: float,
        telemetry_events: List[Dict[str, Any]],
        static_analysis: Optional[Dict[str, Any]] = None,
        network_capture: Optional[Dict[str, Any]] = None,
        screenshots: Optional[Dict[str, Any]] = None,
        process_dumps: Optional[Dict[str, Any]] = None,
        dropped_files: Optional[Dict[str, Any]] = None,
        execution_info: Optional[Dict[str, Any]] = None,
        status: str = "completed",
        error: Optional[str] = None,
        sigma_engine: Optional[SigmaEngine] = None,
    ) -> Dict[str, Any]:
        """Build the baseline report schema (Phase 1)."""
        now = datetime.now(timezone.utc).isoformat()

        # Aggregate basic counters
        event_counts: Dict[str, int] = {}
        for event in telemetry_events:
            event_type = event.get("EventType") or event.get("event_type") or "unknown"
            event_counts[event_type] = event_counts.get(event_type, 0) + 1

        # Alerts + scope + verdict via the shared detection core (also used by
        # the offline replay/metrics/calibration tooling, so there's one path).
        detection = compute_detection(
            telemetry_events,
            static_analysis=static_analysis,
            process_dumps=process_dumps,
            dropped_files=dropped_files,
            execution_info=execution_info,
            sigma_engine=sigma_engine,
        )
        alerts = detection["alerts"]
        lineage = detection["lineage"]
        verdict = detection["verdict"]
        sample_alert_count = detection["sample_alert_count"]
        environment_alert_count = detection["environment_alert_count"]

        coverage = compute_coverage(telemetry_events, alerts)
        # Widen the ATT&CK coverage matrix with capa's *static* capabilities, so
        # a sample that was detected statically (or barely ran) still shows the
        # techniques capa attributed to it -- surfaced as its own row rather
        # than folded into a dynamic event type.
        capa_result = (static_analysis or {}).get("capa") or {}
        if capa_result.get("available") and capa_result.get("attack"):
            coverage["capa (static capabilities)"] = {
                "count": capa_result.get("capability_count", 0),
                "mitre": capa_result.get("attack", []),
                "source": "static",
            }
        process_tree = build_process_tree(telemetry_events)
        # First time build_report() does file I/O (parses the pcap, if any,
        # via pcap_view) -- deliberate and safe here since build_report() is
        # only ever called once per analysis from executor.py's already
        # multi-minute background run, never from a fast page-load path
        # (unlike NetworkView.render()'s async-not-awaited fetch, which
        # exists specifically to keep a slow capture from blocking page view).
        ioc_summary = build_ioc_summary(
            telemetry_events, network_capture, dropped_files, static_analysis, alerts, lineage
        )

        report = {
            "report_version": "1.0",
            "analysis_id": analysis_id,
            "status": status,
            "error": error,
            "timestamp": now,
            "verdict": verdict,
            "sample": {
                "id": sample_metadata.get("id"),
                "filename": sample_metadata.get("filename"),
                "size": sample_metadata.get("size"),
                "hashes": sample_metadata.get("hashes", {}),
                "tags": sample_metadata.get("tags", []),
                "sample_type": sample_metadata.get("sample_type"),
                "url": sample_metadata.get("url"),
                "url_mode": sample_metadata.get("url_mode"),
            },
            "environment": {
                "vm_name": vm_name,
                "vm_ip": vm_ip,
                "base_vhdx": self.config.hyperv.get("base_vhdx"),
                "runtime_seconds": runtime_seconds,
            },
            "summary": {
                "total_events": len(telemetry_events),
                "event_counts": event_counts,
                "alert_count": len(alerts),
                "sample_alert_count": sample_alert_count,
                "environment_alert_count": environment_alert_count,
            },
            "alerts": alerts,
            "events": telemetry_events,
            "mitre_coverage": coverage,
            "process_tree": process_tree,
            "static_analysis": static_analysis or {},
            "network_capture": network_capture or {"enabled": False},
            "screenshots": screenshots or {"enabled": False},
            "process_dumps": process_dumps or {"enabled": False},
            "dropped_files": dropped_files or {"enabled": False},
            "ioc_summary": ioc_summary,
            "execution_info": execution_info or {},
            "apitrace": _apitrace_summary(telemetry_events),
        }
        return report

    def save_report(self, analysis_id: str, report: Dict[str, Any]) -> Path:
        path = self.reports_dir / f"{analysis_id}.json"
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        # Sidecar one-line summary for the reports-history list: reading 100+
        # tiny sidecars is instant, while parsing 100+ full reports (tens of
        # MB each) froze the list page for minutes.
        try:
            from orchestrator.report_view import summarize_report
            self.save_report_summary(analysis_id, summarize_report(report))
        except Exception:
            pass  # the sidecar is an optimization; never fail a save over it
        return path

    # --- summary sidecar (reports list) ------------------------------------

    def _summary_path(self, analysis_id: str) -> Path:
        return self.reports_dir / f"{analysis_id}.summary.json"

    def save_report_summary(self, analysis_id: str, summary: Dict[str, Any]) -> Path:
        path = self._summary_path(analysis_id)
        path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        return path

    def load_report_summary(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Sidecar summary if present and at least as fresh as the report
        itself; otherwise None (caller falls back to a full parse and should
        backfill the sidecar)."""
        path = self._summary_path(analysis_id)
        report_path = self.reports_dir / f"{analysis_id}.json"
        if not path.exists() or not report_path.exists():
            return None
        if path.stat().st_mtime < report_path.stat().st_mtime:
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    # --- parsed-report cache (interactive endpoints) ------------------------
    # The events/alerts/packets pagers used to re-parse the whole report
    # (tens of MB) on EVERY page click. Interactive browsing hits one report
    # repeatedly, so a tiny mtime-validated cache makes those clicks instant.
    _REPORT_CACHE_MAX = 2
    _report_cache: Dict[str, Any] = {}

    def load_report_cached(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        path = self.reports_dir / f"{analysis_id}.json"
        if not path.exists():
            return None
        mtime = path.stat().st_mtime
        hit = self._report_cache.get(analysis_id)
        if hit and hit[0] == mtime:
            return hit[1]
        report = json.loads(path.read_text(encoding="utf-8"))
        if len(self._report_cache) >= self._REPORT_CACHE_MAX:
            self._report_cache.pop(next(iter(self._report_cache)))
        self._report_cache[analysis_id] = (mtime, report)
        return report

    def load_report(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        path = self.reports_dir / f"{analysis_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
