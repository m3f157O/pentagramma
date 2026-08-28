"""Alert-worthiness heuristics over already-collected telemetry events.

Pure-transform module (no file I/O), mirrors report_view.py's style.
Replaces reporting.py's flat alert_types set-membership check with a
predicate that keeps most existing event types unconditionally alert-worthy
but gates a few noisy ones (ImageLoad/DriverLoad) on signature/path, adds new
conditional gating for ProcessCreate (LOLBin/encoded-command patterns), and
synthesizes burst-detection pseudo-alerts from event sequences.

Synthetic alerts use event_ids 9101/9102, chosen to never collide with real
Sysmon IDs (1-29, 255) or, critically, with 25 (ProcessTampering) -- this
structurally protects scripts/harness_assertions.py and
harness_validation.py::validate_harness_alerts, which key on event_id==25 +
PID + Type substring on entries in report["alerts"].
"""

import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from orchestrator import detectors

# Event types that are alert-worthy regardless of their field values -- either
# already narrow/inherently suspicious (CreateRemoteThread, ProcessTampering),
# already pre-filtered at the Sysmon config level (ProcessAccess's
# GrantedAccess mask), or newly added and inherently rare (FileDelete,
# FileCreateStreamHash, ClipboardChange -- no noise concern like ImageLoad).
# NetworkConnect/DnsQuery were previously uncaptured as alerts despite being
# collected -- verified against 35 real historical reports (~30/~19 events
# per run, stable) before adding, well below ImageLoad's noise threshold.
UNCONDITIONAL_ALERT_TYPES = {
    "CreateRemoteThread",
    "ProcessAccess",
    "ProcessTampering",
    "RawAccessRead",
    "FileDeleteDetected",
    "RegistryCreateDelete",
    "RegistryValueSet",
    "RegistryKeyValueRename",
    "PipeCreated",
    "PipeConnected",
    "WmiEventFilter",
    "WmiEventConsumer",
    "WmiEventConsumerToFilter",
    "FileDelete",
    "FileCreateStreamHash",
    "ClipboardChange",
    "FileCreateTime",
    "ScriptBlockLogged",
    "NetworkConnect",
    "DnsQuery",
}

# AMSI-detection selection (ScanResult >= 16384) was migrated to a declarative
# Sigma rule -- see sigma_rules_custom/amsi_detection.yml.

# Moved from unconditional to conditional in this pass: ~1,300 mostly
# legitimate ImageLoad events per run were drowning out the signal (every
# DLL load became an alert regardless of signature). Gated below on
# signature/path instead.
_CONDITIONAL_LOAD_TYPES = {"ImageLoad", "DriverLoad"}

_STANDARD_LOAD_PATH_PREFIXES = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\program files",
    # Confirmed via a live run: Windows Defender's own signed platform DLLs
    # (e.g. MpOAV.dll, loaded into whatever process it's scanning/hooking --
    # here taskkill.exe, entirely routine AV behavior) live under
    # C:\ProgramData\Microsoft\Windows Defender\Platform\..., not any of the
    # prefixes above, so a validly Microsoft-signed module was flagged
    # "unusual" purely for its path.
    r"c:\programdata",
)

# LOLBin command-line selection was migrated to a declarative Sigma rule --
# see sigma_rules_custom/lolbin_command_line.yml.

# 9102 (mass file modification) retired -- migrated to the Sigma correlation
# rule sigma_rules_custom/mass_file_modification.yml (phase 3).
SYNTHETIC_EVENT_ID_PROCESS_BURST = 9101
SYNTHETIC_EVENT_ID_DUMP_YARA_MATCH = 9103
SYNTHETIC_EVENT_ID_DROPPED_FILE_YARA_MATCH = 9104

SHORT_LIVED_THRESHOLD_SECONDS = 0.5
PROCESS_BURST_WINDOW_SECONDS = 2.0
PROCESS_BURST_MIN_COUNT = 3


def _is_unusual_load(data: Dict[str, Any]) -> bool:
    signed = (data.get("Signed") or "").strip().lower()
    sig_status = (data.get("SignatureStatus") or "").strip().lower()
    if signed != "true" or sig_status != "valid":
        return True
    path = (data.get("ImageLoaded") or "").strip().lower()
    if path and not path.startswith(_STANDARD_LOAD_PATH_PREFIXES):
        return True
    return False


def select_alert_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return the subset of events that should become report alerts."""
    selected = []
    for event in events:
        event_type = event.get("event_type") or event.get("EventType")
        data = event.get("data") or {}

        # NOTE: AMSI-detection and LOLBin-command-line selection were migrated
        # to declarative Sigma rules under sigma_rules_custom/ (amsi_detection.yml,
        # lolbin_command_line.yml) in the phase-2 standardization pass -- they
        # are no longer selected here to avoid double-alerting.
        if event_type in UNCONDITIONAL_ALERT_TYPES:
            selected.append(event)
        elif event_type in _CONDITIONAL_LOAD_TYPES and _is_unusual_load(data):
            selected.append(event)
    return selected


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _detect_process_bursts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flag rapid spawn+exit bursts from the same parent -- a classic
    anti-sandbox recon pattern (whoami/systeminfo/tasklist run and closed
    quickly, checking for analysis artifacts).
    """
    lifetimes: Dict[int, Dict[str, Any]] = {}
    for event in events:
        event_type = event.get("event_type") or event.get("EventType")
        if event_type not in ("ProcessCreate", "ProcessTerminate"):
            continue
        data = event.get("data") or {}
        try:
            pid = int(data.get("ProcessId"))
        except (TypeError, ValueError):
            continue
        entry = lifetimes.setdefault(pid, {})
        ts = _parse_iso(event.get("timestamp") or data.get("UtcTime"))
        if event_type == "ProcessCreate":
            entry["start"] = ts
            entry["ppid"] = data.get("ParentProcessId")
        else:
            entry["end"] = ts

    by_parent: Dict[str, List[Tuple[int, datetime]]] = defaultdict(list)
    for pid, info in lifetimes.items():
        start, end, ppid = info.get("start"), info.get("end"), info.get("ppid")
        if start is None or end is None or not ppid:
            continue
        lifetime = (end - start).total_seconds()
        if 0 <= lifetime <= SHORT_LIVED_THRESHOLD_SECONDS:
            by_parent[ppid].append((pid, start))

    alerts = []
    for ppid, children in by_parent.items():
        children.sort(key=lambda c: c[1])
        window = _densest_window([c[1] for c in children], PROCESS_BURST_WINDOW_SECONDS)
        if window is None:
            continue
        i, j, count = window
        if count < PROCESS_BURST_MIN_COUNT:
            continue
        window_pids = [c[0] for c in children[i : j + 1]]
        last_ts = children[j][1]
        alerts.append(
            {
                "source": "heuristic",
                "provider_name": "SandboxHeuristics",
                "event_id": SYNTHETIC_EVENT_ID_PROCESS_BURST,
                "event_type": "ProcessBurstDetected",
                "timestamp": last_ts.isoformat(),
                "data": {
                    "UtcTime": last_ts.isoformat(),
                    "ProcessId": str(ppid),
                    "Type": f"{count} short-lived child processes spawned within {PROCESS_BURST_WINDOW_SECONDS}s",
                    "ChildProcessIds": window_pids,
                },
            }
        )
    return alerts


def _densest_window(
    timestamps: List[datetime], window_seconds: float
) -> Optional[Tuple[int, int, int]]:
    """Given timestamps sorted ascending, find the (start_index, end_index,
    count) of the densest window of width window_seconds. A plain sliding
    window that stops at the first threshold crossing would under-report the
    true peak count if the burst continues past that point.
    """
    if not timestamps:
        return None
    i = 0
    best: Optional[Tuple[int, int, int]] = None
    for j in range(len(timestamps)):
        while (timestamps[j] - timestamps[i]).total_seconds() > window_seconds:
            i += 1
        count = j - i + 1
        if best is None or count > best[2]:
            best = (i, j, count)
    return best


def detect_dump_yara_matches(process_dumps: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Synthesize one alert per YARA rule match found in a re-scanned
    process memory dump -- the payoff for periodic "passive" dynamic
    unpacking (see executor.py): a packed sample's on-disk static scan can
    miss signatures only visible once unpacked in memory. Unlike the burst
    detectors above, the input here is the already-assembled process_dumps
    report dict (produced post-execution in executor.py), not raw
    telemetry events -- there's no natural per-event timestamp for a
    static rescan, so timestamp is left unset.
    """
    if not process_dumps or not process_dumps.get("enabled"):
        return []
    alerts = []
    for item in process_dumps.get("items") or []:
        for match in item.get("yara_matches") or []:
            if "error" in match:
                continue
            rule = match.get("rule")
            filename = item.get("filename")
            alerts.append(
                {
                    "source": "heuristic",
                    "provider_name": "SandboxHeuristics",
                    "event_id": SYNTHETIC_EVENT_ID_DUMP_YARA_MATCH,
                    "event_type": "DmpYaraMatch",
                    "timestamp": None,
                    # No natural per-alert PID to infer scope from (see
                    # orchestrator/pid_lineage.py::classify_alert_scope) --
                    # process_dumps is already scoped to the sample's own
                    # process by executor.py, so this is sample-attributed
                    # by construction, not inference.
                    "in_sample_scope": True,
                    "data": {
                        "Rule": rule,
                        "Tags": match.get("tags"),
                        "DumpFilename": filename,
                        "Type": f"YARA rule '{rule}' matched in memory dump {filename}",
                    },
                }
            )
    return alerts


def detect_dropped_file_yara_matches(dropped_files: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Synthesize one alert per YARA rule match found in a file the sample
    dropped during execution and retrieved (see executor.py). Same shape
    and reasoning as detect_dump_yara_matches() -- no natural per-event
    timestamp for a static rescan, so timestamp is left unset.
    """
    if not dropped_files or not dropped_files.get("enabled"):
        return []
    alerts = []
    for item in dropped_files.get("items") or []:
        for match in item.get("yara_matches") or []:
            if "error" in match:
                continue
            rule = match.get("rule")
            filename = item.get("filename")
            alerts.append(
                {
                    "source": "heuristic",
                    "provider_name": "SandboxHeuristics",
                    "event_id": SYNTHETIC_EVENT_ID_DROPPED_FILE_YARA_MATCH,
                    "event_type": "DroppedFileYaraMatch",
                    "timestamp": None,
                    # dropped_files entries are already scoped to the
                    # sample's own process lineage by
                    # executor.py::_select_dropped_files -- sample-attributed
                    # by construction, see detect_dump_yara_matches() above.
                    "in_sample_scope": True,
                    "data": {
                        "Rule": rule,
                        "Tags": match.get("tags"),
                        "DroppedFilename": filename,
                        "OriginalPath": item.get("original_path"),
                        "Type": f"YARA rule '{rule}' matched in dropped file {filename}",
                    },
                }
            )
    return alerts


def detect_defender_threats(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One alert per distinct Microsoft Defender threat detection (EID 1116).

    Defender is an active sensor in this sandbox (it also backs the AMSI
    detection family). When its real-time engine catches and terminates a
    sample before our own instrumentation can observe the behavior -- e.g. a
    certutil download cradle killed before Sysmon logs ProcessCreate, so the
    LOLBin Sigma rule never gets a command line to match (confirmed
    2026-07-04) -- the threat is still recorded here. Surfacing it turns a
    signal we already collect but discarded into a first-class detection.

    Marked in_sample_scope=True by construction, same rationale as
    detect_dump_yara_matches(): the VM is a clean restored snapshot running
    only the sample, so any Defender detection during the run is the sample's,
    and the event carries no ProcessId to infer scope from anyway (Process Name
    is "Unknown"; the offending command line is in the Path field).
    """
    alerts: List[Dict[str, Any]] = []
    seen = set()
    for event in events:
        if (event.get("event_type") or event.get("EventType")) != "DefenderThreatDetected":
            continue
        data = event.get("data") or {}
        key = (data.get("Threat Name"), data.get("Path"))
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            {
                "source": event.get("source") or "windefend",
                "provider_name": event.get("provider_name") or "Microsoft-Windows-Windows Defender",
                "event_id": event.get("event_id"),
                "event_type": "DefenderThreatDetected",
                "timestamp": event.get("timestamp"),
                "in_sample_scope": True,
                "data": data,
            }
        )
    return alerts


def detect_bursts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Synthesize pseudo-alerts for behavioral patterns spanning multiple
    events (bursts), which select_alert_events's per-event predicate can't see.

    Mass-file-modification was migrated to a declarative Sigma event_count
    correlation rule (sigma_rules_custom/mass_file_modification.yml) in the
    phase-3 standardization pass. ProcessBurst stays here on purpose: its
    trigger is a *short-lived* process -- a ProcessCreate paired with a
    ProcessTerminate < 0.5s later for the SAME process -- which a single-type
    event_count correlation can't express (it would need to correlate two
    different event types about the same entity and measure their gap).
    """
    return _detect_process_bursts(events)


# ---------------------------------------------------------------------------
# Priority annotation -- non-filtering triage hints for registry/pipe alerts.
#
# Unlike ImageLoad/DriverLoad (gated conditionally in select_alert_events,
# because signed+standard-path is a near-complete negative signal), registry
# keys and pipe names have no equivalent universal "definitely benign" test --
# the high-value-key/known-tool-pipe surface is open-ended and keeps growing,
# so gating alerts on a curated list would risk silently dropping real
# persistence not on the list. RegistryCreateDelete/RegistryValueSet/
# RegistryKeyValueRename/PipeCreated/PipeConnected stay unconditionally
# alert-worthy (see UNCONDITIONAL_ALERT_TYPES above); this only ever ADDS a
# priority/priority_reason hint for triage, never removes an alert.
#
# Patterns below are sourced from real SigmaHQ detection rules (not
# reconstructed from memory) and cross-referenced against MITRE ATT&CK
# technique pages.
# ---------------------------------------------------------------------------

_REGISTRY_EVENT_TYPES = {"RegistryCreateDelete", "RegistryValueSet", "RegistryKeyValueRename"}
_PIPE_EVENT_TYPES = {"PipeCreated", "PipeConnected"}

# (required substrings, all case-insensitive and all must match; reason)
_REGISTRY_PRIORITY_RULES: List[Tuple[List[str], str]] = [
    (["\\currentversion\\run"], "Run/RunOnce/RunServices autostart key (T1547.001)"),
    (["\\winlogon\\shell"], "Winlogon Shell persistence (T1547.004)"),
    (["\\winlogon\\userinit"], "Winlogon Userinit persistence (T1547.004)"),
    (["\\winlogon\\notify"], "Winlogon Notify persistence (T1547.004)"),
    (["\\image file execution options\\"], "Image File Execution Options / debugger hijack (T1546.012)"),
    (["appinit_dlls"], "AppInit_DLLs persistence (T1546.010)"),
    (["\\control\\lsa\\security packages"], "LSA Security Package persistence (T1547.005)"),
    (["\\control\\lsa\\authentication packages"], "LSA Authentication Package persistence (T1547.005)"),
    (["\\control\\lsa\\notification packages"], "LSA Notification Package persistence (T1547.005)"),
    (["\\clsid\\", "\\inprocserver32"], "COM CLSID hijacking (T1546.015)"),
    (["\\clsid\\", "\\treatas"], "COM CLSID hijacking (T1546.015)"),
    (["\\services\\", "\\imagepath"], "Service ImagePath modification (T1543.003/T1574.011)"),
    (["\\services\\", "\\servicedll"], "Service ServiceDLL hijack (T1543.003/T1574.011)"),
    (["windows defender", "disablerealtimemonitoring"], "Defender tamper (T1562.001)"),
    (["windows defender", "disableantispyware"], "Defender tamper (T1562.001)"),
    (["windows defender", "disablebehaviormonitoring"], "Defender tamper (T1562.001)"),
    (["windows defender", "\\exclusions\\"], "Defender exclusion added (T1562.001)"),
    (["active setup\\installed components", "\\stubpath"], "Active Setup StubPath persistence (T1112)"),
]

# Simple substring matches, sourced from SigmaHQ's PsExec/PAExec/RemCom pipe
# rules and the "clean" (exclusion-free) Cobalt Strike default-pipe rule --
# deliberately not the broader CS rule, whose patterns overlap legitimate
# Windows RPC pipe names and only work paired with allow-list exclusions this
# module doesn't implement.
_PIPE_SUBSTRING_RULES: List[Tuple[str, str]] = [
    ("\\psexesvc", "PsExec default service pipe name (T1569.002)"),
    ("\\paexec", "PAExec default pipe name (T1569.002)"),
    ("\\remcom", "RemCom default pipe name (T1021.002)"),
    ("\\msagent_", "Cobalt Strike default pipe pattern"),
    ("\\postex_", "Cobalt Strike default pipe pattern"),
    ("\\status_", "Cobalt Strike default pipe pattern"),
    ("\\mojo_", "Cobalt Strike default pipe pattern"),
    ("\\interprocess_", "Cobalt Strike default pipe pattern"),
    ("\\samr_", "Cobalt Strike default pipe pattern"),
    ("\\netlogon_", "Cobalt Strike default pipe pattern"),
    ("\\srvsvc_", "Cobalt Strike default pipe pattern"),
    ("\\lsarpc_", "Cobalt Strike default pipe pattern"),
    ("\\wkssvc_", "Cobalt Strike default pipe pattern"),
]

_PIPE_REGEX_RULES: List[Tuple["re.Pattern[str]", str]] = [
    (re.compile(r"\\msse-.*-server"), "Cobalt Strike default pipe pattern"),
    (re.compile(r"\\winsock2\\catalogchangelistener-.*-0,"), "Cobalt Strike default pipe pattern"),
]


def _registry_priority_reason(data: Dict[str, Any]) -> Optional[str]:
    target = (data.get("TargetObject") or "").lower()
    if target:
        for required, reason in _REGISTRY_PRIORITY_RULES:
            if all(r in target for r in required):
                return reason
    # (A former fallback flagged registry value *data* matching the LOLBin
    # command pattern; that pattern moved to sigma_rules_custom/lolbin_command_line.yml
    # in the phase-2 migration, so the check -- and its now-deleted helper -- were
    # dropped here. Autostart keys carrying an encoded command are still caught by
    # the persistence patterns above.)
    return None


def _pipe_priority_reason(data: Dict[str, Any]) -> Optional[str]:
    pipe_name = (data.get("PipeName") or "").lower()
    if not pipe_name:
        return None
    for substring, reason in _PIPE_SUBSTRING_RULES:
        if substring in pipe_name:
            return reason
    for pattern, reason in _PIPE_REGEX_RULES:
        if pattern.search(pipe_name):
            return reason
    return None


def annotate_priority(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Tag registry/pipe alerts matching a known-sensitive pattern with
    priority="high" + priority_reason, purely for triage. Never filters --
    every input alert is returned, unchanged except for these two added keys
    on a subset -- so this cannot affect scripts/harness_assertions.py or
    harness_validation.py::validate_harness_alerts (both only ever read
    event_id/data.ProcessId/data.Type off report["alerts"]).
    """
    annotated = []
    for alert in alerts:
        event_type = alert.get("event_type") or alert.get("EventType")
        data = alert.get("data") or {}
        reason = None
        if event_type in _REGISTRY_EVENT_TYPES:
            reason = _registry_priority_reason(data)
        elif event_type in _PIPE_EVENT_TYPES:
            reason = _pipe_priority_reason(data)
        if reason:
            alert = dict(alert)
            alert["priority"] = "high"
            alert["priority_reason"] = reason
        annotated.append(alert)
    return annotated


def describe_detectors() -> List[Dict[str, Any]]:
    """Declarative inventory of the hardcoded (non-Sigma, non-YARA) detectors
    in this module, in the standardized detector schema (id/family/severity/
    kind/mitre/detail -- see orchestrator/detectors.py). Derived from the
    module's own constants so it can't drift far from the actual logic; the
    logic itself stays imperative (Phase 1 standardizes the interface, not the
    implementation).
    """
    return [
        {
            "id": "heuristic.alert-worthy-event-types",
            "family": detectors.FAMILY_HEURISTIC,
            "name": "Alert-worthy event types",
            "severity": "medium",
            "kind": "event-selection",
            "mitre": [],
            "description": (
                "Emits an alert for any telemetry event of an inherently "
                "suspicious/narrow type (injection, process access, registry "
                "persistence, named pipes, WMI persistence, file delete, "
                "clipboard, script-block, network/DNS, etc.)."
            ),
            "detail": sorted(UNCONDITIONAL_ALERT_TYPES),
        },
        {
            "id": "heuristic.unusual-module-load",
            "family": detectors.FAMILY_HEURISTIC,
            "name": "Unusual module/driver load",
            "severity": "medium",
            "kind": "conditional",
            "mitre": ["T1574"],
            "description": (
                "ImageLoad/DriverLoad events are alerted only when the loaded "
                "module is unsigned or loads from a non-standard path (routine "
                "signed system DLLs are ignored to avoid ~1000s of alerts/run)."
            ),
            "detail": sorted(_CONDITIONAL_LOAD_TYPES),
        },
        {
            "id": "heuristic.process-burst",
            "family": detectors.FAMILY_HEURISTIC,
            "name": "Process burst",
            "severity": "medium",
            "kind": "sequence",
            "mitre": [],
            "description": (
                f"Synthetic alert when >= {PROCESS_BURST_MIN_COUNT} short-lived child "
                f"processes are spawned within {PROCESS_BURST_WINDOW_SECONDS}s "
                "(rapid process churn)."
            ),
            "detail": ["ProcessBurstDetected"],
        },
        {
            "id": "heuristic.priority-annotation",
            "family": detectors.FAMILY_HEURISTIC,
            "name": "Priority triage annotation",
            "severity": "informational",
            "kind": "annotation",
            "mitre": ["T1547", "T1543"],
            "description": (
                "Not a separate alert -- flags registry-persistence keys "
                "(Run keys, services, etc.) and known-sensitive named pipes as "
                "priority=high on existing alerts, as a triage hint."
            ),
            "detail": sorted(_REGISTRY_EVENT_TYPES | _PIPE_EVENT_TYPES),
        },
    ]
