"""Behavioral signatures over argument-level API-trace events.

Track 3.3: the MinHook monitor (`agent/windows/monitor_src/`) injects into the
sample and streams every hooked API call as a newline-delimited JSON event.
This module turns those low-level events into high-level alerts using
presence/sequence patterns that Sysmon (and the infeasible ETW-TI provider)
cannot reliably surface, especially for reflective/direct-syscall injection
chains.

Design constraints inherited from the monitor's volume controls:
  - Signatures key off *presence* and short temporal/actor correlation, never
    exact event counts (dup-collapsing and per-API caps make counts lossy).
  - Argument detail is packed into the single string field `data.Arg0`; we
    parse the `key=value` form used by memory/injection APIs.
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from orchestrator import detectors

# Synthetic event IDs. 9200 is the raw apitrace event ID used by the guest
# telemetry collector; 9201+ are the behavioral alerts derived from them.
APITRACE_EVENT_ID = 9200
APITRACE_CHAIN_EVENT_ID = 9201
APITRACE_CROSS_PROCESS_WRITE_EVENT_ID = 9202
APITRACE_EXEC_PROTECTION_EVENT_ID = 9203
APITRACE_REMOTE_THREAD_EVENT_ID = 9204
APITRACE_REFLECTIVE_LOAD_EVENT_ID = 9205
APITRACE_TRUNCATED_EVENT_ID = 9206
APITRACE_ANTI_SANDBOX_TIMING_EVENT_ID = 9207
APITRACE_CRYPTO_BURST_EVENT_ID = 9208
APITRACE_TOKEN_MANIPULATION_EVENT_ID = 9209
APITRACE_ANTI_DEBUG_EVENT_ID = 9210
APITRACE_CROSS_PROCESS_READ_EVENT_ID = 9211
APITRACE_ANTI_TAMPER_EVENT_ID = 9212
APITRACE_TRANSACTION_ABUSE_EVENT_ID = 9213
APITRACE_PPID_SPOOF_EVENT_ID = 9214
APITRACE_BLIND_SPOT_EVENT_ID = 9215
APITRACE_SILENCE_EVENT_ID = 9216

# SandboxGuard kernel guardian (agent/windows/guardian_agent.py drains the
# driver ring; telemetry source "guardian"). 9400/9404 are informational
# (unavailable / injection placed) and never alert; the rest map 1:1.
GUARDIAN_SOURCE = "guardian"
GUARDIAN_PROTECTED_ACCESS_EVENT_ID = 9401
GUARDIAN_PROTECTED_REGISTRY_EVENT_ID = 9402
GUARDIAN_MODULE_REMAP_EVENT_ID = 9403
GUARDIAN_INJECTION_FAILED_EVENT_ID = 9405

_GUARDIAN_ALERT_SPECS = {
    GUARDIAN_PROTECTED_ACCESS_EVENT_ID: "GuardianProtectedAccess",
    GUARDIAN_PROTECTED_REGISTRY_EVENT_ID: "GuardianProtectedRegistry",
    GUARDIAN_MODULE_REMAP_EVENT_ID: "GuardianModuleRemap",
    GUARDIAN_INJECTION_FAILED_EVENT_ID: "GuardianInjectionFailed",
}

# APIs treated as allocation/map events (base + Ex variants, so malware
# using the newer entry points can't slip past the memory signatures).
_ALLOC_MAP_APIS = ("NtAllocateVirtualMemory", "NtMapViewOfSection", "NtAllocateVirtualMemoryEx", "NtMapViewOfSectionEx")
_UNMAP_APIS = ("NtUnmapViewOfSection", "NtUnmapViewOfSectionEx")
_THREAD_FINISH_APIS = ("NtCreateThreadEx", "NtQueueApcThread", "NtSetContextThread", "NtQueueApcThreadEx")

APITRACE_SOURCE = "apitrace"
APITRACE_EVENT_TYPE = "ApiCall"

# Threshold for RWX-allocation noise (e.g. .NET JIT legitimately allocates
# executable pages). A packed/self-modifying sample typically produces many
# such allocations; a benign .NET binary usually stays under this.
# Measured on benign runs: the x86 CLR JIT produced 18 RWX allocs on a
# trivial powershell, and the x64 guest CLR (powershell 5.1 + AMSI) reached
# 62 -- so the bar sits at 100 with ~60% headroom over the worst measured
# benign runtime.
EXECUTABLE_ALLOCATION_THRESHOLD = 100

# Anti-sandbox timing: timing-source polls that survive the monitor's dedup
# ring represent ~1/sec each, so a handful already means persistent polling.
# Long relative delays are the sleep-out-the-sandbox tell.
# NOTE: the pure polling arm (lifetime count, then burst-window) was REMOVED
# after two measured benign FPs (2026-08-17, dressed image): the CLR/powershell
# runtime polls NtQuerySystemTime in a tight startup burst (~12 in 0.3s) and
# accumulates 15+ over a long lifetime, so no count/rate threshold separates
# it from evasion loops. Polling now only matters in combination with a long
# non-alertable delay (time-acceleration check arm below).
LONG_DELAY_MS = 10000
VERY_LONG_DELAY_MS = 60000
# Garbage guard: above this the value is an overflow artifact, not a sleep
# (the monitor clamps, but old traces may carry garbage).
MAX_PLAUSIBLE_DELAY_MS = 24 * 3600 * 1000

# Crypto burst: bulk encrypt/decrypt operations from one actor. Hashing is
# deliberately excluded (TLS/.NET hash constantly); the monitor's per-API cap
# (1000) bounds the raw count, so the threshold sits far below it.
CRYPTO_BURST_THRESHOLD = 25

# Load-path markers for the reflective-load signature: user-writable
# directories and UNC paths. System32/SysWOW64/WinSxS/Program Files loads are
# routine and excluded. Our own child-injected monitor DLL is excluded by
# name (it loads from the guest agent directory on every run).
_SUSPICIOUS_LOAD_MARKERS = (
    "\\users\\", "\\programdata\\", "\\temp\\", "\\tmp\\",
    "\\downloads\\", "\\desktop\\", "\\public\\", "\\appdata\\",
)
# System-vendor dirs that sit under otherwise-suspicious roots: Defender's own
# platform DLLs (MpOav/MPCLIENT) load from ProgramData\Microsoft into EVERY
# powershell (AMSI provider), which FP'd the signature on a benign ps1.
_SUSPICIOUS_LOAD_EXCLUSIONS = ("\\programdata\\microsoft\\",)
_MONITOR_DLL_NAMES = ("monitor_x64.dll", "monitor_x86.dll")

# Max number of example Arg0 strings kept in an alert for analyst visibility.
_MAX_EVIDENCE_SAMPLES = 5

# WS-B runtime blind-spot detectors (apitrace<->Sysmon cross-correlation, map
# curated in orchestrator/data/coverage_map.yaml). A Sysmon event whose EID is
# a `both`-class hook's counterpart must have a same-pid apitrace event with a
# counterpart API inside this window, or the hook is suspected blind.
BLINDSPOT_WINDOW_SECONDS = 2
# One-off misses are collector-drain artifacts; genuine unhooking removes the
# hook for the rest of the run and misses REPEATEDLY. Require 2+.
BLINDSPOT_MIN_MISSES = 2
# __wow64_follow__ marks the gap while the monitor re-injects into a spawned
# 32-bit child -- hooks are legitimately not yet placed, so suppress nearby.
WOW64_FOLLOW_SUPPRESS_SECONDS = 5
# EID 7 grace after __monitor_attached__: process-init image loads (the exe,
# ntdll, static imports) are mapped by the kernel loader WITHOUT calling
# LdrLoadDll, and the burst straddles hook placement, so an immediate ImageLoad
# with no LdrLoadDll counterpart is routine, not a blind hook.
IMAGE_LOAD_GRACE_SECONDS = 5
# Kernel-side registry bookkeeping attributed to the process but never
# performed via a user-mode NtSetValueKey: BAM/DAM activity records, written
# by the kernel at process exit (Sysmon EID 13 still reports them).
_KERNEL_REGISTRY_PREFIXES = ("\\services\\bam\\", "\\services\\dam\\")
# Telemetry silence: a traced pid that stops producing dual-covered API events
# while Sysmon still sees it active. Thresholds guard against short/quiet runs.
SILENCE_MIN_APITRACE_EVENTS = 5
SILENCE_MIN_SYSMON_EVENTS = 8
SILENCE_MIN_SPAN_SECONDS = 10

# Machine form of the curated coverage map, generated by
# scripts/build_coverage_table.py. Lazy-loaded once; if the file is missing
# (offline replay of an old report tree, partial checkout) the blind-spot
# detectors no-op instead of failing the whole detection pass.
_COVERAGE_MAP_PATH = Path(__file__).resolve().parent / "data" / "coverage_map.json"
_COVERAGE_MAP_CACHE: Optional[Dict[str, Any]] = None


def _load_coverage_map() -> Dict[str, Any]:
    global _COVERAGE_MAP_CACHE
    if _COVERAGE_MAP_CACHE is None:
        try:
            _COVERAGE_MAP_CACHE = json.loads(_COVERAGE_MAP_PATH.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            _COVERAGE_MAP_CACHE = {}
    return _COVERAGE_MAP_CACHE


def _safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_kv(arg0: Any) -> Dict[str, str]:
    """Parse the `key=value` Arg0 strings emitted by the monitor.

    Memory/injection APIs use space-separated `k=v` pairs, e.g.
      target_pid=8636 size=4096 protect=0x4 executable=0 cross_process=0
    File/process/registry APIs store plain strings (paths, commands, value
    names) and are returned under the synthetic key `_raw`.
    """
    text = arg0 if isinstance(arg0, str) else str(arg0 or "")
    out: Dict[str, str] = {}
    # Look for at least one 'key=value' token. Mixed content falls back to raw.
    pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)", text)
    if pairs:
        for k, v in pairs:
            out[k] = v
    if not out:
        out["_raw"] = text
    return out


def _apitrace_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Raw apitrace events that have enough structure to be useful."""
    selected = []
    for event in events:
        if event.get("source") != APITRACE_SOURCE:
            continue
        if event.get("event_id") != APITRACE_EVENT_ID:
            continue
        if event.get("event_type") != APITRACE_EVENT_TYPE:
            continue
        data = event.get("data") or {}
        if not data.get("Api"):
            continue
        selected.append(event)
    return selected


def _actor_pid(event: Dict[str, Any]) -> Optional[int]:
    return _safe_int((event.get("data") or {}).get("ProcessId"))


def _kv_int(kv: Dict[str, str], key: str) -> Optional[int]:
    return _safe_int(kv.get(key))


def _kv_bool(kv: Dict[str, str], key: str) -> bool:
    val = kv.get(key, "")
    if val == "1":
        return True
    if val == "0":
        return False
    # For hex flags like protect=0x20 we treat any non-zero value as truthy.
    try:
        return bool(int(val, 0))
    except (TypeError, ValueError):
        return False


def _is_executable_protect(kv: Dict[str, str]) -> bool:
    """`executable=1` iff protect & 0xF0 (any PAGE_EXECUTE* bit)."""
    return _kv_bool(kv, "executable")


def _target_pid(event: Dict[str, Any]) -> Optional[int]:
    """Memory/injection APIs embed the target pid in Arg0."""
    arg0 = (event.get("data") or {}).get("Arg0", "")
    kv = _parse_kv(arg0)
    return _kv_int(kv, "target_pid")


def _event_timestamp(event: Dict[str, Any]) -> str:
    ts = event.get("timestamp") or ""
    if not ts:
        data = event.get("data") or {}
        ts = data.get("UtcTime") or ""
    return ts


def _collect_evidence(events: Iterable[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """Return (apis, arg0_samples) for an alert, capped for size."""
    apis: List[str] = []
    seen_api: Set[str] = set()
    samples: List[str] = []
    for ev in events:
        api = (ev.get("data") or {}).get("Api")
        if api and api not in seen_api:
            apis.append(api)
            seen_api.add(api)
        if len(samples) < _MAX_EVIDENCE_SAMPLES:
            arg0 = (ev.get("data") or {}).get("Arg0", "")
            if arg0 and (not samples or arg0 != samples[-1]):
                samples.append(str(arg0))
    return apis, samples


def _build_alert(
    event_id: int,
    event_type: str,
    actor_pid: int,
    target_pid: Optional[int],
    evidence_events: List[Dict[str, Any]],
    detail: str,
) -> Dict[str, Any]:
    apis, samples = _collect_evidence(evidence_events)
    ts = _event_timestamp(evidence_events[-1]) if evidence_events else ""
    data: Dict[str, Any] = {
        "UtcTime": ts,
        "ProcessId": actor_pid,
        "Type": detail,
        "EvidenceApis": apis,
        "Evidence": samples,
    }
    if target_pid is not None:
        data["TargetProcessId"] = target_pid
    return {
        "source": APITRACE_SOURCE,
        "provider_name": "BehavioralSignatures",
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": ts,
        "data": data,
    }


# ---------------------------------------------------------------------------
# Signature producers
# ---------------------------------------------------------------------------


def _detect_injection_chains(
    events: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Set[Tuple[int, int]]]:
    """Cross-process write + thread start/resume on the same target.

    Returns alerts plus the set of (actor_pid, target_pid) pairs already
    covered so downstream cross-process-write/remote-thread producers can
    dedupe.
    """
    by_actor: Dict[int, Dict[int, Dict[str, List[Dict[str, Any]]]]] = defaultdict(
        lambda: defaultdict(lambda: {"write": [], "thread": [], "resume": [], "alloc_map": [], "unmap": []})
    )

    for event in events:
        actor = _actor_pid(event)
        if actor is None:
            continue
        api = (event.get("data") or {}).get("Api", "")
        target = _target_pid(event)
        if target is None:
            continue
        bucket = by_actor[actor][target]
        if api == "NtWriteVirtualMemory":
            bucket["write"].append(event)
        elif api in _THREAD_FINISH_APIS:
            # APC-queue and context-set finish the chain just as a thread
            # create does -- and Sysmon can't see either.
            bucket["thread"].append(event)
        elif api == "NtResumeThread":
            bucket["resume"].append(event)
        elif api in _UNMAP_APIS:
            kv = _parse_kv((event.get("data") or {}).get("Arg0", ""))
            if _kv_bool(kv, "cross_process"):
                # Hollowing step 1: gutting the victim's mapped image.
                bucket["unmap"].append(event)
        elif api in _ALLOC_MAP_APIS:
            kv = _parse_kv((event.get("data") or {}).get("Arg0", ""))
            if _kv_bool(kv, "cross_process"):
                bucket["alloc_map"].append(event)

    alerts: List[Dict[str, Any]] = []
    covered: Set[Tuple[int, int]] = set()
    for actor, targets in by_actor.items():
        for target, bucket in targets.items():
            has_write = bool(bucket["write"])
            has_thread_start = bool(bucket["thread"]) or bool(bucket["resume"])
            has_unmap = bool(bucket["unmap"])
            # Classic chain: write + thread start/resume. Hollowing variant:
            # image unmap + (write OR thread start) -- the gutting is itself
            # the tell, the resume may come much later.
            if (has_write and has_thread_start) or (has_unmap and (has_write or has_thread_start)):
                evidence = (
                    bucket["unmap"][:1]
                    + bucket["write"][:1]
                    + (bucket["thread"][:1] if bucket["thread"] else [])
                    + (bucket["resume"][:1] if bucket["resume"] else [])
                )
                if has_unmap:
                    detail = f"Process hollowing into {target}: image unmapped, then written/started"
                else:
                    detail = f"Write into remote process {target} followed by thread start/resume"
                alerts.append(
                    _build_alert(
                        APITRACE_CHAIN_EVENT_ID,
                        "ApitraceInjectionChain",
                        actor,
                        target,
                        evidence,
                        detail,
                    )
                )
                covered.add((actor, target))
    return alerts, covered


def _child_pids_by_actor(events: List[Dict[str, Any]]) -> Dict[int, Set[int]]:
    """actor pid -> pids of children it created (NtCreateUserProcess events)."""
    children: Dict[int, Set[int]] = defaultdict(set)
    for event in events:
        if (event.get("data") or {}).get("Api") != "NtCreateUserProcess":
            continue
        actor = _actor_pid(event)
        kv = _parse_kv((event.get("data") or {}).get("Arg0", ""))
        child = _kv_int(kv, "child_pid")
        if actor is not None and child:
            children[actor].add(child)
    return children


def _detect_cross_process_writes(
    events: List[Dict[str, Any]],
    covered: Set[Tuple[int, int]],
    children: Dict[int, Set[int]],
) -> List[Dict[str, Any]]:
    """NtWriteVirtualMemory without the full chain -- still a strong signal.

    Writes into the actor's OWN just-created child are excluded: kernel32's
    CreateProcess path writes the process-parameter block into every new
    child, so benign spawns (cmd -> certutil, installers -> helpers) would
    otherwise FP here. Process hollowing is unaffected -- it still needs a
    caller-initiated thread resume, which the injection-chain signature
    catches.
    """
    alerts: List[Dict[str, Any]] = []
    seen: Set[Tuple[int, int]] = set(covered)
    for event in events:
        if (event.get("data") or {}).get("Api") != "NtWriteVirtualMemory":
            continue
        actor = _actor_pid(event)
        target = _target_pid(event)
        if actor is None or target is None:
            continue
        if target == actor:
            continue  # monitor only emits cross-process writes
        if target in children.get(actor, ()):
            continue  # process-creation parameter write into own child
        key = (actor, target)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            _build_alert(
                APITRACE_CROSS_PROCESS_WRITE_EVENT_ID,
                "ApitraceCrossProcessWrite",
                actor,
                target,
                [event],
                f"Cross-process write into process {target}",
            )
        )
    return alerts


def _detect_exec_protection(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Transitions to executable memory (write->exec) or excessive RWX allocs.

    .NET JIT legitimately creates executable allocations; we only flag the
    protect->executable transition (rare in benign code) or a volume of RWX
    allocations that suggests unpacking/shellcode staging.
    """
    by_actor: Dict[int, Dict[str, Any]] = defaultdict(lambda: {"protect": [], "alloc": []})
    for event in events:
        actor = _actor_pid(event)
        if actor is None:
            continue
        api = (event.get("data") or {}).get("Api", "")
        arg0 = (event.get("data") or {}).get("Arg0", "")
        kv = _parse_kv(arg0)
        if api == "NtProtectVirtualMemory" and _is_executable_protect(kv):
            # Same-process JIT/codegen noise: MinHook trampolines flip 5-byte
            # regions RX (one per hook), .NET's JIT flips small code pages --
            # both routine. The unpacking/shellcode tell is a LARGE region
            # (>= one page) or any CROSS-process flip. Raw small events stay
            # in the trace, just not scored here.
            if not _kv_bool(kv, "cross_process") and (_kv_int(kv, "size") or 0) < 4096:
                continue
            by_actor[actor]["protect"].append(event)
        elif api in ("NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx") and _is_executable_protect(kv):
            by_actor[actor]["alloc"].append(event)

    alerts: List[Dict[str, Any]] = []
    for actor, bucket in by_actor.items():
        if bucket["protect"]:
            alerts.append(
                _build_alert(
                    APITRACE_EXEC_PROTECTION_EVENT_ID,
                    "ApitraceExecProtection",
                    actor,
                    None,
                    bucket["protect"][:1],
                    "Memory protection changed to executable",
                )
            )
        elif len(bucket["alloc"]) >= EXECUTABLE_ALLOCATION_THRESHOLD:
            alerts.append(
                _build_alert(
                    APITRACE_EXEC_PROTECTION_EVENT_ID,
                    "ApitraceExecProtection",
                    actor,
                    None,
                    bucket["alloc"][:1],
                    f"{len(bucket['alloc'])} executable memory allocations",
                )
            )
    return alerts


def _detect_remote_threads(
    events: List[Dict[str, Any]],
    covered: Set[Tuple[int, int]],
) -> List[Dict[str, Any]]:
    """NtCreateThreadEx or NtResumeThread to a remote process not part of a chain."""
    alerts: List[Dict[str, Any]] = []
    seen: Set[Tuple[int, int]] = set(covered)
    for event in events:
        api = (event.get("data") or {}).get("Api", "")
        if api not in ("NtCreateThreadEx", "NtResumeThread", "NtQueueApcThread", "NtSetContextThread", "NtQueueApcThreadEx"):
            continue
        actor = _actor_pid(event)
        target = _target_pid(event)
        if actor is None or target is None:
            continue
        if api in ("NtCreateThreadEx", "NtQueueApcThread", "NtSetContextThread", "NtQueueApcThreadEx"):
            # Same-process thread ops are routine (.NET spawns threads
            # constantly); only cross-process ones are the injection tell.
            kv = _parse_kv((event.get("data") or {}).get("Arg0", ""))
            if not _kv_bool(kv, "cross_process") or target == actor:
                continue
        key = (actor, target)
        if key in seen:
            continue
        seen.add(key)
        detail = f"Remote thread start via {api}" if api == "NtCreateThreadEx" else f"Remote thread resume via {api}"
        alerts.append(
            _build_alert(
                APITRACE_REMOTE_THREAD_EVENT_ID,
                "ApitraceRemoteThread",
                actor,
                target,
                [event],
                f"{detail} on process {target}",
            )
        )
    return alerts


def _detect_reflective_load(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """LdrLoadDll from a user-writable or UNC path.

    Closes the loader-wrapper-bypass blind spot: samples calling LdrLoadDll
    directly (skipping kernel32!LoadLibrary) to stage a payload DLL. Manual
    mapping never calls LdrLoadDll at all and stays covered by the memory
    hooks + injection-chain signatures. System dirs and bare DLL names
    (search-order loads) are out of scope; our own child-injected monitor
    DLL is excluded by name since it loads from the guest agent dir.
    """
    alerts: List[Dict[str, Any]] = []
    seen: Set[Tuple[int, str]] = set()
    for event in events:
        if (event.get("data") or {}).get("Api") != "LdrLoadDll":
            continue
        actor = _actor_pid(event)
        if actor is None:
            continue
        path = str((event.get("data") or {}).get("Arg0", ""))
        low = path.lower()
        if any(m in low for m in _MONITOR_DLL_NAMES):
            continue
        if "\\" not in path and "/" not in path:
            continue  # bare module name = normal search-order load
        suspicious = low.startswith("\\\\") or any(m in low for m in _SUSPICIOUS_LOAD_MARKERS)
        if not suspicious:
            continue
        if any(x in low for x in _SUSPICIOUS_LOAD_EXCLUSIONS):
            continue  # system-vendor dir under a suspicious root
        key = (actor, low)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            _build_alert(
                APITRACE_REFLECTIVE_LOAD_EVENT_ID,
                "ApitraceReflectiveLoad",
                actor,
                None,
                [event],
                f"Module loaded from user-writable/UNC path: {path}",
            )
        )

    # Same-address variant (Phase 2: events now carry base=/start=): an
    # executable allocation at address B followed by a thread/APC started at
    # B -- the reflective-load/manual-map execution tell.
    exec_bases: Dict[int, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for event in events:
        api = (event.get("data") or {}).get("Api", "")
        actor = _actor_pid(event)
        if actor is None:
            continue
        kv = _parse_kv((event.get("data") or {}).get("Arg0", ""))
        if api in ("NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx") and _is_executable_protect(kv):
            base = kv.get("base")
            if base and base != "0x0":
                exec_bases[actor].setdefault(base, event)
        elif api in _THREAD_FINISH_APIS or api == "NtResumeThread":
            start = kv.get("start")
            if not start or start == "0x0":
                continue
            hit = exec_bases[actor].get(start)
            if hit:
                alerts.append(
                    _build_alert(
                        APITRACE_REFLECTIVE_LOAD_EVENT_ID,
                        "ApitraceReflectiveLoad",
                        actor,
                        None,
                        [hit, event],
                        f"Executable allocation at {start} followed by thread start at the same address (reflective load)",
                    )
                )
    return alerts


def _detect_anti_sandbox_timing(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Long relative delays and timer-APC execution, per actor.

    NtDelayExecution/NtSetTimer carry delay_ms; long relative sleeps inside a
    short analysis window are the classic sleep-out-the-sandbox evasion, and
    timer APCs are the Foliage/Ekko execution channel. GetTickCount64/
    NtQuerySystemTime polls only count as evidence IN COMBINATION with a long
    non-alertable delay (a pure-polling arm false-positived twice on benign
    runtimes -- see the constants comment).
    """
    by_actor: Dict[int, Dict[str, List[Dict[str, Any]]]] = defaultdict(
        lambda: {"polls": [], "long": [], "very_long": [], "timer_apc": []}
    )
    for event in events:
        actor = _actor_pid(event)
        if actor is None:
            continue
        api = (event.get("data") or {}).get("Api", "")
        if api in ("GetTickCount64", "NtQuerySystemTime"):
            by_actor[actor]["polls"].append(event)
        elif api in ("NtDelayExecution", "NtSetTimer"):
            kv = _parse_kv((event.get("data") or {}).get("Arg0", ""))
            # Timer-APC execution (Foliage/Ekko): code runs via the timer's
            # APC instead of a sleeping thread -- always worth an alert.
            if api == "NtSetTimer" and _kv_bool(kv, "apc"):
                by_actor[actor]["timer_apc"].append(event)
                continue
            delay = _kv_int(kv, "delay_ms")
            if delay is None or delay < 0 or delay > MAX_PLAUSIBLE_DELAY_MS:
                continue  # absolute-time delay or overflow garbage -- out of scope
            if _kv_bool(kv, "alertable"):
                # Alertable waits are parked runtime threads (CLR/powershell
                # idle waits accept APC delivery) -- measured on a benign
                # guest powershell: 10s and 7-day alertable waits from the
                # runtime, none from the sample. Sleep-out-the-sandbox uses
                # plain non-alertable sleeps; APC-based evasion (Ekko/
                # Foliage) is caught by the timer_apc arm above instead.
                continue
            if delay >= VERY_LONG_DELAY_MS:
                by_actor[actor]["very_long"].append(event)
            elif delay >= LONG_DELAY_MS:
                by_actor[actor]["long"].append(event)

    alerts: List[Dict[str, Any]] = []
    for actor, bucket in by_actor.items():
        polls = bucket["polls"]
        if bucket["timer_apc"]:
            alerts.append(
                _build_alert(
                    APITRACE_ANTI_SANDBOX_TIMING_EVENT_ID,
                    "ApitraceAntiSandboxTiming",
                    actor,
                    None,
                    bucket["timer_apc"][:1],
                    "Code execution scheduled via timer APC (sleep-obfuscation family)",
                )
            )
        elif bucket["very_long"]:
            evidence = (polls[:1] + bucket["very_long"][:1]) or bucket["very_long"][:1]
            alerts.append(
                _build_alert(
                    APITRACE_ANTI_SANDBOX_TIMING_EVENT_ID,
                    "ApitraceAntiSandboxTiming",
                    actor,
                    None,
                    evidence,
                    f"Very long relative delay (>= {VERY_LONG_DELAY_MS // 1000}s) inside the analysis window",
                )
            )
        elif len(polls) >= 3 and bucket["long"]:
            alerts.append(
                _build_alert(
                    APITRACE_ANTI_SANDBOX_TIMING_EVENT_ID,
                    "ApitraceAntiSandboxTiming",
                    actor,
                    None,
                    polls[:1] + bucket["long"][:1],
                    "Timing-source polling combined with a long delay (time-acceleration check)",
                )
            )
    return alerts


def _detect_crypto_burst(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Bulk BCrypt encrypt/decrypt from one actor (ransomware-style).

    HashData is excluded -- TLS/.NET hash constantly. Each event survived
    the monitor's dedup ring, so the count tracks genuinely distinct ops.
    """
    by_actor: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        api = (event.get("data") or {}).get("Api", "")
        if api not in ("BCryptEncrypt", "BCryptDecrypt"):
            continue
        actor = _actor_pid(event)
        if actor is not None:
            by_actor[actor].append(event)

    alerts: List[Dict[str, Any]] = []
    for actor, evs in by_actor.items():
        if len(evs) >= CRYPTO_BURST_THRESHOLD:
            alerts.append(
                _build_alert(
                    APITRACE_CRYPTO_BURST_EVENT_ID,
                    "ApitraceCryptoBurst",
                    actor,
                    None,
                    evs[:3],
                    f"{len(evs)} bulk encrypt/decrypt operations from one process",
                )
            )
    return alerts


def _detect_token_manipulation(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Privilege-escalation / token-theft patterns, per actor.

    Two independent tells (either fires):
      * SeDebugPrivilege or SeImpersonatePrivilege being enabled (the monitor
        only emits NtAdjustPrivilegesToken for exactly these two).
      * Cross-process NtOpenProcessToken combined with NtDuplicateToken --
        the token-theft sequence. The monitor only emits the open when it
        targets another process, so presence of both is the pattern.
    """
    alerts: List[Dict[str, Any]] = []
    by_actor: Dict[int, Dict[str, List[Dict[str, Any]]]] = defaultdict(
        lambda: {"adjust": [], "open": [], "dup": []}
    )
    for event in events:
        actor = _actor_pid(event)
        if actor is None:
            continue
        api = (event.get("data") or {}).get("Api", "")
        if api == "NtAdjustPrivilegesToken":
            by_actor[actor]["adjust"].append(event)
        elif api == "NtOpenProcessToken":
            by_actor[actor]["open"].append(event)
        elif api == "NtDuplicateToken":
            by_actor[actor]["dup"].append(event)

    for actor, bucket in by_actor.items():
        # SeDebug-enable alone is not enough (stock powershell enables it on
        # startup), and SeDebug + token duplication is STILL routine COM/WMI
        # behavior (measured: benign powershell, 1 adjust + 3 dups). The
        # actionable pattern is the privilege plus a CROSS-PROCESS token
        # open. Token theft (open + duplicate) stands on its own.
        if bucket["adjust"] and bucket["open"]:
            target = _target_pid(bucket["open"][0]) if bucket["open"] else None
            arg0 = (bucket["adjust"][0].get("data") or {}).get("Arg0", "")
            alerts.append(
                _build_alert(
                    APITRACE_TOKEN_MANIPULATION_EVENT_ID,
                    "ApitraceTokenManipulation",
                    actor,
                    target,
                    (bucket["adjust"][:1] + bucket["open"][:1] + bucket["dup"][:1])[:2],
                    f"Privilege escalation followed by token action ({arg0})",
                )
            )
        elif bucket["open"] and bucket["dup"]:
            target = _target_pid(bucket["open"][0])
            alerts.append(
                _build_alert(
                    APITRACE_TOKEN_MANIPULATION_EVENT_ID,
                    "ApitraceTokenManipulation",
                    actor,
                    target,
                    bucket["open"][:1] + bucket["dup"][:1],
                    f"Token of process {target} opened and duplicated (token theft)",
                )
            )
    return alerts


def _detect_cross_process_reads(
    events: List[Dict[str, Any]],
    children: Dict[int, Set[int]],
) -> List[Dict[str, Any]]:
    """Cross-process NtReadVirtualMemory -- secret theft / injection recon.

    The monitor only emits this API for cross-process targets, so presence
    is meaningful. Own-child reads are excluded (same rationale as writes).
    """
    alerts: List[Dict[str, Any]] = []
    seen: Set[Tuple[int, int]] = set()
    for event in events:
        if (event.get("data") or {}).get("Api") != "NtReadVirtualMemory":
            continue
        actor = _actor_pid(event)
        target = _target_pid(event)
        if actor is None or target is None:
            continue
        if target in children.get(actor, ()):
            continue
        key = (actor, target)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            _build_alert(
                APITRACE_CROSS_PROCESS_READ_EVENT_ID,
                "ApitraceCrossProcessRead",
                actor,
                target,
                [event],
                f"Cross-process memory read from process {target}",
            )
        )
    return alerts


def _detect_anti_debug(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Anti-debugging moves: ThreadHideFromDebugger or process debug-class
    tampering. The monitor only emits these info classes, so presence fires."""
    by_actor: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        api = (event.get("data") or {}).get("Api", "")
        if api not in ("NtSetInformationThread", "NtSetInformationProcess"):
            continue
        actor = _actor_pid(event)
        if actor is not None:
            by_actor[actor].append(event)

    alerts: List[Dict[str, Any]] = []
    for actor, evs in by_actor.items():
        first = (evs[0].get("data") or {}).get("Arg0", "")
        alerts.append(
            _build_alert(
                APITRACE_ANTI_DEBUG_EVENT_ID,
                "ApitraceAntiDebug",
                actor,
                None,
                evs[:2],
                f"Anti-debugging behavior ({first})",
            )
        )
    return alerts


def _detect_anti_tamper(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Writes/protects landing inside ntdll or amsi.dll (unhooking / ETW-AMSI
    blinding). The monitor flags these with `targets_module=` in Arg0."""
    by_actor: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        arg0 = str((event.get("data") or {}).get("Arg0", ""))
        if "targets_module=" not in arg0:
            continue
        actor = _actor_pid(event)
        if actor is not None:
            by_actor[actor].append(event)

    alerts: List[Dict[str, Any]] = []
    for actor, evs in by_actor.items():
        first = str((evs[0].get("data") or {}).get("Arg0", ""))
        module = "ntdll" if "targets_module=ntdll" in first else "amsi.dll"
        alerts.append(
            _build_alert(
                APITRACE_ANTI_TAMPER_EVENT_ID,
                "ApitraceAntiTamper",
                actor,
                None,
                evs[:2],
                f"Memory write/protect inside {module} (unhooking / ETW-AMSI blinding attempt)",
            )
        )
    return alerts


def _detect_transaction_abuse(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """NTFS transaction creation -- the process-doppelganging primitive.
    Near-absent from benign software (MSI is the notable exception)."""
    by_actor: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        if (event.get("data") or {}).get("Api") != "NtCreateTransaction":
            continue
        actor = _actor_pid(event)
        if actor is not None:
            by_actor[actor].append(event)

    alerts: List[Dict[str, Any]] = []
    for actor, evs in by_actor.items():
        alerts.append(
            _build_alert(
                APITRACE_TRANSACTION_ABUSE_EVENT_ID,
                "ApitraceTransactionAbuse",
                actor,
                None,
                evs[:1],
                "NTFS transaction created (process doppelganging primitive)",
            )
        )
    return alerts


def _detect_ppid_spoof(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """NtCreateUserProcess with a parent-process attribute pointing at a
    DIFFERENT process -- the monitor emits ppid_spoofed=1 for these."""
    alerts: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for event in events:
        if (event.get("data") or {}).get("Api") != "NtCreateUserProcess":
            continue
        kv = _parse_kv((event.get("data") or {}).get("Arg0", ""))
        if not _kv_bool(kv, "ppid_spoofed"):
            continue
        actor = _actor_pid(event)
        if actor is None or actor in seen:
            continue
        seen.add(actor)
        alerts.append(
            _build_alert(
                APITRACE_PPID_SPOOF_EVENT_ID,
                "ApitracePpidSpoof",
                actor,
                _kv_int(kv, "child_pid"),
                [event],
                f"Parent-PID spoof: child created naming pid {kv.get('ppid')} as parent",
            )
        )
    return alerts


def _detect_truncation(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Volume cap hit or pipe-loss gap -- analyst transparency, unscored."""
    meta_events = [
        e
        for e in events
        if (e.get("data") or {}).get("Category") == "meta"
        and (e.get("data") or {}).get("Api") in ("__event_cap_reached__", "__pipe_lost__")
    ]
    if not meta_events:
        return []
    # One alert per actor process that hit the cap.
    by_actor: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for event in meta_events:
        actor = _actor_pid(event)
        if actor is None:
            continue
        by_actor[actor].append(event)

    alerts: List[Dict[str, Any]] = []
    for actor, evs in by_actor.items():
        kinds = {(e.get("data") or {}).get("Api") for e in evs}
        if "__pipe_lost__" in kinds and "__event_cap_reached__" in kinds:
            detail = "API-trace volume cap reached and collector pipe was lost; sequence is incomplete"
        elif "__pipe_lost__" in kinds:
            detail = "Collector pipe was lost and reconnected; events missing in the gap"
        else:
            detail = "API-trace volume cap reached; sequence may be incomplete"
        alerts.append(
            _build_alert(
                APITRACE_TRUNCATED_EVENT_ID,
                "ApiTraceTruncated",
                actor,
                None,
                evs[:1],
                detail,
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# WS-B: apitrace<->Sysmon blind-spot detectors
# ---------------------------------------------------------------------------


def _parse_ts(event: Dict[str, Any]) -> Optional[datetime]:
    ts = _event_timestamp(event)
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _sysmon_actor_pid(event: Dict[str, Any]) -> Optional[int]:
    """Actor pid of a Sysmon event. EID 8/10 name the actor SourceProcessId
    (ProcessId is the TARGET there); everything else uses ProcessId. EID 25
    only carries the tampered process's ProcessId -- the same-pid join is
    approximate for it (v1 limitation, documented in coverage_map.yaml)."""
    data = event.get("data") or {}
    return _safe_int(data.get("SourceProcessId")) or _safe_int(data.get("ProcessId"))


def _index_apitrace_by_pid(
    apitrace: List[Dict[str, Any]],
) -> Dict[int, Dict[str, Any]]:
    """pid -> {events: [(ts, api, event)], cap_reached, wow64: [ts], attached}.

    Meta events are folded into flags instead of the event list: the volume
    cap makes trace absence meaningless, __monitor_attached__ is the hook
    handshake, and __wow64_follow__ marks the re-injection gap.
    """
    by_pid: Dict[int, Dict[str, Any]] = defaultdict(
        lambda: {"events": [], "cap_reached": False, "wow64": [], "attached": None}
    )
    for event in apitrace:
        pid = _actor_pid(event)
        ts = _parse_ts(event)
        if pid is None or ts is None:
            continue
        api = (event.get("data") or {}).get("Api", "")
        slot = by_pid[pid]
        if api == "__event_cap_reached__":
            slot["cap_reached"] = True
        elif api == "__wow64_follow__":
            slot["wow64"].append(ts)
        elif api == "__monitor_attached__":
            if slot["attached"] is None or ts < slot["attached"]:
                slot["attached"] = ts
        else:
            slot["events"].append((ts, api, event))
    return by_pid


def _detect_counterpart_misses(
    events: List[Dict[str, Any]],
    apitrace: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Sysmon saw a behavior that the corresponding hook should also have seen,
    but no same-pid apitrace counterpart exists within +/-2s -- the hook is
    suspected blind (unhooking or direct syscalls).

    v1 is presence-based only: artifact matching (path/pid joins) was deemed
    too fragile, so any counterpart API in-window counts as covered. Suppressed
    when the trace is known-lossy (cap reached), when Sysmon predates the
    monitor handshake, around a wow64 re-injection gap, or for pids outside
    the traced tree (no apitrace event before the Sysmon event).

    Three structural Sysmon artifacts are additionally excluded because the
    user-mode hook can NEVER see them (measured on benign runs):
      * EID 13 under \\Services\\bam\\dam\\ -- kernel-side BAM/DAM bookkeeping
        written at process exit, attributed to the dying process.
      * EID 7 within a short grace after the monitor handshake -- process-init
        image loads bypass LdrLoadDll by design.
      * EID 8/10 targeting the actor's OWN just-created child -- the monitor's
        child-following injection (and kernel32's process-creation parameter
        writes) operate on every new child but are suppressed monitor-side.
    """
    eid_to_apis = _load_coverage_map().get("eid_to_apis") or {}
    if not eid_to_apis:
        return []
    by_pid = _index_apitrace_by_pid(apitrace)
    children = _child_pids_by_actor(apitrace)

    alerts: List[Dict[str, Any]] = []
    misses: Dict[Tuple[int, str], Dict[str, Any]] = {}
    for event in events:
        if event.get("source") != "sysmon":
            continue
        apis = eid_to_apis.get(str(event.get("event_id")))
        if not apis:
            continue
        eid = event.get("event_id")
        data = event.get("data") or {}
        if eid == 13 and any(p in str(data.get("TargetObject", "")).lower() for p in _KERNEL_REGISTRY_PREFIXES):
            continue  # kernel-side BAM/DAM bookkeeping -- no user-mode call exists
        pid = _sysmon_actor_pid(event)
        ts = _parse_ts(event)
        if pid is None or ts is None:
            continue
        slot = by_pid.get(pid)
        if not slot:
            continue  # untraced process -- outside the sample's traced tree
        if not any(ev_ts <= ts for ev_ts, _, _ in slot["events"]):
            continue  # no apitrace from this pid yet -- not (yet) our traced tree
        if slot["cap_reached"]:
            continue  # trace is lossy -- absence proves nothing
        attached = slot["attached"]
        if attached is not None and ts < attached:
            continue  # Sysmon saw the process before the monitor handshake
        if attached is not None and eid == 7 and (ts - attached).total_seconds() <= IMAGE_LOAD_GRACE_SECONDS:
            continue  # process-init load burst straddling hook placement
        if any(abs((w - ts).total_seconds()) <= WOW64_FOLLOW_SUPPRESS_SECONDS for w in slot["wow64"]):
            continue  # wow64 re-injection gap -- hooks not yet placed
        if eid in (8, 10) and _safe_int(data.get("TargetProcessId")) in children.get(pid, ()):
            continue  # monitor's child-following injection / kernel32 spawn writes
        covered = any(
            api in apis and abs((ev_ts - ts).total_seconds()) <= BLINDSPOT_WINDOW_SECONDS
            for ev_ts, api, _ in slot["events"]
        )
        if covered:
            continue
        # Group per (pid, canonical hook): the canonical hook of an EID group
        # is its first counterpart api (several hooks can share an EID, e.g.
        # CreateFileW + NtCreateFile both map to EID 11).
        canonical = apis[0]
        slot_miss = misses.setdefault((pid, canonical), {"count": 0, "first": event, "eid": eid})
        slot_miss["count"] += 1

    for (pid, canonical), miss in misses.items():
        if miss["count"] < BLINDSPOT_MIN_MISSES:
            continue  # one-off collector artifact -- see docstring
        alerts.append(
            _build_alert(
                APITRACE_BLIND_SPOT_EVENT_ID,
                "ApitraceBlindSpot",
                pid,
                None,
                [miss["first"]],
                f"hook {canonical} blind: {miss['count']} Sysmon EID {miss['eid']} events with no "
                f"apitrace counterpart, first at {_event_timestamp(miss['first'])} "
                "(unhooking or direct syscalls)",
            )
        )
    return alerts


def _detect_telemetry_silence(
    events: List[Dict[str, Any]],
    apitrace: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """A traced pid stops producing dual-covered ("both"-class) API events for
    the rest of the run while Sysmon still sees it active -- the mid-run
    unhooking tell. One alert per pid, only for a trailing span reaching
    end-of-run; capped pids are suppressed (their silence is expected).
    """
    hooks = _load_coverage_map().get("hooks") or []
    if not hooks:
        return []
    both_apis = {h["api"] for h in hooks if h.get("coverage") == "both"}
    by_pid = _index_apitrace_by_pid(apitrace)

    run_end: Optional[datetime] = None
    sysmon_by_pid: Dict[int, List[Tuple[datetime, Dict[str, Any]]]] = defaultdict(list)
    for event in events:
        ts = _parse_ts(event)
        if ts is None:
            continue
        if run_end is None or ts > run_end:
            run_end = ts
        if event.get("source") == "sysmon":
            pid = _sysmon_actor_pid(event)
            if pid is not None:
                sysmon_by_pid[pid].append((ts, event))
    if run_end is None:
        return []

    alerts: List[Dict[str, Any]] = []
    for pid, slot in by_pid.items():
        if slot["cap_reached"]:
            continue
        traced = slot["events"]
        if len(traced) < SILENCE_MIN_APITRACE_EVENTS:
            continue
        both_events = [(ts, ev) for ts, api, ev in traced if api in both_apis]
        if not both_events:
            # Hook-only-heavy pid (timing/crypto/token/... only): it never
            # produced dual-covered telemetry, so its "silence" is the
            # baseline, not an anomaly.
            continue
        span_start, last_both_event = max(both_events, key=lambda pair: pair[0])
        span = (run_end - span_start).total_seconds()
        if span < SILENCE_MIN_SPAN_SECONDS:
            continue
        trailing = [(ts, ev) for ts, ev in sysmon_by_pid.get(pid, []) if ts > span_start]
        if len(trailing) < SILENCE_MIN_SYSMON_EVENTS:
            continue
        alerts.append(
            _build_alert(
                APITRACE_SILENCE_EVENT_ID,
                "ApitraceSilence",
                pid,
                None,
                [last_both_event, trailing[-1][1]],
                f"API trace silent for the final {int(span)}s of the run while Sysmon "
                f"still saw {len(trailing)} events from the process (mid-run unhooking)",
            )
        )
    return alerts


def describe_signatures() -> List[Dict[str, Any]]:
    """Declarative inventory of the behavioral signatures in this module, in
    the standardized detector schema (id/family/name/severity/kind/mitre/
    description/detail -- see orchestrator/detectors.py). Backs the rules
    catalog (/api/rules) and the report page's 'Detections applied' family
    block, so the signatures aren't mislabeled as generic heuristics.
    """
    return [
        {
            "id": "behavioral.injection-chain",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Injection chain (API trace)",
            "severity": "critical",
            "kind": "sequence",
            "mitre": ["T1055"],
            "description": (
                "Cross-process NtWriteVirtualMemory into a target followed by "
                "NtCreateThreadEx/NtResumeThread on the same target -- the "
                "classic alloc->write->start injection chain, seen at argument "
                "level even when it bypasses Win32 wrappers (direct syscalls "
                "to the hooked Nt* choke points)."
            ),
            "detail": ["NtWriteVirtualMemory", "NtCreateThreadEx", "NtResumeThread"],
        },
        {
            "id": "behavioral.cross-process-write",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Cross-process memory write (API trace)",
            "severity": "high",
            "kind": "presence",
            "mitre": ["T1055"],
            "description": (
                "NtWriteVirtualMemory into another process without the full "
                "chain being observed (the monitor only emits this API for "
                "cross-process targets, so presence alone is a strong signal)."
            ),
            "detail": ["NtWriteVirtualMemory"],
        },
        {
            "id": "behavioral.remote-thread",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Remote thread start/resume (API trace)",
            "severity": "high",
            "kind": "presence",
            "mitre": ["T1055"],
            "description": (
                "NtCreateThreadEx, NtResumeThread, NtQueueApcThread or "
                "NtSetContextThread targeting another process, not already "
                "covered by an injection-chain alert. APC-queue and "
                "context-set finishers are invisible to Sysmon entirely. "
                "Kernel32's automatic resume of a just-created child's "
                "initial thread is suppressed monitor-side so benign process "
                "spawning does not fire this."
            ),
            "detail": ["NtCreateThreadEx", "NtResumeThread", "NtQueueApcThread", "NtSetContextThread"],
        },
        {
            "id": "behavioral.exec-protection",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Executable memory transition (API trace)",
            "severity": "medium",
            "kind": "presence+threshold",
            "mitre": ["T1027", "T1055"],
            "description": (
                "NtProtectVirtualMemory flipping a region to executable (the "
                "write->exec unpacking/shellcode tell), or an unusual volume "
                "of executable NtAllocateVirtualMemory calls from one process "
                "(threshold guards against .NET-JIT-style RWX noise)."
            ),
            "detail": ["NtProtectVirtualMemory", "NtAllocateVirtualMemory"],
        },
        {
            "id": "behavioral.reflective-load",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Module load from user-writable path (API trace)",
            "severity": "high",
            "kind": "presence",
            "mitre": ["T1055", "T1027"],
            "description": (
                "LdrLoadDll loading a module from a user-writable directory "
                "(Temp/AppData/Downloads/Public/ProgramData/Users) or a UNC "
                "path -- payload-DLL staging that bypasses the kernel32 "
                "LoadLibrary wrapper. Manual mapping never calls LdrLoadDll "
                "and is covered by the memory hooks + injection-chain "
                "signatures instead."
            ),
            "detail": ["LdrLoadDll"],
        },
        {
            "id": "behavioral.anti-sandbox-timing",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Anti-sandbox timing check (API trace)",
            "severity": "medium",
            "kind": "presence+threshold",
            "mitre": ["T1497"],
            "description": (
                "Timing-source polling combined with a long non-alertable "
                "NtDelayExecution (time-acceleration check), a very long "
                "relative delay (>= 60s), or code execution via a timer APC "
                "(Foliage/Ekko) -- sleep-out-the-sandbox evasion. "
                "(Pure polling alone is not flagged: benign runtimes poll too.)"
            ),
            "detail": ["GetTickCount64", "NtQuerySystemTime", "NtDelayExecution"],
        },
        {
            "id": "behavioral.crypto-burst",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Bulk crypto operations (API trace)",
            "severity": "high",
            "kind": "presence+threshold",
            "mitre": ["T1486"],
            "description": (
                "One process performing many distinct BCryptEncrypt/"
                "BCryptDecrypt operations (ransomware-style bulk encryption). "
                "Hashing is excluded -- TLS/.NET hash constantly."
            ),
            "detail": ["BCryptEncrypt", "BCryptDecrypt"],
        },
        {
            "id": "behavioral.token-manipulation",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Token manipulation / privilege escalation (API trace)",
            "severity": "high",
            "kind": "presence",
            "mitre": ["T1134"],
            "description": (
                "SeDebugPrivilege/SeImpersonatePrivilege being enabled, or a "
                "cross-process token open combined with token duplication "
                "(token theft). Benign own-process token opens are filtered "
                "monitor-side."
            ),
            "detail": ["NtAdjustPrivilegesToken", "NtOpenProcessToken", "NtDuplicateToken"],
        },
        {
            "id": "behavioral.cross-process-read",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Cross-process memory read (API trace)",
            "severity": "medium",
            "kind": "presence",
            "mitre": ["T1005"],
            "description": (
                "NtReadVirtualMemory into another process -- secret theft "
                "(LSASS/browser credential stores) or injection recon. The "
                "monitor only emits this API for cross-process targets."
            ),
            "detail": ["NtReadVirtualMemory"],
        },
        {
            "id": "behavioral.anti-debug",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Anti-debugging (API trace)",
            "severity": "medium",
            "kind": "presence",
            "mitre": ["T1622"],
            "description": (
                "ThreadHideFromDebugger or process debug-class tampering "
                "(NtSetInformationThread/Process) -- the sample is trying "
                "to blind analysis tooling."
            ),
            "detail": ["NtSetInformationThread", "NtSetInformationProcess"],
        },
        {
            "id": "behavioral.anti-tamper",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Security-tool tampering (API trace)",
            "severity": "high",
            "kind": "presence",
            "mitre": ["T1562.001"],
            "description": (
                "Memory write or protect landing inside ntdll.dll or "
                "amsi.dll -- an unhooking or ETW/AMSI-blinding attempt "
                "(the sample is trying to blind this monitor and AMSI)."
            ),
            "detail": ["NtWriteVirtualMemory", "NtProtectVirtualMemory"],
        },
        {
            "id": "behavioral.transaction-abuse",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "NTFS transaction abuse (API trace)",
            "severity": "medium",
            "kind": "presence",
            "mitre": ["T1055.013"],
            "description": (
                "NTFS transaction created -- the process-doppelganging "
                "primitive. Near-absent from benign software (MSI is the "
                "notable exception)."
            ),
            "detail": ["NtCreateTransaction"],
        },
        {
            "id": "behavioral.ppid-spoof",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Parent-PID spoofing (API trace)",
            "severity": "high",
            "kind": "presence",
            "mitre": ["T1134.004"],
            "description": (
                "Child process created with a parent-process attribute "
                "naming a different process as its parent (lineage "
                "forgery), parsed from the NtCreateUserProcess attribute "
                "list."
            ),
            "detail": ["NtCreateUserProcess"],
        },
        {
            "id": "behavioral.apitrace-blind-spot",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Hook blind spot (Sysmon saw it, apitrace did not)",
            "severity": "high",
            "kind": "correlation",
            "mitre": ["T1562.001"],
            "description": (
                "Sysmon logged an event whose behavior a dual-covered hook "
                "(coverage_map.yaml 'both' class) should also have observed, "
                "but no same-pid apitrace counterpart exists within +/-2s -- "
                "the hook is suspected blind (unhooking or direct syscalls). "
                "Suppressed for capped traces, pre-handshake events, wow64 "
                "re-injection gaps, pids outside the traced tree, kernel-side "
                "BAM/DAM registry bookkeeping (EID 13), the process-init image-"
                "load burst right after hook placement (EID 7), and the "
                "monitor's own child-following injection into just-created "
                "children (EID 8/10)."
            ),
            "detail": ["coverage_map.json", "eid_to_apis"],
        },
        {
            "id": "behavioral.apitrace-silence",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "API-trace silence while Sysmon stays active",
            "severity": "medium",
            "kind": "correlation",
            "mitre": ["T1562.001"],
            "description": (
                "A traced process stops producing dual-covered API events for "
                "the rest of the run (>= 10s trailing span, >= 8 Sysmon events "
                "in it) while Sysmon still sees it active -- the mid-run "
                "unhooking tell. Capped pids are suppressed; hook-only-heavy "
                "pids never qualify."
            ),
            "detail": ["coverage_map.json", "both-class hooks"],
        },
        {
            "id": "behavioral.trace-truncated",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "API trace truncated (transparency)",
            "severity": "informational",
            "kind": "meta",
            "mitre": [],
            "description": (
                "The monitor's volume cap was reached for an API (or globally), "
                "so the trace may be incomplete. Surfaced for analyst "
                "transparency; deliberately unscored."
            ),
            "detail": ["__event_cap_reached__"],
        },
        {
            "id": "behavioral.guardian-protected-access",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Guardian: access to protected process denied",
            "severity": "high",
            "kind": "kernel",
            "mitre": ["T1562.001"],
            "description": (
                "SandboxGuard's Ob callback stripped dangerous access rights "
                "(TERMINATE/VM_WRITE/VM_OPERATION/CREATE_THREAD/SET_INFORMATION) "
                "from a handle open targeting a protected telemetry process "
                "(Sysmon, guardian agent)."
            ),
            "detail": ["SandboxGuard.sys", "ObRegisterCallbacks"],
        },
        {
            "id": "behavioral.guardian-protected-registry",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Guardian: protected registry key write denied",
            "severity": "high",
            "kind": "kernel",
            "mitre": ["T1562.001"],
            "description": (
                "SandboxGuard's Cm callback denied a write/delete on a "
                "protected key (Sysmon service/config, AMSI providers, "
                "Defender exclusions, IFEO)."
            ),
            "detail": ["SandboxGuard.sys", "CmRegisterCallbackEx"],
        },
        {
            "id": "behavioral.guardian-module-remap",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Guardian: module remap detected",
            "severity": "high",
            "kind": "kernel",
            "mitre": ["T1562.001"],
            "description": (
                "ntdll/kernel32/amsi mapped twice into the same process -- "
                "the copy-and-remap unhooking primitive, unblindable from "
                "user mode."
            ),
            "detail": ["SandboxGuard.sys", "PsSetLoadImageNotifyRoutine"],
        },
        {
            "id": "behavioral.guardian-injection-failed",
            "family": detectors.FAMILY_BEHAVIORAL,
            "name": "Guardian: injection placement failed",
            "severity": "medium",
            "kind": "kernel",
            "mitre": [],
            "description": (
                "The driver failed to place the monitor into a targeted "
                "process (NTSTATUS in the event data). Transparency signal "
                "for placement coverage gaps (e.g. WoW64 targets before the "
                "x86 loader address is available)."
            ),
            "detail": ["SandboxGuard.sys", "APC placement"],
        },
    ]


# ---------------------------------------------------------------------------
# SandboxGuard guardian events (kernel protection + placement feedback)
# ---------------------------------------------------------------------------


def _guardian_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [e for e in events if e.get("source") == GUARDIAN_SOURCE]


def _guardian_detail(event_id: Optional[int], data: Dict[str, Any]) -> str:
    pid = data.get("ProcessId") or 0
    target = data.get("TargetProcessId") or 0
    text = data.get("Text") or ""
    value = data.get("Value") or 0
    if event_id == GUARDIAN_PROTECTED_ACCESS_EVENT_ID:
        return f"Access to protected process {target} denied for pid {pid} (stripped access mask 0x{value:x})"
    if event_id == GUARDIAN_PROTECTED_REGISTRY_EVENT_ID:
        return f"Registry write/delete on protected key denied for pid {pid}: {text}"
    if event_id == GUARDIAN_MODULE_REMAP_EVENT_ID:
        return f"Module mapped twice into pid {target} (possible ntdll/amsi remap): {text}"
    if event_id == GUARDIAN_INJECTION_FAILED_EVENT_ID:
        return f"Guardian placement APC into pid {target} failed (NTSTATUS 0x{value & 0xFFFFFFFF:08x})"
    return "Guardian driver event"


def _detect_guardian_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pass guardian driver events through as behavioral alerts.

    The kernel callback IS the detection (a denial/remap only exists because
    the driver already classified it), so this is a 1:1 mapping, not a
    correlation. Works with or without an apitrace stream.
    """
    alerts: List[Dict[str, Any]] = []
    for ev in _guardian_events(events):
        event_type = _GUARDIAN_ALERT_SPECS.get(ev.get("event_id"))
        if event_type is None:
            continue
        data = ev.get("data") or {}
        ts = ev.get("timestamp") or ""
        alert_data: Dict[str, Any] = {
            "UtcTime": ts,
            "ProcessId": data.get("ProcessId") or 0,
            "Type": _guardian_detail(ev.get("event_id"), data),
            "Evidence": [data.get("Text") or ""],
        }
        if data.get("TargetProcessId"):
            alert_data["TargetProcessId"] = data["TargetProcessId"]
        alerts.append(
            {
                "source": GUARDIAN_SOURCE,
                "provider_name": "BehavioralSignatures",
                "event_id": ev.get("event_id"),
                "event_type": event_type,
                "timestamp": ts,
                "data": alert_data,
            }
        )
    return alerts


def detect_behavioral_signatures(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Main entry point: telemetry events -> apitrace/guardian-derived alerts.

    Pure function over the report event list, so offline replay picks it up
    automatically via reporting.compute_detection().
    """
    # Guardian alerts don't depend on the apitrace stream at all -- compute
    # them before the apitrace early-return.
    guardian_alerts = _detect_guardian_events(events)
    apitrace = _apitrace_events(events)
    if not apitrace:
        return guardian_alerts

    children = _child_pids_by_actor(apitrace)
    chain_alerts, covered = _detect_injection_chains(apitrace)
    write_alerts = _detect_cross_process_writes(apitrace, covered, children)
    exec_alerts = _detect_exec_protection(apitrace)
    thread_alerts = _detect_remote_threads(apitrace, covered)
    load_alerts = _detect_reflective_load(apitrace)
    timing_alerts = _detect_anti_sandbox_timing(apitrace)
    crypto_alerts = _detect_crypto_burst(apitrace)
    token_alerts = _detect_token_manipulation(apitrace)
    read_alerts = _detect_cross_process_reads(apitrace, children)
    debug_alerts = _detect_anti_debug(apitrace)
    tamper_alerts = _detect_anti_tamper(apitrace)
    tx_alerts = _detect_transaction_abuse(apitrace)
    ppid_alerts = _detect_ppid_spoof(apitrace)
    trunc_alerts = _detect_truncation(apitrace)
    # WS-B blind-spot detectors correlate against the FULL event list (they
    # need the Sysmon stream, not just the apitrace slice).
    blindspot_alerts = _detect_counterpart_misses(events, apitrace)
    silence_alerts = _detect_telemetry_silence(events, apitrace)

    return (
        chain_alerts + write_alerts + exec_alerts + thread_alerts
        + load_alerts + timing_alerts + crypto_alerts + token_alerts
        + read_alerts + debug_alerts + tamper_alerts + tx_alerts + ppid_alerts
        + trunc_alerts + blindspot_alerts + silence_alerts + guardian_alerts
    )
