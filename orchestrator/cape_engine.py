"""CAPE community-signature engine over our apitrace stream.

Replays the monitor's ApiCall events through the vendored CAPE community
signatures (cape_signatures/) using the compatibility layer in
orchestrator/cape_compat.py -- the same detection corpus CAPE/Triage users
curate, without a CAPE deployment.

Model mapping (apitrace -> Cuckoo results model):
- Each apitrace ApiCall event becomes one CAPE call dict (api/category/
  thread_id/arguments). Arg0 kv-pairs become named arguments, with a small
  per-API normalization to CAPE argument names (path -> filepath, ...).
- Our Nt-level API names are matched against a signature's filter_apinames
  through API_ALIASES (e.g. NtWriteVirtualMemory also satisfies a
  WriteProcessMemory filter); call["api"] always stays the true hooked name.
- summary lists (files/keys/executed_commands) are derived from the same
  events; the network block is left empty (no Suricata/DNS lookups offline).

Coverage is intentionally partial -- signatures filtering on APIs we do not
hook simply never fire; they are skipped at dispatch, not treated as errors.
"""

import contextlib
import importlib.util
import io
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from orchestrator.cape_compat import Signature, install_compat_modules

logger = logging.getLogger(__name__)

CAPE_SIGNATURE_EVENT_ID = 9300

# Our monitor categories -> CAPE call categories.
_CATEGORY_MAP = {
    "file": "filesystem",
    "process": "process",
    "memory": "memory",
    "thread": "threading",
    "injection": "threading",
    "registry": "registry",
    "loader": "system",
    "timing": "timing",
    "crypto": "crypto",
    "token": "security",
    "evasion": "misc",
    "meta": "__meta__",
}

# Filter-matching aliases: our hooked API name -> every name a signature's
# filter_apinames may legitimately use for the same underlying operation
# (Win32 wrappers CAPE also logs). call["api"] stays the true name; aliases
# only widen dispatch, so signatures inspecting call["api"] still see Nt*.
_API_ALIASES = {
    "CreateFileW": ["CreateFileW", "CreateFileA", "NtCreateFile"],
    "NtCreateFile": ["NtCreateFile", "CreateFileW", "CreateFileA", "ZwCreateFile"],
    "NtAllocateVirtualMemory": ["NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx", "ZwAllocateVirtualMemory"],
    "NtAllocateVirtualMemoryEx": ["NtAllocateVirtualMemoryEx", "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx"],
    "NtProtectVirtualMemory": ["NtProtectVirtualMemory", "VirtualProtect", "VirtualProtectEx", "ZwProtectVirtualMemory"],
    "NtWriteVirtualMemory": ["NtWriteVirtualMemory", "WriteProcessMemory", "ZwWriteVirtualMemory"],
    "NtReadVirtualMemory": ["NtReadVirtualMemory", "ReadProcessMemory", "ZwReadVirtualMemory"],
    "NtCreateThreadEx": ["NtCreateThreadEx", "CreateRemoteThread", "CreateRemoteThreadEx", "RtlCreateUserThread"],
    "NtResumeThread": ["NtResumeThread", "ResumeThread", "ZwResumeThread"],
    "NtSuspendThread": ["NtSuspendThread", "SuspendThread", "ZwSuspendThread"],
    "NtQueueApcThread": ["NtQueueApcThread", "QueueUserAPC"],
    "NtQueueApcThreadEx": ["NtQueueApcThreadEx", "NtQueueApcThread", "QueueUserAPC"],
    "NtSetContextThread": ["NtSetContextThread", "SetThreadContext", "ZwSetContextThread"],
    "NtGetContextThread": ["NtGetContextThread", "GetThreadContext", "ZwGetContextThread"],
    "NtCreateUserProcess": ["NtCreateUserProcess", "CreateProcessInternalW", "CreateProcessW", "CreateProcessA"],
    "CreateProcessW": ["CreateProcessW", "CreateProcessA", "CreateProcessInternalW"],
    "LdrLoadDll": ["LdrLoadDll", "LoadLibraryW", "LoadLibraryA", "LoadLibraryExW"],
    "NtDelayExecution": ["NtDelayExecution", "Sleep", "SleepEx", "ZwDelayExecution"],
    "GetTickCount64": ["GetTickCount64", "GetTickCount"],
    "NtQuerySystemTime": ["NtQuerySystemTime", "GetSystemTime", "GetLocalTime", "GetSystemTimeAsFileTime"],
    "NtSetValueKey": ["NtSetValueKey", "RegSetValueExW", "RegSetValueExA", "ZwSetValueKey"],
    "NtOpenProcessToken": ["NtOpenProcessToken", "OpenProcessToken"],
    "NtDuplicateToken": ["NtDuplicateToken", "DuplicateToken", "DuplicateTokenEx"],
    "NtAdjustPrivilegesToken": ["NtAdjustPrivilegesToken", "AdjustTokenPrivileges"],
    "NtSetInformationThread": ["NtSetInformationThread", "SetInformationThread"],
    "NtSetInformationProcess": ["NtSetInformationProcess"],
    "NtMapViewOfSection": ["NtMapViewOfSection", "MapViewOfFile", "MapViewOfFileEx"],
    "NtMapViewOfSectionEx": ["NtMapViewOfSectionEx", "NtMapViewOfSection", "MapViewOfFile", "MapViewOfFileEx"],
    "NtUnmapViewOfSection": ["NtUnmapViewOfSection", "UnmapViewOfFile"],
    "NtUnmapViewOfSectionEx": ["NtUnmapViewOfSectionEx", "NtUnmapViewOfSection", "UnmapViewOfFile"],
    "NtCreateTimer": ["NtCreateTimer", "CreateWaitableTimerW", "CreateWaitableTimerExW"],
    "NtSetTimer": ["NtSetTimer", "SetWaitableTimer"],
    "NtCreateTransaction": ["NtCreateTransaction", "CreateTransaction"],
    "NtRollbackTransaction": ["NtRollbackTransaction", "RollbackTransaction"],
    "BCryptEncrypt": ["BCryptEncrypt", "CryptEncrypt"],
    "BCryptDecrypt": ["BCryptDecrypt", "CryptDecrypt"],
    "BCryptHashData": ["BCryptHashData", "CryptHashData"],
}

# Per-API argument normalization to EXACT CAPE argument names and value
# formats (read from the community sources: Protection == "0x00000040",
# NewAccessProtection, ProcessHandle / ProcessIdentifier, BaseAddress, ...).
# Each entry: (our kv key, CAPE arg name, formatter). The raw kv keys are
# kept too, so nothing is lost.
def _hx8(v: str) -> str:
    """0x4 -> '0x00000040'... (CAPE protection/handle string format)."""
    try:
        return f"0x{int(str(v), 0):08x}"
    except (TypeError, ValueError):
        return str(v)


_ARG_SPECS = {
    "NtCreateFile": [("path", "FilePath", None), ("path", "FileName", None)],
    "CreateFileW": [("path", "FilePath", None), ("path", "FileName", None)],
    "LdrLoadDll": [("module", "FileName", None), ("module", "ModuleName", None)],
    "CreateProcessW": [("cmdline", "CommandLine", None), ("path", "FilePath", None),
                       ("child_pid", "ProcessIdentifier", None)],
    "NtCreateUserProcess": [("child_pid", "ProcessIdentifier", None)],
    "NtDelayExecution": [("delay_ms", "TimeInMilliseconds", None), ("delay_ms", "milliseconds", None)],
    "NtAllocateVirtualMemory": [("protect", "Protection", _hx8), ("base", "BaseAddress", None),
                                ("size", "Size", None)],
    "NtAllocateVirtualMemoryEx": [("protect", "Protection", _hx8), ("base", "BaseAddress", None),
                                  ("size", "Size", None)],
    "NtProtectVirtualMemory": [("new_protect", "NewAccessProtection", _hx8), ("base", "BaseAddress", None),
                               ("size", "Size", None)],
    "NtWriteVirtualMemory": [("base", "BaseAddress", None), ("len", "Size", None)],
    "NtReadVirtualMemory": [("base", "BaseAddress", None), ("len", "Size", None)],
    "NtMapViewOfSection": [("protect", "Protection", _hx8)],
    "NtMapViewOfSectionEx": [("protect", "Protection", _hx8)],
    "NtCreateThreadEx": [("start", "StartAddress", None)],
    "NtQueueApcThread": [("start", "StartAddress", None)],
    "NtQueueApcThreadEx": [("start", "StartAddress", None)],
    "NtSetValueKey": [("value", "ValueName", None)],
    "BCryptEncrypt": [("input_len", "length", None)],
    "BCryptDecrypt": [("input_len", "length", None)],
}

# APIs whose events carry a target_pid (cross-process operations).
_TARGET_PID_APIS = {
    "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx", "NtProtectVirtualMemory",
    "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtCreateThreadEx", "NtResumeThread",
    "NtSuspendThread", "NtQueueApcThread", "NtQueueApcThreadEx", "NtSetContextThread",
    "NtGetContextThread", "NtMapViewOfSection", "NtMapViewOfSectionEx",
    "NtUnmapViewOfSection", "NtUnmapViewOfSectionEx", "NtOpenProcessToken",
}

_KV_RE = re.compile(r"(\w+)=([^\s]*)")

# CAPE severity int -> our severity strings (detectors.SEVERITY_WEIGHTS keys).
# Community sigs use 1-6; anything >= 3 is a strong signal -> "high" (we
# reserve "critical" for chain-style confirmations, matching detectors.py).
_SEVERITY_MAP = {1: "low", 2: "medium", 3: "high", 4: "high", 5: "high", 6: "high"}


def _parse_args(api: str, arg0: str) -> List[Dict[str, str]]:
    """Turn the monitor's Arg0 string into CAPE-style argument dicts.

    Raw kv keys are kept verbatim; CAPE-canonical names/formats are added on
    top (protection constants as 0x%08x, BaseAddress, Size, ...). Numeric kv
    values also get a raw_value int for get_raw_argument() users. For
    target-pid APIs a ProcessHandle/ProcessIdentifier pair is synthesized --
    "0xffffffff" for same-process calls (the pseudo self-handle, which the
    community injection sigs explicitly exclude), 0x<pid> for cross-process.
    """
    args: List[Dict[str, Any]] = []
    kvs = _KV_RE.findall(arg0 or "")
    kv = dict(kvs)
    for k, v in kvs:
        arg: Dict[str, Any] = {"name": k, "value": v}
        try:
            arg["raw_value"] = int(v, 0)
        except (TypeError, ValueError):
            pass
        args.append(arg)
    for our_key, cape_name, fmt in _ARG_SPECS.get(api, []):
        if our_key in kv:
            v = kv[our_key]
            args.append({"name": cape_name, "value": fmt(v) if fmt else v})
    if not kvs and arg0:
        # Bare positional payload (a path, module name, command line, value
        # name, or marker like "poll"/"create") -- surface it under the
        # CAPE names signatures look for.
        seen = set()
        for _k, cape_name, _f in _ARG_SPECS.get(api, []):
            if cape_name not in seen:
                seen.add(cape_name)
                args.append({"name": cape_name, "value": arg0})
        args.append({"name": "value", "value": arg0})
    if api in _TARGET_PID_APIS and "target_pid" in kv:
        cross = kv.get("cross_process", "1") != "0"
        handle = _hx8(kv["target_pid"]) if cross else "0xffffffff"
        args.append({"name": "ProcessHandle", "value": handle})
        args.append({"name": "ThreadHandle", "value": handle})
        args.append({"name": "ProcessIdentifier", "value": kv["target_pid"]})
    return args


class CapeEngine:
    """Loads vendored CAPE community signatures and replays apitrace events.

    min_severity: community severity floor for EMITTING an alert (CAPE scale
    1-6; mirrors sigma's min_level policy of not surfacing noise levels).
    score: whether matches may contribute to the verdict (detectors.py gates
    on the "cape_score" flag); ship False until corpus validation passes.
    """

    def __init__(self, signature_dir: Path, min_severity: int = 1, score: bool = True):
        self._dir = Path(signature_dir)
        self._min_severity = min_severity
        self._score = score
        self.skipped_low_severity = 0
        self._signatures: List[type] = []
        self._class_files: Dict[str, Path] = {}
        self._load_errors: List[str] = []
        self._load()

    # ------------------------------------------------------------------
    # loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        install_compat_modules()
        if not self._dir.is_dir():
            self._load_errors.append(f"signature dir not found: {self._dir}")
            return
        seen_names = set()
        for path in sorted(self._dir.glob("*.py")):
            mod_name = f"cape_community_{path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec is None or spec.loader is None:
                    raise ImportError("no loader")
                module = importlib.util.module_from_spec(spec)
                # some signature modules print() at import time -- swallow it
                with contextlib.redirect_stdout(io.StringIO()):
                    spec.loader.exec_module(module)
            except Exception as exc:  # bad imports must not kill the set
                self._load_errors.append(f"{path.name}: {exc}")
                continue
            for obj in vars(module).values():
                if (
                    isinstance(obj, type)
                    and issubclass(obj, Signature)
                    and obj is not Signature
                    and getattr(obj, "name", "")
                ):
                    # all/ and windows/ overlap; helper base classes repeat --
                    # one instance per signature name.
                    if obj.name in seen_names:
                        continue
                    seen_names.add(obj.name)
                    self._signatures.append(obj)
                    self._class_files[obj.name] = path

    @property
    def signature_count(self) -> int:
        return len(self._signatures)

    @property
    def load_errors(self) -> List[str]:
        return list(self._load_errors)

    def get_rule_source(self, name: str) -> Optional[str]:
        """Raw Python source of the module defining a signature (lazy raw
        view in the rules catalog, like Sigma/YARA source)."""
        path = self._class_files.get(name)
        if not path or not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    # ------------------------------------------------------------------
    # catalog
    # ------------------------------------------------------------------

    def describe_signatures(self) -> List[Dict[str, Any]]:
        """Declarative inventory for the rules catalog (detector schema)."""
        out = []
        for cls in sorted(self._signatures, key=lambda c: c.name):
            out.append({
                "id": f"cape.{cls.name}",
                "family": "cape",
                "name": cls.description or cls.name,
                "severity": _SEVERITY_MAP.get(getattr(cls, "severity", 1), "low"),
                "kind": "evented" if getattr(cls, "evented", False) else "summary",
                "mitre": list(getattr(cls, "ttps", []) or []),
                "description": cls.description or cls.name,
                "detail": sorted(getattr(cls, "filter_apinames", set()) or []),
            })
        return out

    # ------------------------------------------------------------------
    # evaluation
    # ------------------------------------------------------------------

    def _build_results(self, events: List[Dict[str, Any]], lineage=None) -> Dict[str, Any]:
        """Translate apitrace ApiCall events into the Cuckoo results model."""
        processes: Dict[int, Dict[str, Any]] = {}
        order: List[int] = []
        summary = {
            "files": [], "read_files": [], "write_files": [], "delete_files": [],
            "keys": [], "read_keys": [], "write_keys": [], "delete_keys": [],
            "mutexes": [], "started_services": [], "created_services": [],
            "executed_commands": [],
        }
        pid_names: Dict[int, str] = {}
        children: Dict[int, set] = {}
        lineage_pids = set(getattr(lineage, "pids", None) or ())

        def _in_scope(pid) -> bool:
            # No lineage available (unit tests, pre-scoping callers): include.
            if not lineage_pids:
                return True
            return pid in lineage_pids

        for e in events:
            et = e.get("event_type")
            d = e.get("data") or {}
            # Process names + lineage come from Sysmon process-creation telemetry.
            if et == "ProcessCreate":
                try:
                    pid = int(d.get("ProcessId"))
                except (TypeError, ValueError):
                    pid = None
                try:
                    ppid = int(d.get("ParentProcessId"))
                except (TypeError, ValueError):
                    ppid = None
                image = d.get("Image")
                if pid and image:
                    pid_names.setdefault(pid, str(image).rsplit("\\", 1)[-1])
                if pid and ppid:
                    children.setdefault(ppid, set()).add(pid)
                cmdline = d.get("CommandLine")
                if cmdline and _in_scope(pid):
                    summary["executed_commands"].append(str(cmdline))
                continue
            if e.get("source") != "apitrace" or et != "ApiCall":
                continue
            api = d.get("Api") or ""
            if api.startswith("__"):
                continue  # monitor meta events (attach/cap/pipe-lost)
            category = _CATEGORY_MAP.get(d.get("Category") or "", "misc")
            pid = d.get("ProcessId")
            tid = d.get("ThreadId")
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                continue

            kv = dict(_KV_RE.findall(d.get("Arg0") or ""))

            # Authoritative lineage from the same stream: the monitor emits
            # child_pid= on every process-creation call.
            if api in ("CreateProcessW", "NtCreateUserProcess") and (kv.get("child_pid") or "").isdigit():
                children.setdefault(pid, set()).add(int(kv["child_pid"]))

            # Same guard as behavioral_signatures: kernel32 writes the
            # parameter block into (and resumes the initial thread of) every
            # just-created child -- routine process spawning, not injection.
            if api in ("NtWriteVirtualMemory", "NtResumeThread"):
                tgt = kv.get("target_pid")
                if tgt and tgt.isdigit() and int(tgt) in children.get(pid, ()):
                    continue

            call = {
                "timestamp": str(e.get("timestamp") or ""),
                "thread_id": str(tid or ""),
                "category": category,
                "api": api,
                "status": True,
                "return": "0x0",
                "repeated": 0,
                "arguments": _parse_args(api, d.get("Arg0") or ""),
            }

            proc = processes.get(pid)
            if proc is None:
                proc = processes[pid] = {
                    "process_id": pid,
                    "process_name": "",
                    "calls": [],
                    "environ": {},
                }
                order.append(pid)
            proc["calls"].append(call)

            # Summaries (best-effort from the hooked subset), sample-lineage
            # only -- see evaluate()'s docstring.
            if not _in_scope(pid):
                continue
            if api in ("NtCreateFile", "CreateFileW"):
                path = self._first_arg(call, "FilePath") or (d.get("Arg0") or "")
                if path:
                    summary["files"].append(path)
            elif api == "NtSetValueKey":
                val = self._first_arg(call, "ValueName") or (d.get("Arg0") or "")
                if val:
                    summary["keys"].append(val)
                    summary["write_keys"].append(val)
            elif api == "CreateProcessW":
                cmdline = d.get("Arg0") or ""
                if cmdline:
                    summary["executed_commands"].append(cmdline)

        # Enrich process names from Sysmon (best effort; empty is fine).
        for pid, name in pid_names.items():
            if pid in processes:
                processes[pid]["process_name"] = name

        return {
            # Several signatures guard on results["info"]["package"] /
            # results["target"] in __init__ -- provide minimal sane values.
            "info": {"package": "exe", "id": "offline"},
            "target": {"category": "file", "file": {"path": ""}},
            "behavior": {
                "processes": [processes[p] for p in order],
                "summary": summary,
            },
            "network": {"hosts": [], "domains": [], "http": []},
            "signatures": [],
        }

    @staticmethod
    def _first_arg(call: Dict[str, Any], name: str) -> Optional[str]:
        for a in call["arguments"]:
            if a["name"] == name:
                return a["value"]
        return None

    def evaluate(self, events: List[Dict[str, Any]], lineage=None) -> List[Dict[str, Any]]:
        """Replay events through all signatures; return one alert per match.

        lineage (optional PidLineage): when provided and non-empty, the
        behavior SUMMARIES (executed_commands / files / keys) are built only
        from the sample's own process tree -- command-scanning summary sigs
        (clears_logs, suspicious_command_tools, ...) otherwise fire on the
        sandbox's own tooling and the harness launcher, identically on
        benign and malicious runs (measured 2026-07-27).
        """
        self.skipped_low_severity = 0
        self._scoping_active = bool(getattr(lineage, "pids", None))
        results = self._build_results(events, lineage)
        processes = results["behavior"]["processes"]
        if not processes:
            return []

        # Partition exactly like CAPE's RunSignatures: a signature is evented
        # only if it OVERRIDES on_call; everything else (including
        # evented=True classes that only implement run()/on_complete) goes to
        # the run() list.
        evented = []
        runners = []
        for cls in self._signatures:
            if not getattr(cls, "enabled", True):
                continue
            # file-analysis only set (skip url-only signatures)
            fat = getattr(cls, "filter_analysistypes", set()) or set()
            if fat and "file" not in fat:
                continue
            is_evented = (
                getattr(cls, "evented", False)
                and getattr(cls.on_call, "__module__", None) != getattr(Signature.on_call, "__module__", None)
            )
            (evented if is_evented else runners).append(cls)
        runners.sort(key=lambda c: getattr(c, "order", 0))

        alerts: List[Dict[str, Any]] = []
        matched_results: List[Dict[str, Any]] = []

        # --- evented dispatch ---
        instances = []
        for cls in evented:
            try:
                instances.append(cls(results))
            except Exception as exc:
                logger.debug("cape sig %s init failed: %s", cls.name, exc)
        for proc in processes:
            for cid, call in enumerate(proc["calls"]):
                aliases = set(_API_ALIASES.get(call["api"], [call["api"]]))
                for sig in instances:
                    if sig.matched:
                        continue
                    fa = sig.filter_apinames
                    if fa and not (set(fa) & aliases):
                        continue
                    fc = sig.filter_categories
                    if fc and call["category"] not in fc:
                        continue
                    fp = sig.filter_processnames
                    if fp and proc["process_name"].lower() not in {p.lower() for p in fp}:
                        continue
                    sig.pid = proc["process_id"]
                    sig.cid = cid
                    sig.call = call
                    try:
                        result = sig.on_call(call, proc)
                    except NotImplementedError:
                        result = False
                    except Exception as exc:
                        logger.debug("cape sig %s on_call failed: %r", sig.name, exc)
                        result = False
                    if result:
                        # matched: on_complete is NOT executed (CAPE semantics)
                        sig.matched = True
        for sig in instances:
            if sig.matched:
                res = sig.as_result()
                matched_results.append(res)
                alert = self._emit_match(sig, res, events)
                if alert:
                    alerts.append(alert)
                continue
            try:
                done = sig.on_complete()
            except NotImplementedError:
                continue
            except Exception as exc:
                logger.debug("cape sig %s on_complete failed: %r", sig.name, exc)
                continue
            if done:
                res = sig.as_result()
                matched_results.append(res)
                alert = self._emit_match(sig, res, events)
                if alert:
                    alerts.append(alert)

        results["signatures"] = matched_results

        # --- non-evented (run()) signatures, in order; match = truthy return ---
        for cls in runners:
            try:
                sig = cls(results)
                outcome = sig.run()
            except NotImplementedError:
                continue
            except Exception as exc:
                logger.debug("cape sig %s run failed: %r", getattr(cls, "name", "?"), exc)
                continue
            if outcome:
                res = sig.as_result()
                matched_results.append(res)
                results["signatures"] = matched_results  # meta-sigs see earlier matches
                alert = self._emit_match(sig, res, events)
                if alert:
                    alerts.append(alert)

        return alerts

    # ------------------------------------------------------------------
    # alert shaping
    # ------------------------------------------------------------------

    def _emit_match(self, sig: Signature, res: Dict[str, Any], events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """min_severity gate (mirrors sigma's min_level): matches below the
        floor are counted for transparency but not surfaced as alerts."""
        if (res.get("severity") or 1) < self._min_severity:
            self.skipped_low_severity += 1
            return None
        return self._build_alert(sig, res, events)

    def _build_alert(self, sig: Signature, res: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
        ttps = [t for t in (getattr(sig, "ttps", []) or []) if isinstance(t, str) and t.startswith("T")]
        mitre_candidates = [{"technique_id": t, "technique_name": "", "tactic": ""} for t in ttps]
        evidence: List[str] = []
        actor_pid = None
        for block in (res.get("new_data") or [])[:3]:
            proc = block.get("process") or {}
            if actor_pid is None and proc.get("process_id"):
                actor_pid = proc["process_id"]
            for sign in (block.get("signs") or [])[:2]:
                evidence.append(f"{sign.get('type')}: {str(sign.get('value'))[:120]}")
        for mark in (res.get("data") or [])[:2]:
            if mark.get("type") == "call":
                if actor_pid is None:
                    actor_pid = mark.get("pid")
                evidence.append(f"call pid={mark.get('pid')} cid={mark.get('cid')}")
        alert: Dict[str, Any] = {
            "source": "cape",
            "provider_name": "CapeSignatures",
            "event_id": CAPE_SIGNATURE_EVENT_ID,
            "event_type": "CapeSignature",
            "timestamp": events[-1].get("timestamp") if events else None,
            # verdict contribution gate (detectors.py) + UI severity coloring
            "cape_score": self._score,
            "severity": _SEVERITY_MAP.get(res.get("severity", 1), "low"),
            "data": {
                "Type": res["name"],
                "Name": res["name"],
                # lets pid_lineage.classify_alert_scope attribute the match
                "ProcessId": actor_pid,
                "Description": res.get("description") or "",
                "Severity": res.get("severity", 1),
                "SeverityStr": _SEVERITY_MAP.get(res.get("severity", 1), "low"),
                "Categories": res.get("categories") or [],
                "Families": res.get("families") or [],
                "Evidence": evidence[:6],
            },
            "mitre": {
                "primary": mitre_candidates[0] if mitre_candidates else None,
                "candidates": mitre_candidates[1:] if mitre_candidates else [],
            },
        }
        # Matches WITHOUT an actor pid come from the lineage-scoped summaries
        # by construction (commands/files/keys of the sample's own tree), so
        # they are sample-scoped even though classify_alert_scope couldn't
        # attribute them -- same convention as the dump/dropped-file YARA
        # matches, whose inputs are likewise pre-scoped upstream. Without
        # this they'd sink into the environment-noise section.
        if actor_pid is None and self._scoping_active:
            alert["in_sample_scope"] = True
        return alert


_ENGINE_CACHE: Dict[str, "CapeEngine"] = {}


def get_engine(cfg) -> Optional[CapeEngine]:
    """Cached engine built from SandboxConfig (config.yaml::cape_signatures).
    Returns None when the integration is disabled or no dir is configured.
    Loading 458 modules takes ~1-2s, hence the process-wide cache -- same
    pattern as the Sigma engine singleton in main.py, but callable from the
    offline replay tooling too (one alert-assembly path)."""
    section = getattr(cfg, "cape_signatures", None) or {}
    if not section.get("enabled", False):
        return None
    sig_dir = section.get("dir") or "cape_signatures"
    key = f"{sig_dir}|{section.get('min_severity', 1)}|{section.get('score', False)}"
    if key not in _ENGINE_CACHE:
        _ENGINE_CACHE[key] = CapeEngine(
            Path(sig_dir),
            min_severity=int(section.get("min_severity", 1)),
            score=bool(section.get("score", False)),
        )
    return _ENGINE_CACHE[key]
