"""Guest-side telemetry collector for the sandbox.

Runs inside the analysis VM. Supports multiple telemetry sources:
  - sysmon      : primary (process, file, registry, network, DNS, etc.)
  - etw_ti      : experimental ETW Threat-Intelligence (injection chains)
  - amsi        : AMSI scan content
  - wmi_etw     : WMI-Activity ETW (persistence: temporary/permanent consumers)
  - powershell  : PowerShell script block logging
  - security_log: Windows Security event log (logon, account mgmt, service install, etc.)
  - system_log  : Windows System event log (service crashes/installs, NTFS corruption, etc.)
  - defender_log: Windows Defender operational log (detections, tamper/config changes)
  - apitrace     : argument-level Win32/Native API events from the Track 3
                    behavioral monitor (agent/windows/monitor_src), written by
                    apitrace_collector.py to apitrace.jsonl. Unlike every other
                    source here, its START/STOP lifecycle is NOT managed by
                    init()/collect() -- it's a long-lived guest process the
                    orchestrator starts before the sample launches and stops
                    right before calling collect() (mirrors network capture's
                    start-before/stop-after, executor.py). collect() only
                    READS whatever apitrace.jsonl already contains by then.
  - guardian     : SandboxGuard.sys driver events (protection denials, module
                    remap, injection placement) drained by guardian_agent.py
                    to guardian.jsonl. Same lifecycle carve-out as apitrace:
                    collect() only READS the file.

Usage inside the guest:
    python telemetry_collector.py init          # install sources, clear logs, write baseline
    python telemetry_collector.py collect       # collect events since baseline, write JSONL
"""

import argparse
import json
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

import proc_util
from sysmon_manager import SysmonManager
from sysmon_parser import SysmonParser
from etw_ti_collector import EtwTiCollector
from powershell_logging_manager import PowerShellLoggingManager
from powershell_parser import POWERSHELL_LOG_NAME, PowerShellParser
from amsi_collector import AmsiCollector
from wmi_collector import WmiCollector
from security_audit_manager import SecurityAuditManager
from security_log_parser import SECURITY_LOG_NAME, SecurityLogParser
from system_log_parser import SYSTEM_LOG_NAME, SystemLogParser
from defender_log_parser import DEFENDER_LOG_NAME, DefenderLogParser


BASELINE_FILE = Path("C:\\SandboxAgent\\telemetry_baseline.json")
OUTPUT_FILE = Path("C:\\SandboxAgent\\telemetry.jsonl")
# Matches behavioral_tracing.guest_apitrace_file's default in config.yaml.
APITRACE_FILE = Path("C:\\SandboxAgent\\apitrace.jsonl")
# Synthetic event_id for apitrace events -- outside both the real Sysmon EID
# range and heuristics.py's own synthetic range (9101-9104), so it can't
# collide with an indexed Sigma rule or a heuristics-emitted alert.
APITRACE_SYNTHETIC_EVENT_ID = 9200


# Matches guardian.guest_output_file's default in config.yaml. Events are
# already normalized by guardian_agent.py (source "guardian", synthetic EIDs
# 9400-9405) -- collect() just passes them through.
GUARDIAN_FILE = Path("C:\\SandboxAgent\\guardian.jsonl")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_baseline(sources: List[str]) -> None:
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "sources": sources,
        "baseline_time": _utc_now_iso(),
        "created": _utc_now_iso(),
    }
    BASELINE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _read_baseline() -> Dict:
    if not BASELINE_FILE.exists():
        raise RuntimeError("Baseline not found. Run 'telemetry_collector.py init' first.")
    return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))


class TelemetryCollector:
    def __init__(self, sources: Optional[List[str]] = None):
        self.sources = sources or ["sysmon"]
        self.events: List[Dict] = []

    @staticmethod
    def _clear_log(log_name: str, label: str) -> None:
        """Clear an event-log channel so collect() only sees this analysis.
        Non-fatal: a failed clear just means some pre-baseline events survive,
        which the since-baseline query already filters out anyway.
        """
        result = proc_util.run_text(["wevtutil", "cl", log_name])
        if result.returncode != 0:
            print(f"[telemetry] warning: could not clear {label} log: {result.stderr.strip()}")

    def init(self) -> None:
        """Install/enable telemetry sources and record baseline timestamp."""
        if "sysmon" in self.sources:
            print("[telemetry] ensuring Sysmon is installed")
            SysmonManager().ensure_running()
            print("[telemetry] updating Sysmon configuration")
            SysmonManager().update_config()
            self._clear_log("Microsoft-Windows-Sysmon/Operational", "Sysmon")

        if "etw_ti" in self.sources:
            # ETW-Ti is captured by the boot autologger (etw_ti_manager.py,
            # configured in the golden image) -- there's nothing to start per
            # run; the session is already running from boot. Just report whether
            # the provider is even present so an operator can tell config from
            # capability problems.
            available = EtwTiCollector().is_available()
            print(f"[telemetry] ETW-Ti provider available: {available} (captured via boot autologger)")

        if "powershell" in self.sources:
            print("[telemetry] ensuring PowerShell script-block logging is enabled")
            PowerShellLoggingManager().ensure_enabled()
            self._clear_log(POWERSHELL_LOG_NAME, "PowerShell")

        if "amsi" in self.sources:
            print("[telemetry] starting AMSI trace session")
            AmsiCollector().start()

        if "wmi_etw" in self.sources:
            print("[telemetry] starting WMI-Activity trace session")
            WmiCollector().start()

        if "security_log" in self.sources:
            print("[telemetry] ensuring Security-log audit policy covers the vendored Sigma ruleset")
            SecurityAuditManager().ensure_enabled()
            self._clear_log(SECURITY_LOG_NAME, "Security")

        if "system_log" in self.sources:
            print("[telemetry] clearing System log for a clean baseline")
            self._clear_log(SYSTEM_LOG_NAME, "System")

        if "defender_log" in self.sources:
            print("[telemetry] clearing Windows Defender operational log for a clean baseline")
            self._clear_log(DEFENDER_LOG_NAME, "Defender")

        _write_baseline(self.sources)
        print(f"[telemetry] baseline recorded at {_utc_now_iso()}")

    def _collect_source(
        self,
        name: str,
        collect_fn: Callable[[], List[Dict]],
        all_events: List[Dict],
    ) -> int:
        """Run one source's collection, isolating its failures. A single
        source blowing up (e.g. a wevtutil hiccup or an unmappable byte in a
        captured stream) must not throw away the telemetry other sources
        already gathered -- we record the failure and carry on so the run
        still produces a report from whatever succeeded.

        On failure we emit a synthetic ``SourceCollectionError`` event into
        the telemetry stream itself (not just stderr, which is redirected to a
        guest log the snapshot revert wipes). That makes a silently-empty
        source visible in the copied-back report -- "0 events" then reads as
        either a real failure (an error event is present, with the exception
        and traceback) or a genuine empty result (no error event), which is
        exactly what's needed to tell those two apart.
        """
        print(f"[telemetry] collecting {name} events")
        try:
            events = collect_fn()
        except Exception as exc:  # noqa: BLE001 -- deliberately broad, see docstring
            print(f"[telemetry] ERROR collecting {name}: {exc!r}")
            traceback.print_exc()
            all_events.append(
                {
                    "source": "telemetry_agent",
                    "event_type": "SourceCollectionError",
                    "timestamp": _utc_now_iso(),
                    "data": {
                        "failed_source": name,
                        "error": repr(exc),
                        "traceback": traceback.format_exc(),
                    },
                }
            )
            return -1
        all_events.extend(events)
        print(f"[telemetry] {name} events: {len(events)}")
        return len(events)

    @staticmethod
    def _collect_apitrace() -> List[Dict]:
        """Read apitrace.jsonl (already stopped by the caller by this point --
        see the module docstring) and normalize each line into the same event
        shape every other source emits ({source, event_id, timestamp,
        event_type, data}), so it merge-sorts and displays alongside Sysmon/
        AMSI/etc. without special-casing downstream. A malformed line is
        skipped rather than aborting the whole collection -- one corrupt
        record (e.g. a partial write from a force-killed collector) must not
        cost every other captured API call.
        """
        if not APITRACE_FILE.exists():
            return []
        events: List[Dict] = []
        with APITRACE_FILE.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                try:
                    timestamp = datetime.fromtimestamp(float(raw.get("ts")), tz=timezone.utc).isoformat()
                except (TypeError, ValueError):
                    timestamp = _utc_now_iso()
                events.append(
                    {
                        "source": "apitrace",
                        "event_id": APITRACE_SYNTHETIC_EVENT_ID,
                        "timestamp": timestamp,
                        "event_type": "ApiCall",
                        "data": {
                            "Api": raw.get("api"),
                            "Category": raw.get("category"),
                            "ProcessId": raw.get("pid"),
                            "ThreadId": raw.get("tid"),
                            "Arg0": raw.get("arg0"),
                        },
                    }
                )
        return events

    @staticmethod
    def _collect_guardian() -> List[Dict]:
        """Read guardian.jsonl (already stopped by the caller -- same contract
        as apitrace). guardian_agent.py writes fully-normalized events, so
        this is a pass-through; malformed lines are skipped, not fatal."""
        if not GUARDIAN_FILE.exists():
            return []
        events: List[Dict] = []
        with GUARDIAN_FILE.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events

    def _probe_windows_log(self, log_name: str, all_events: List[Dict]) -> None:
        """One-shot diagnostic emitted when a Windows event-log source comes
        back empty or failed: directly query the log for a single record and
        capture this session's token integrity level, so "why 0 events" can be
        answered from the copied-back report. The leading hypothesis for the
        Security log is that reading it needs a *high*-integrity (elevated)
        token, which the PowerShell Direct session's filtered admin token may
        lack -- whoami's Mandatory Label SID (S-1-16-12288 High vs 8192
        Medium) plus wevtutil's own return code / stderr settle that directly.
        """
        data: Dict = {"log_name": log_name}
        try:
            probe = proc_util.run_text(["wevtutil", "qe", log_name, "/c:1", "/f:text"])
            data["wevtutil_returncode"] = probe.returncode
            data["wevtutil_stderr"] = (probe.stderr or "").strip()[:500]
            data["wevtutil_stdout_head"] = (probe.stdout or "").strip()[:200]
        except Exception as exc:  # noqa: BLE001
            data["wevtutil_probe_error"] = repr(exc)
        try:
            who = proc_util.run_text(["whoami", "/groups"])
            data["whoami_returncode"] = who.returncode
            data["integrity_lines"] = "\n".join(
                line.strip() for line in (who.stdout or "").splitlines() if "S-1-16-" in line
            )[:400]
        except Exception as exc:  # noqa: BLE001
            data["whoami_probe_error"] = repr(exc)
        print(f"[telemetry] emitted SourceDiagnostic for empty/failed log: {log_name}")
        all_events.append(
            {
                "source": "telemetry_agent",
                "event_type": "SourceDiagnostic",
                "timestamp": _utc_now_iso(),
                "data": data,
            }
        )

    def collect(self) -> List[Dict]:
        """Collect events from all configured sources since baseline."""
        baseline = _read_baseline()
        since = baseline.get("baseline_time")
        all_events: List[Dict] = []

        if "sysmon" in self.sources:
            self._collect_source("Sysmon", lambda: SysmonParser().query_events(since_iso=since), all_events)

        if "etw_ti" in self.sources:
            self._collect_source("ETW-Ti", lambda: EtwTiCollector().collect(since_iso=since), all_events)

        if "powershell" in self.sources:
            self._collect_source("PowerShell", lambda: PowerShellParser().query_events(since_iso=since), all_events)

        if "amsi" in self.sources:
            self._collect_source("AMSI", lambda: AmsiCollector().collect(since_iso=since), all_events)

        if "wmi_etw" in self.sources:
            self._collect_source("WMI-Activity", lambda: WmiCollector().collect(since_iso=since), all_events)

        if "security_log" in self.sources:
            n = self._collect_source("Security", lambda: SecurityLogParser().query_events(since_iso=since), all_events)
            if n <= 0:
                self._probe_windows_log(SECURITY_LOG_NAME, all_events)

        if "system_log" in self.sources:
            n = self._collect_source("System", lambda: SystemLogParser().query_events(since_iso=since), all_events)
            if n <= 0:
                self._probe_windows_log(SYSTEM_LOG_NAME, all_events)

        if "defender_log" in self.sources:
            n = self._collect_source("Defender", lambda: DefenderLogParser().query_events(since_iso=since), all_events)
            if n <= 0:
                self._probe_windows_log(DEFENDER_LOG_NAME, all_events)

        if "apitrace" in self.sources:
            self._collect_source("Apitrace", self._collect_apitrace, all_events)

        if "guardian" in self.sources:
            self._collect_source("Guardian", self._collect_guardian, all_events)

        # Sort by timestamp for a unified timeline
        all_events.sort(key=lambda e: e.get("timestamp") or "")

        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with OUTPUT_FILE.open("w", encoding="utf-8") as fh:
            for ev in all_events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")

        print(f"[telemetry] wrote {len(all_events)} events to {OUTPUT_FILE}")
        return all_events


AGENT_LOG_FILE = Path("C:\\SandboxAgent\\telemetry_agent.log")


def _harden_console() -> None:
    """Keep the guest telemetry command from ever failing the analysis via
    its own output streams. Two distinct hazards, two fixes:

    stdout -- lenient encode. The guest console codepage (cp1252 on this VM)
    can't encode every character that shows up in event content; a bare
    print() of such a character would raise UnicodeEncodeError and abort.

    stderr -- REDIRECT to a log file, not just reconfigure. This process is
    launched via PowerShell Direct's Invoke-Command, which turns *any* bytes
    a native command writes to stderr into a NativeCommandError that fails
    the whole telemetry_collect step -- even when the process exits 0. That
    is the real reason every stray Python traceback, thread-exception dump,
    or warning killed the run (the reader-thread decode crash was just the
    most common source of such stderr). Routing Python's stderr to a
    guest-local log keeps diagnostics without ever touching the console
    stderr PowerShell is watching. Child processes don't leak to the console
    either: their output is captured via pipes (proc_util.run_text), not
    inherited fd 2.
    """
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    try:
        AGENT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        sys.stderr = open(AGENT_LOG_FILE, "a", encoding="utf-8", errors="replace")
    except OSError:
        pass


def main() -> int:
    _harden_console()
    parser = argparse.ArgumentParser(description="Guest-side sandbox telemetry collector")
    parser.add_argument(
        "action",
        choices=["init", "collect"],
        help="init: install sources and record baseline; collect: gather events since baseline",
    )
    parser.add_argument(
        "--sources",
        default="sysmon",
        help="Comma-separated telemetry sources (default: sysmon)",
    )
    args = parser.parse_args()

    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    collector = TelemetryCollector(sources=sources)

    if args.action == "init":
        collector.init()
    elif args.action == "collect":
        collector.collect()

    return 0


if __name__ == "__main__":
    sys.exit(main())
