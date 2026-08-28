"""AMSI (Antimalware Scan Interface) telemetry via the
Microsoft-Antimalware-Scan-Interface ETW provider.

Captures the actual script/buffer content passed through AMSI-integrated
scanners (PowerShell, WSH, Office macros, etc.) -- the payload itself,
decoded, not just "a scan happened." Confirmed working at Administrator-
level ETW sessions (unlike Microsoft-Windows-Threat-Intelligence, which
needs PPL -- see docs/detection-gap-tracker.md).

Provider GUID verified empirically this session (captured real events via a
raw logman+tracerpt session and inspected the decoded XML directly) -- it
does NOT match the commonly-cited manifest GUID from third-party AMSI
*provider* implementations like SimpleAmsiProvider (those register a COM
component that receives scan requests, a different thing from the ETW
*event* provider Windows itself uses to log scan results system-wide).
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import proc_util
from etw_common import filetime_to_iso, parse_etl_file, start_logman_session, stop_logman_session

AMSI_PROVIDER_NAME = "Microsoft-Antimalware-Scan-Interface"
AMSI_SCAN_EVENT_ID = 1101
SESSION_NAME = "SandboxAmsi"

# AMSI is system-wide, not scoped to the sample process -- verified
# empirically that even a few seconds of capture can produce tens of
# thousands of events on a busy host.
MAX_EVENTS = 5000
MAX_CONTENT_CHARS = 4000


def _decode_content(hex_str: Optional[str]) -> str:
    """AMSI's scanned content arrives as a "0x..."-prefixed hex string of
    UTF-16LE bytes (verified empirically against real captured events).
    """
    if not hex_str or not hex_str.startswith("0x"):
        return ""
    try:
        raw = bytes.fromhex(hex_str[2:])
        text = raw.decode("utf-16le", errors="replace")
    except ValueError:
        return ""
    if len(text) > MAX_CONTENT_CHARS:
        return text[:MAX_CONTENT_CHARS] + "...(truncated)"
    return text


def _decode_amsi_event(event_id: int, event_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    header = event_dict.get("EventHeader") or {}
    timestamp_raw = header.get("TimeStamp")
    timestamp = filetime_to_iso(timestamp_raw) if timestamp_raw else None
    return {
        "source": "amsi",
        "provider_name": AMSI_PROVIDER_NAME,
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": "AmsiScanDetected",
        "data": {
            "ProcessId": header.get("ProcessId"),
            "ThreadId": header.get("ThreadId"),
            "AppName": event_dict.get("appname"),
            "ContentName": event_dict.get("contentname"),
            "ContentSize": event_dict.get("contentsize"),
            "ScanResult": event_dict.get("scanResult"),
            "ScanStatus": event_dict.get("scanStatus"),
            "ContentFiltered": event_dict.get("contentFiltered"),
            "Hash": event_dict.get("hash"),
            "Content": _decode_content(event_dict.get("content")),
        },
    }


class AmsiCollector:
    def __init__(self, output_dir: Path = Path("C:\\SandboxAgent")):
        self.output_dir = Path(output_dir)
        self.etl_path = self.output_dir / "amsi.etl"
        self._started = False

    def is_available(self) -> bool:
        """Best-effort check that the AMSI ETW provider is registered."""
        try:
            proc = proc_util.run_text(
                ["logman", "query", "providers", AMSI_PROVIDER_NAME],
                timeout=10,
            )
            return proc.returncode == 0 and AMSI_PROVIDER_NAME in proc.stdout
        except Exception:
            return False

    def start(self) -> bool:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.etl_path.exists():
            self.etl_path.unlink()
        ok = start_logman_session(SESSION_NAME, AMSI_PROVIDER_NAME, str(self.etl_path))
        self._started = ok
        if ok:
            print(f"[amsi] trace session started; ETL={self.etl_path}")
        else:
            print("[amsi] failed to start trace session")
        return ok

    def collect(self, since_iso: Optional[str] = None) -> List[Dict[str, Any]]:
        """Stop the session and decode the ETL file. since_iso is accepted
        for interface parity with other collectors but not used to filter --
        the whole capture window is one analysis run, so everything in the
        ETL is in scope.

        init() and collect() run as separate subprocess invocations (see
        telemetry_collector.py), so self._started from a start() call in a
        different process isn't available here -- always attempt the stop;
        it's a harmless no-op if the session is already stopped.
        """
        stop_logman_session(SESSION_NAME)
        self._started = False

        if not self.etl_path.exists():
            print("[amsi] no ETL file found; nothing to collect")
            return []

        result = parse_etl_file(
            str(self.etl_path),
            event_id_filter=[AMSI_SCAN_EVENT_ID],
            field_decoder=_decode_amsi_event,
            max_events=MAX_EVENTS,
        )
        events = result["events"]
        if result["truncated"]:
            print(f"[amsi] WARNING: capped at {MAX_EVENTS} events; capture was truncated")
        print(f"[amsi] decoded {len(events)} scan events")
        return events


if __name__ == "__main__":
    collector = AmsiCollector()
    print(f"[amsi] available: {collector.is_available()}")
