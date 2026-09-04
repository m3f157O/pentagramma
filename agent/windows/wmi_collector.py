"""WMI persistence telemetry via the Microsoft-Windows-WMI-Activity ETW
provider.

Closes the dead Sysmon EID 19/20/21 gap (see docs/detection-gap-tracker.md:
Sysmon on this guest emits zero WMI events even with a correct WmiEvent
config -- a known Sysmon/build limitation). WMI-Activity is NOT PPL-gated
(unlike ETW-TI), so a plain Administrator logman session works -- same
pattern as amsi_collector.py.

Events (WMI-Activity operational log IDs):
  5857  WmiOperation            -- generic provider activity (noisy: kept as
                                   events, not alerts)
  5858  WmiQueryFailure         -- failed WMI operations (kept, not alerted)
  5859  WmiFilterActivity       -- filter check activity (kept, not alerted)
  5860  WmiTemporaryConsumer    -- TEMPORARY event consumer registration
                                   (processes receiving WMI events until exit)
  5861  WmiPermanentConsumer    -- PERMANENT filter->consumer binding -- THE
                                   WMI persistence primitive (T1546.003)
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import proc_util
from etw_common import filetime_to_iso, parse_etl_file, start_logman_session, stop_logman_session

WMI_PROVIDER_NAME = "Microsoft-Windows-WMI-Activity"
SESSION_NAME = "SandboxWmi"

WMI_EVENT_TYPES = {
    5857: "WmiOperation",
    5858: "WmiQueryFailure",
    5859: "WmiFilterActivity",
    5860: "WmiTemporaryConsumer",
    5861: "WmiPermanentConsumer",
}

# Field names worth surfacing per event (decoded names come from the
# provider manifest, lowercased by pywintrace's TDH path; unknown extras are
# preserved under "raw" by the caller-side generic decoder anyway).
_INTERESTING_FIELDS = (
    "namespace", "ess", "consumer", "query", "possiblecause", "operation",
    "user", "clientmachine", "clientprocessid", "resultcode", "querylanguage",
    "correlationid", "groupoperationid", "operationid", "providername",
)

MAX_EVENTS = 5000


def _decode_wmi_event(event_id: int, event_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    event_type = WMI_EVENT_TYPES.get(event_id)
    if event_type is None:
        return None
    header = event_dict.get("EventHeader") or {}
    timestamp_raw = header.get("TimeStamp")
    data: Dict[str, Any] = {}
    for key, value in event_dict.items():
        if key == "EventHeader":
            continue
        lk = str(key).lower()
        if lk in _INTERESTING_FIELDS:
            data[key] = value
    data["ProcessId"] = header.get("ProcessId")
    return {
        "source": "wmi_etw",
        "provider_name": WMI_PROVIDER_NAME,
        "event_id": event_id,
        "timestamp": filetime_to_iso(timestamp_raw) if timestamp_raw else None,
        "event_type": event_type,
        "data": data,
    }


class WmiCollector:
    def __init__(self, output_dir: Path = Path("C:\\SandboxAgent")):
        self.output_dir = Path(output_dir)
        self.etl_path = self.output_dir / "wmi_activity.etl"
        self._started = False

    def is_available(self) -> bool:
        """Best-effort check that the WMI-Activity provider is registered."""
        try:
            proc = proc_util.run_text(
                ["logman", "query", "providers", WMI_PROVIDER_NAME],
                timeout=10,
            )
            return proc.returncode == 0 and WMI_PROVIDER_NAME in proc.stdout
        except Exception:
            return False

    def start(self) -> bool:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.etl_path.exists():
            self.etl_path.unlink()
        ok = start_logman_session(SESSION_NAME, WMI_PROVIDER_NAME, str(self.etl_path))
        self._started = ok
        if ok:
            print(f"[wmi] trace session started; ETL={self.etl_path}")
        else:
            print("[wmi] failed to start trace session")
        return ok

    def collect(self, since_iso: Optional[str] = None) -> List[Dict[str, Any]]:
        """Stop the session and decode the ETL. since_iso unused (the whole
        capture window is one run) -- see amsi_collector.py's collect() for
        the same interface-parity note.
        """
        stop_logman_session(SESSION_NAME)
        self._started = False

        if not self.etl_path.exists():
            print("[wmi] no ETL file found; nothing to collect")
            return []

        result = parse_etl_file(
            str(self.etl_path),
            event_id_filter=list(WMI_EVENT_TYPES),
            field_decoder=_decode_wmi_event,
            max_events=MAX_EVENTS,
        )
        events = result["events"]
        if result["truncated"]:
            print(f"[wmi] WARNING: capped at {MAX_EVENTS} events; capture was truncated")
        print(f"[wmi] decoded {len(events)} WMI-Activity events")
        return events


if __name__ == "__main__":
    collector = WmiCollector()
    print(f"[wmi] available: {collector.is_available()}")
