"""ETW Threat-Intelligence (ETW-Ti) collector.

ETW-Ti surfaces kernel-visible operations that user-mode-hook-based tooling
(Sysmon) can miss:
  - cross-process memory alloc/write/protect (process hollowing, manual map)
  - remote thread creation / APC queue / SetThreadContext (injection)
  - RWX allocations before thread start

Provider: Microsoft-Windows-Threat-Intelligence {f4e1897c-bb5d-5668-f1d8-040f4d8dd344}

IMPORTANT capture constraint: the TI provider only delivers events to a
Protected-Process-Light (anti-malware) consumer or to a boot **autologger**.
A normal user/admin real-time session starts but usually receives nothing. So
the intended capture path is the boot autologger configured by
etw_ti_manager.py (applied ONCE to the golden image) -- this collector then
flushes that session's ETL at collect time and decodes it offline with
pywintrace (see etw_common.parse_etl_file, the same mechanism amsi_collector
uses). If no ETL / no events are present the collector returns [] cleanly, so
enabling this source can never break a run.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import proc_util
from etw_common import filetime_to_iso, parse_etl_file, stop_logman_session

ETW_TI_PROVIDER = "Microsoft-Windows-Threat-Intelligence"
ETW_TI_GUID = "{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}"

# Boot autologger (see etw_ti_manager.py) -- the reliable capture path.
AUTOLOGGER_NAME = "SandboxEtwTi"
AUTOLOGGER_ETL_PATH = Path("C:\\Windows\\Temp\\sandbox_etw_ti.etl")

MAX_EVENTS = 5000

# Best-effort friendly names. Event IDs vary by Windows build, so anything not
# listed still decodes (falls back to EtwTiEvent<id>) and the injection Sigma
# rule keys off the cross-process field pattern, not on a specific EventID.
ETW_TI_EVENT_IDS = {
    1: "AllocVm",
    2: "ProtectVm",
    3: "MapView",
    4: "QueueApc",
    5: "SetThreadContext",
    6: "CreateThread",
    7: "OpenProcess",
    8: "ReadVm",
    9: "WriteVm",
    10: "ImageLoad",
}

# Field-name variants the TI manifest may use for the *target* of a remote
# operation -- normalized to TargetProcessId so a rule can compare it against
# the calling process with |fieldref.
_TARGET_PID_KEYS = ("TargetProcessId", "targetProcessId", "TargetProcessID", "TargetPid")


def _decode_etw_ti_event(event_id: int, event_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    header = event_dict.get("EventHeader") or {}
    ts_raw = header.get("TimeStamp")
    data: Dict[str, Any] = {
        "CallingProcessId": header.get("ProcessId"),
        "CallingThreadId": header.get("ThreadId"),
    }
    # Pass every provider field through so nothing is lost regardless of the
    # build's exact schema (BaseAddress, RegionSize, ProtectionMask, ...).
    for key, value in event_dict.items():
        if key == "EventHeader":
            continue
        data[key] = value
    if "TargetProcessId" not in data:
        for alt in _TARGET_PID_KEYS:
            if alt in event_dict:
                data["TargetProcessId"] = event_dict[alt]
                break
    return {
        "source": "etw_ti",
        "provider_name": ETW_TI_PROVIDER,
        "event_id": event_id,
        "timestamp": filetime_to_iso(ts_raw) if ts_raw else None,
        "event_type": ETW_TI_EVENT_IDS.get(event_id, f"EtwTiEvent{event_id}"),
        "data": data,
    }


class EtwTiCollector:
    def __init__(self, session_name: str = AUTOLOGGER_NAME):
        self.session_name = session_name

    def is_available(self) -> bool:
        """True if the TI provider is registered on this system."""
        try:
            proc = proc_util.run_text(["logman", "query", "providers", ETW_TI_PROVIDER], timeout=10)
            return proc.returncode == 0 and ETW_TI_PROVIDER in proc.stdout
        except Exception:
            return False

    def collect(self, since_iso: Optional[str] = None) -> List[Dict[str, Any]]:
        """Flush the autologger session and decode its ETL. since_iso is
        accepted for interface parity but not used to filter -- the ETL only
        covers this boot (snapshot restore gives a fresh VM), so it's all in
        scope; downstream PID-lineage scoping trims it to the sample.
        """
        # Stopping the live autologger session flushes its buffers to the ETL
        # file. Harmless (returns nonzero) if it isn't running.
        stop_logman_session(self.session_name)

        p = AUTOLOGGER_ETL_PATH
        if not p.exists() or p.stat().st_size == 0:
            print("[etw-ti] no autologger ETL found (autologger not configured on this image?); nothing to collect")
            return []

        result = parse_etl_file(
            str(p),
            event_id_filter=[],  # decode every event -- the ETL is TI-provider-only
            field_decoder=_decode_etw_ti_event,
            max_events=MAX_EVENTS,
        )
        events = result["events"]
        if result["truncated"]:
            print(f"[etw-ti] WARNING: capped at {MAX_EVENTS} events; capture was truncated")
        print(f"[etw-ti] decoded {len(events)} events")
        return events

    def write_jsonl(self, events: List[Dict[str, Any]], output_path: Path) -> int:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        return len(events)


if __name__ == "__main__":
    collector = EtwTiCollector()
    print(f"[etw-ti] provider available: {collector.is_available()}")
