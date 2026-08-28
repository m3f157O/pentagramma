"""Parse PowerShell script-block-logging events from the Windows Event Log
into normalized JSON. Mirrors agent/windows/sysmon_parser.py's approach --
same generic Windows Event Log XML schema, same wevtutil-based query.
"""

import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import proc_util

POWERSHELL_LOG_NAME = "Microsoft-Windows-PowerShell/Operational"
EVENT_XML_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Only EID 4104 (script block text) is collected -- 4103 (module/pipeline
# logging) fires per-cmdlet-invocation and risks the same noise problem
# ImageLoad had before it was gated in orchestrator/heuristics.py.
SCRIPT_BLOCK_EVENT_ID = 4104


def _build_xpath(since_iso: Optional[str] = None) -> str:
    """Build a wevtutil XPath query for EID 4104 events. If since_iso is
    None, fetch the last 60 seconds.
    """
    if since_iso:
        dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00"))
        query_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return f"*[System[(EventID={SCRIPT_BLOCK_EVENT_ID}) and TimeCreated[@SystemTime >= '{query_time}']]]"
    return f"*[System[(EventID={SCRIPT_BLOCK_EVENT_ID}) and TimeCreated[timediff(@SystemTime) <= 60000]]]"


class PowerShellParser:
    def __init__(self, log_name: str = POWERSHELL_LOG_NAME):
        self.log_name = log_name

    def query_events(
        self,
        since_iso: Optional[str] = None,
        timeout: int = 60,
    ) -> List[Dict]:
        """Query script-block-logging events from the event log and return normalized JSON."""
        xpath = _build_xpath(since_iso)
        cmd = [
            "wevtutil",
            "qe",
            self.log_name,
            "/f:xml",
            f"/q:{xpath}",
        ]
        proc = proc_util.run_text(cmd, timeout=timeout)
        if proc.returncode != 0:
            err = proc.stderr.strip()
            if "The interface is unknown" in err or "not exist" in err.lower():
                raise RuntimeError(
                    "PowerShell Operational log not found. Ensure script-block "
                    "logging is enabled: python agent/windows/powershell_logging_manager.py ensure"
                )
            raise RuntimeError(f"wevtutil failed ({proc.returncode}): {err}")

        xml_data = proc.stdout.strip()
        if not xml_data:
            return []

        if not xml_data.startswith("<?xml"):
            xml_data = f'<?xml version="1.0" encoding="UTF-8"?><Events>{xml_data}</Events>'

        return self._parse_xml(xml_data)

    def _parse_xml(self, xml_data: str) -> List[Dict]:
        ns = EVENT_XML_NS
        events: List[Dict] = []

        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError:
            return events

        event_nodes = root.findall(f"{{{ns}}}Event")
        if not event_nodes and root.tag == f"{{{ns}}}Event":
            event_nodes = [root]

        for ev in event_nodes:
            system = ev.find(f"{{{ns}}}System")
            if system is None:
                continue

            event_id_el = system.find(f"{{{ns}}}EventID")
            time_created = system.find(f"{{{ns}}}TimeCreated")
            computer = system.find(f"{{{ns}}}Computer")

            event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0
            timestamp = time_created.get("SystemTime") if time_created is not None else None
            computer_name = computer.text if computer is not None else None

            event_data = ev.find(f"{{{ns}}}EventData")
            data: Dict[str, Optional[str]] = {}
            if event_data is not None:
                for field in event_data:
                    name = field.get("Name")
                    if name:
                        data[name] = field.text

            normalized = {
                "source": "powershell",
                "provider_name": "Microsoft-Windows-PowerShell",
                "event_id": event_id,
                "timestamp": timestamp,
                "computer": computer_name,
                "event_type": self._classify(event_id),
                "data": data,
            }
            events.append(normalized)

        return events

    def _classify(self, event_id: int) -> str:
        mapping = {
            4103: "ModuleLogged",
            4104: "ScriptBlockLogged",
        }
        return mapping.get(event_id, f"PowerShellEvent{event_id}")

    def write_jsonl(
        self,
        events: List[Dict],
        output_path: Path,
    ) -> int:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        return len(events)


def main() -> int:
    parser = PowerShellParser()
    events = parser.query_events()
    out = Path("logs/powershell_test.jsonl")
    count = parser.write_jsonl(events, out)
    print(f"[powershell] wrote {count} events to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
