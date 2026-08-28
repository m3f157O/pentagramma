"""Parse Sysmon events from the Windows Event Log into normalized JSON."""

import json
import xml.etree.ElementTree as ET

import proc_util
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
SYSMON_XML_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_xpath(since_iso: Optional[str] = None) -> str:
    """Build a wevtutil XPath query. If since_iso is None, fetch last 60 s."""
    if since_iso:
        # wevtutil expects ISO 8601 without timezone offset suffix
        dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00"))
        query_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return f"*[System[TimeCreated[@SystemTime >= '{query_time}']]]"
    return "*[System[TimeCreated[timediff(@SystemTime) <= 60000]]]"


class SysmonParser:
    def __init__(self, log_name: str = SYSMON_LOG_NAME):
        self.log_name = log_name

    def query_events(
        self,
        since_iso: Optional[str] = None,
        timeout: int = 60,
    ) -> List[Dict]:
        """Query Sysmon events from the event log and return normalized JSON."""
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
                    "Sysmon event log not found. Install Sysmon first: "
                    "python agent/windows/sysmon_manager.py install"
                )
            raise RuntimeError(f"wevtutil failed ({proc.returncode}): {err}")

        xml_data = proc.stdout.strip()
        if not xml_data:
            return []

        # wevtutil with /f:xml returns multiple <Event> roots; wrap them.
        if not xml_data.startswith("<?xml"):
            xml_data = f'<?xml version="1.0" encoding="UTF-8"?><Events>{xml_data}</Events>'

        return self._parse_xml(xml_data)

    def _parse_xml(self, xml_data: str) -> List[Dict]:
        ns = SYSMON_XML_NS
        events: List[Dict] = []

        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError:
            return events

        # Wevtutil may return a single root <Events> or raw <Event> elements.
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
                "source": "sysmon",
                "provider_name": "Microsoft-Windows-Sysmon",
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
            1: "ProcessCreate",
            2: "FileCreateTime",
            3: "NetworkConnect",
            5: "ProcessTerminate",
            6: "DriverLoad",
            7: "ImageLoad",
            8: "CreateRemoteThread",
            9: "RawAccessRead",
            10: "ProcessAccess",
            11: "FileCreate",
            12: "RegistryCreateDelete",
            13: "RegistryValueSet",
            14: "RegistryKeyValueRename",
            15: "FileCreateStreamHash",
            17: "PipeCreated",
            18: "PipeConnected",
            19: "WmiEventFilter",
            20: "WmiEventConsumer",
            21: "WmiEventConsumerToFilter",
            22: "DnsQuery",
            23: "FileDelete",
            24: "ClipboardChange",
            25: "ProcessTampering",
            26: "FileDeleteDetected",
            27: "FileBlockExecutable",
            28: "FileBlockShredding",
            29: "FileExecutableDetected",
        }
        return mapping.get(event_id, f"SysmonEvent{event_id}")

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
    import sys

    parser = SysmonParser()
    events = parser.query_events()
    out = Path("logs/sysmon_test.jsonl")
    count = parser.write_jsonl(events, out)
    print(f"[sysmon] wrote {count} events to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
