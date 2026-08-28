"""Generic Windows Event Log collector -- the query/parse recipe already
duplicated once (agent/windows/sysmon_parser.py, agent/windows/
powershell_parser.py -- the latter's own docstring says "mirrors
sysmon_parser.py's approach"): wevtutil qe <log_name> /f:xml /q:<xpath>,
a small XML->dict normalizer, a numeric-EventID->name table with a
numeric fallback. Security/System/Windows-Defender logs are three more
channels of the exact same shape -- this is the shared base so a 4th-6th
copy isn't pasted.

sysmon_parser.py/powershell_parser.py are left as-is (no regression risk
to two already-proven collectors); new sources build on this instead.
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import proc_util

XML_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Windows Event Log XPath (the /q filter wevtutil accepts) is limited to 20
# expressions per query, and each "EventID=N" term is one expression. A
# larger EventID set can't be filtered server-side -- wevtutil rejects it
# with error 15001 ("This operator is unsupported by this implementation of
# the filter / the specified query is invalid"). This bit the Security log
# specifically: its vendored ruleset references 43 distinct EventIDs, so the
# 43-term OR chain overflowed the limit and the whole source silently
# collected nothing (System/Defender, at 10 EIDs each, stayed under and were
# fine). Above the cap we drop the EventID clause from the query and filter
# by EventID in Python instead (see _parse_xml). The TimeCreated term is
# itself an expression, so the cap leaves headroom under 20.
_MAX_XPATH_EVENT_IDS = 18


class WindowsEventLogParser:
    def __init__(
        self,
        log_name: str,
        source: str,
        event_id_names: Optional[Dict[int, str]] = None,
        event_id_filter: Optional[List[int]] = None,
    ):
        """
        log_name: the Windows Event Log channel, e.g. "Security", "System",
            "Microsoft-Windows-Windows Defender/Operational".
        source: short label stamped on every normalized event's "source"
            field (e.g. "security", "system", "windefend") -- this is what
            orchestrator/sigma_engine.py's service-rule dispatch routes on.
        event_id_names: EventID -> human-readable event_type, same
            convention as sysmon_parser.py::_classify()'s table. Missing
            entries fall back to f"{source.capitalize()}Event{event_id}" --
            not a blocker for Sigma matching either way, since rule
            evaluation resolves the numeric EventID field directly; this
            is purely for report/UI readability.
        event_id_filter: if given, scopes the wevtutil query to only these
            EventIDs (mirrors powershell_parser.py's single-EID filter,
            generalized to a list) -- Security/System logs can carry much
            higher background volume than Sysmon's own curated operational
            log, so only pulling the EIDs the vendored Sigma ruleset
            actually references avoids collecting irrelevant noise.
        """
        self.log_name = log_name
        self.source = source
        self.event_id_names = event_id_names or {}
        self.event_id_filter = event_id_filter
        # Always enforced Python-side in _parse_xml, so filtering is correct
        # whether or not the query could express the EventID clause server-side.
        self._event_id_filter_set = set(event_id_filter) if event_id_filter else None

    def _build_xpath(self, since_iso: Optional[str] = None) -> str:
        id_clause = ""
        if self.event_id_filter and len(self.event_id_filter) <= _MAX_XPATH_EVENT_IDS:
            ids = " or ".join(f"EventID={eid}" for eid in self.event_id_filter)
            id_clause = f"({ids}) and "
        if since_iso:
            dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00"))
            query_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            return f"*[System[{id_clause}TimeCreated[@SystemTime >= '{query_time}']]]"
        return f"*[System[{id_clause}TimeCreated[timediff(@SystemTime) <= 60000]]]"

    def query_events(self, since_iso: Optional[str] = None, timeout: int = 60) -> List[Dict]:
        xpath = self._build_xpath(since_iso)
        cmd = ["wevtutil", "qe", self.log_name, "/f:xml", f"/q:{xpath}"]
        proc = proc_util.run_text(cmd, timeout=timeout)
        if proc.returncode != 0:
            err = proc.stderr.strip()
            raise RuntimeError(f"wevtutil failed for '{self.log_name}' ({proc.returncode}): {err}")

        xml_data = proc.stdout.strip()
        if not xml_data:
            return []
        if not xml_data.startswith("<?xml"):
            xml_data = f'<?xml version="1.0" encoding="UTF-8"?><Events>{xml_data}</Events>'
        return self._parse_xml(xml_data)

    def _parse_xml(self, xml_data: str) -> List[Dict]:
        ns = XML_NS
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
            provider = system.find(f"{{{ns}}}Provider")

            event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0
            # Python-side EventID filter: authoritative when the query could
            # not express the clause server-side (large filters, e.g. the
            # Security log's 43 EIDs -- see _MAX_XPATH_EVENT_IDS), and a
            # harmless no-op when it could.
            if self._event_id_filter_set is not None and event_id not in self._event_id_filter_set:
                continue
            timestamp = time_created.get("SystemTime") if time_created is not None else None
            computer_name = computer.text if computer is not None else None
            provider_name = provider.get("Name") if provider is not None else None

            event_data = ev.find(f"{{{ns}}}EventData")
            data: Dict[str, Optional[str]] = {}
            if event_data is not None:
                for field in event_data:
                    name = field.get("Name")
                    if name:
                        data[name] = field.text

            normalized = {
                "source": self.source,
                "provider_name": provider_name,
                "event_id": event_id,
                "timestamp": timestamp,
                "computer": computer_name,
                "event_type": self.event_id_names.get(event_id, f"{self.source.capitalize()}Event{event_id}"),
                "data": data,
            }
            events.append(normalized)

        return events

    def write_jsonl(self, events: List[Dict], output_path: Path) -> int:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        return len(events)
