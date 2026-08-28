"""Windows System Event Log collector -- thin instantiation of
windows_eventlog_parser.py's generic recipe. Unlike Security, the System
log needs no auditpol enabling -- it's on by default. EventID list scoped
to exactly what orchestrator/sigma_rules/builtin/system/'s vendored
ruleset (54 rules) references (10 distinct EIDs, extracted directly from
the vendored rules).
"""

from typing import List

from windows_eventlog_parser import WindowsEventLogParser

SYSTEM_LOG_NAME = "System"

EVENT_ID_NAMES = {
    55: "SystemNtfsCorruptionDetected",
    104: "SystemEventLogCleared",
    7023: "SystemServiceTerminatedWithError",
    7034: "SystemServiceCrashedUnexpectedly",
    7036: "SystemServiceStateChange",
    7045: "SystemServiceInstalled",
}

# Every distinct EventID sigma_rules/builtin/system/**/*.yml actually
# references (extracted via grep across the vendored rules).
EVENT_ID_FILTER: List[int] = [16, 26, 55, 98, 104, 7023, 7034, 7036, 7045, 10001]


class SystemLogParser(WindowsEventLogParser):
    def __init__(self) -> None:
        super().__init__(
            log_name=SYSTEM_LOG_NAME,
            source="system",
            event_id_names=EVENT_ID_NAMES,
            event_id_filter=EVENT_ID_FILTER,
        )
