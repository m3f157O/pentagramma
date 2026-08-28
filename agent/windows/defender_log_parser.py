"""Windows Defender operational log collector -- thin instantiation of
windows_eventlog_parser.py's generic recipe. No auditpol enabling needed
(on by default whenever Defender is active) -- confirmed via a live-VM
check that Defender is actually running in this project's golden image
(WinDefend service Running, RealTimeProtectionEnabled=True), which was the
open question gating whether this collector was worth building at all.
EventID list scoped to exactly what orchestrator/sigma_rules/builtin/
windefend/'s vendored ruleset (16 rules) references (10 distinct EIDs).
"""

from typing import List

from windows_eventlog_parser import WindowsEventLogParser

DEFENDER_LOG_NAME = "Microsoft-Windows-Windows Defender/Operational"

EVENT_ID_NAMES = {
    1116: "DefenderThreatDetected",
    1121: "DefenderAttackSurfaceReductionBlocked",
    5001: "DefenderRealTimeProtectionDisabled",
    5007: "DefenderConfigurationChanged",
    5010: "DefenderMalwareScanningDisabled",
    5012: "DefenderVirusScanningDisabled",
    5013: "DefenderTamperProtectionBlocked",
}

# Every distinct EventID sigma_rules/builtin/windefend/*.yml actually
# references (extracted via grep across the vendored rules).
EVENT_ID_FILTER: List[int] = [1009, 1013, 1116, 1121, 5001, 5007, 5010, 5012, 5013, 5101]


class DefenderLogParser(WindowsEventLogParser):
    def __init__(self) -> None:
        super().__init__(
            log_name=DEFENDER_LOG_NAME,
            source="windefend",
            event_id_names=EVENT_ID_NAMES,
            event_id_filter=EVENT_ID_FILTER,
        )
