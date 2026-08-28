"""Windows Security Event Log collector -- thin instantiation of
windows_eventlog_parser.py's generic recipe. EventID list and names are
scoped to exactly what orchestrator/sigma_rules/builtin/security/'s
vendored ruleset (140 rules) actually references (43 distinct EIDs,
extracted directly from the vendored rules, not guessed) -- this is a much
higher-background-volume log than Sysmon's own curated operational log,
so only pulling the EIDs the ruleset cares about avoids collecting
irrelevant noise.

Reading this log requires the querying account to be a local Administrator
or a member of "Event Log Readers" -- confirmed readable with this
project's existing guest credentials via a live-VM check.
"""

from typing import List

from windows_eventlog_parser import WindowsEventLogParser

SECURITY_LOG_NAME = "Security"

# Best-effort human-readable names for the well-known/high-signal EIDs in
# this set; anything not listed here still matches correctly (Sigma rules
# key off the numeric EventID field directly) and falls back to
# "SecurityEvent<id>" -- this table is for report/UI readability only, not
# a matching requirement.
EVENT_ID_NAMES = {
    1102: "SecurityAuditLogCleared",
    4616: "SecuritySystemTimeChanged",
    4648: "SecurityExplicitCredentialLogon",
    4657: "SecurityRegistryValueModified",
    4663: "SecurityObjectAccessAttempt",
    4697: "SecurityServiceInstalled",
    4698: "SecurityScheduledTaskCreated",
    4699: "SecurityScheduledTaskDeleted",
    4702: "SecurityScheduledTaskUpdated",
    4704: "SecurityUserRightAssigned",
    4719: "SecurityAuditPolicyChanged",
    4720: "SecurityUserAccountCreated",
    4732: "SecurityGroupMemberAdded",
    4738: "SecurityUserAccountChanged",
    5140: "SecurityNetworkShareAccessed",
    5145: "SecurityNetworkShareObjectChecked",
    5379: "SecurityCredentialManagerRead",
    6416: "SecurityNewExternalDeviceRecognized",
}

# Every distinct EventID sigma_rules/builtin/security/*.yml actually
# references (extracted via grep across the vendored rules, not assumed).
EVENT_ID_FILTER: List[int] = [
    517, 1102, 4611, 4616, 4648, 4649, 4656, 4657, 4661, 4662, 4663, 4673,
    4674, 4692, 4697, 4698, 4699, 4702, 4704, 4706, 4719, 4720, 4732, 4738,
    4742, 4768, 4769, 4776, 4781, 4794, 4800, 4825, 4898, 4899, 5136, 5140,
    5145, 5156, 5379, 5447, 5449, 6416, 6423,
]


class SecurityLogParser(WindowsEventLogParser):
    def __init__(self) -> None:
        super().__init__(
            log_name=SECURITY_LOG_NAME,
            source="security",
            event_id_names=EVENT_ID_NAMES,
            event_id_filter=EVENT_ID_FILTER,
        )
