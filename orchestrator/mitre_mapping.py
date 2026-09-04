"""MITRE ATT&CK mapping for sandbox alerts.

Provides a lightweight, event-type-based mapping that can be enriched later with
harness-specific technique labels (e.g., by correlating alert PIDs with harness
stdout).
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

# Vendored once via scripts/vendor_attack_techniques.py from the official
# MITRE ATT&CK STIX bundle (mitre-attack/attack-stix-data) -- {technique_id:
# {name, tactics}}, ~700 entries. Used to resolve human-readable names for
# Sigma-sourced technique IDs (orchestrator/sigma_engine.py::_build_alert()),
# which otherwise only carry the bare ID from a rule's own `tags:`. Absence
# of an ID in this table (e.g. a sub-technique added after vendoring) is
# normal, not an error -- callers must handle a missing lookup gracefully.
_ATTACK_TECHNIQUES_PATH = Path(__file__).resolve().parent / "data" / "attack_techniques.json"
try:
    ATTACK_TECHNIQUES: Dict[str, Dict[str, Any]] = json.loads(
        _ATTACK_TECHNIQUES_PATH.read_text(encoding="utf-8")
    )
except (FileNotFoundError, json.JSONDecodeError):
    ATTACK_TECHNIQUES = {}


def lookup_technique_name(technique_id: str) -> Optional[str]:
    entry = ATTACK_TECHNIQUES.get(technique_id)
    return entry.get("name") if entry else None


def lookup_technique_tactic(technique_id: str) -> Optional[str]:
    entry = ATTACK_TECHNIQUES.get(technique_id)
    tactics = entry.get("tactics") if entry else None
    return tactics[0] if tactics else None


# Mapping from normalized Sysmon event type to likely MITRE technique(s).
# A single event type can map to multiple techniques; the first is used as the
# primary technique for scoring.
EVENT_TYPE_TO_MITRE: Dict[str, List[Dict[str, str]]] = {
    "CreateRemoteThread": [
        {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Defense Evasion"},
        {"technique_id": "T1055.002", "technique_name": "Portable Executable Injection", "tactic": "Defense Evasion"},
    ],
    "ProcessAccess": [
        {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Defense Evasion"},
        {"technique_id": "T1003", "technique_name": "OS Credential Dumping", "tactic": "Credential Access"},
    ],
    "ProcessTampering": [
        {"technique_id": "T1055.012", "technique_name": "Process Hollowing", "tactic": "Defense Evasion"},
        {"technique_id": "T1055.013", "technique_name": "Process Doppelgänging", "tactic": "Defense Evasion"},
    ],
    "ImageLoad": [
        {"technique_id": "T1073", "technique_name": "DLL Side-Loading", "tactic": "Persistence"},
        {"technique_id": "T1129", "technique_name": "Shared Modules", "tactic": "Execution"},
    ],
    "DriverLoad": [
        {"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "RawAccessRead": [
        {"technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection"},
    ],
    "FileDeleteDetected": [
        {"technique_id": "T1070.004", "technique_name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion"},
    ],
    "FileCreateTime": [
        {"technique_id": "T1070.006", "technique_name": "Indicator Removal: Timestomp", "tactic": "Defense Evasion"},
    ],
    "RegistryCreateDelete": [
        {"technique_id": "T1547", "technique_name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    ],
    "RegistryValueSet": [
        {"technique_id": "T1547", "technique_name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
        {"technique_id": "T1112", "technique_name": "Modify Registry", "tactic": "Defense Evasion"},
    ],
    "RegistryKeyValueRename": [
        {"technique_id": "T1112", "technique_name": "Modify Registry", "tactic": "Defense Evasion"},
    ],
    "PipeCreated": [
        {"technique_id": "T1095", "technique_name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "PipeConnected": [
        {"technique_id": "T1095", "technique_name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "WmiEventFilter": [
        {"technique_id": "T1546.003", "technique_name": "WMI Event Subscription", "tactic": "Persistence"},
    ],
    "WmiTemporaryConsumer": [
        {"technique_id": "T1546.003", "technique_name": "WMI Event Subscription", "tactic": "Persistence"},
    ],
    "WmiPermanentConsumer": [
        {"technique_id": "T1546.003", "technique_name": "WMI Event Subscription", "tactic": "Persistence"},
    ],
    "WmiEventConsumer": [
        {"technique_id": "T1546.003", "technique_name": "WMI Event Subscription", "tactic": "Persistence"},
    ],
    "WmiEventConsumerToFilter": [
        {"technique_id": "T1546.003", "technique_name": "WMI Event Subscription", "tactic": "Persistence"},
    ],
    "ProcessCreate": [
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"technique_id": "T1218", "technique_name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    ],
    "FileDelete": [
        {"technique_id": "T1070.004", "technique_name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion"},
    ],
    "FileCreateStreamHash": [
        {"technique_id": "T1564.004", "technique_name": "Hide Artifacts: NTFS File Attributes", "tactic": "Defense Evasion"},
    ],
    "ClipboardChange": [
        {"technique_id": "T1115", "technique_name": "Clipboard Data", "tactic": "Collection"},
    ],
    "ProcessBurstDetected": [
        {"technique_id": "T1497", "technique_name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion"},
        {"technique_id": "T1057", "technique_name": "Process Discovery", "tactic": "Discovery"},
    ],
    "MassFileModificationDetected": [
        {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"technique_id": "T1485", "technique_name": "Data Destruction", "tactic": "Impact"},
    ],
    "ScriptBlockLogged": [
        {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
    ],
    "AmsiScanDetected": [
        {"technique_id": "T1027", "technique_name": "Obfuscated/Compressed Files or Information", "tactic": "Defense Evasion"},
    ],
    "NetworkConnect": [
        {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "DnsQuery": [
        {"technique_id": "T1071.004", "technique_name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
    ],
    "NetworkBurstDetected": [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"},
        {"technique_id": "T1071.004", "technique_name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
        {"technique_id": "T1572", "technique_name": "Protocol Tunneling", "tactic": "Command and Control"},
        {"technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    ],
    "DmpYaraMatch": [
        {"technique_id": "T1027", "technique_name": "Obfuscated/Compressed Files or Information", "tactic": "Defense Evasion"},
    ],
    "DroppedFileYaraMatch": [
        {"technique_id": "T1027", "technique_name": "Obfuscated/Compressed Files or Information", "tactic": "Defense Evasion"},
    ],
    "ApitraceInjectionChain": [
        {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Defense Evasion"},
        {"technique_id": "T1055.012", "technique_name": "Process Hollowing", "tactic": "Defense Evasion"},
    ],
    "ApitraceCrossProcessWrite": [
        {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Defense Evasion"},
    ],
    "ApitraceRemoteThread": [
        {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Defense Evasion"},
    ],
    "ApitraceExecProtection": [
        {"technique_id": "T1027", "technique_name": "Obfuscated/Compressed Files or Information", "tactic": "Defense Evasion"},
        {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Defense Evasion"},
    ],
    "ApitraceReflectiveLoad": [
        {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "Defense Evasion"},
        {"technique_id": "T1027", "technique_name": "Obfuscated/Compressed Files or Information", "tactic": "Defense Evasion"},
    ],
    "ApitraceAntiSandboxTiming": [
        {"technique_id": "T1497", "technique_name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion"},
    ],
    "ApitraceCryptoBurst": [
        {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
    ],
    "ApitraceTokenManipulation": [
        {"technique_id": "T1134", "technique_name": "Access Token Manipulation", "tactic": "Privilege Escalation"},
    ],
    "ApitraceAntiDebug": [
        {"technique_id": "T1622", "technique_name": "Debugger Evasion", "tactic": "Defense Evasion"},
    ],
    "ApitraceCrossProcessRead": [
        {"technique_id": "T1005", "technique_name": "Data from Local System", "tactic": "Collection"},
    ],
    "ApitraceAntiTamper": [
        {"technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion"},
    ],
    "ApitraceTransactionAbuse": [
        {"technique_id": "T1055.013", "technique_name": "Process Doppelganging", "tactic": "Defense Evasion"},
    ],
    "ApitracePpidSpoof": [
        {"technique_id": "T1134.004", "technique_name": "Access Token Manipulation: Parent PID Spoofing", "tactic": "Privilege Escalation"},
    ],
    "ApitraceBlindSpot": [
        {"technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion"},
    ],
    "ApitraceSilence": [
        {"technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion"},
    ],
}


def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the alert with MITRE mapping added.

    Sigma-sourced alerts (orchestrator/sigma_engine.py) carry their own
    rule-specific ATT&CK tags under alert["sigma"]["mitre_candidates"] --
    more precise than this blanket per-event-type mapping. Folded in here
    as additional candidates rather than replacing the blanket mapping, so
    every alert keeps going through the same single enrichment path.
    """
    event_type = alert.get("event_type") or alert.get("EventType")
    mapping = list(EVENT_TYPE_TO_MITRE.get(event_type, []))
    sigma_candidates = (alert.get("sigma") or {}).get("mitre_candidates") or []

    enriched = dict(alert)
    if mapping:
        primary = mapping[0]
        candidates = mapping[1:] + sigma_candidates
    else:
        primary = sigma_candidates[0] if sigma_candidates else None
        candidates = sigma_candidates[1:] if sigma_candidates else []
    enriched["mitre"] = {"primary": primary, "candidates": candidates}
    # Behavioral-signature alerts also carry their catalog severity so the UI
    # can color/group them without duplicating detectors.py's severity map.
    from orchestrator.detectors import apitrace_signature_severity  # local: keeps this module dependency-light
    severity = apitrace_signature_severity(event_type)
    if severity:
        enriched["severity"] = severity
    return enriched


def compute_coverage(events: List[Dict[str, Any]], alerts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Build a coverage matrix: event type -> count + MITRE techniques seen.

    `alerts` (optional) folds alert-only types into the matrix: behavioral
    signatures (ApitraceInjectionChain etc.) and other synthesized alerts are
    not telemetry events, so without this their ATT&CK techniques never show
    up in the coverage matrix -- the one place meant to summarize them.
    """
    coverage: Dict[str, Any] = {}
    for event in events:
        event_type = event.get("event_type") or event.get("EventType", "unknown")
        if event_type not in coverage:
            coverage[event_type] = {
                "count": 0,
                "mitre": EVENT_TYPE_TO_MITRE.get(event_type, []),
            }
        coverage[event_type]["count"] += 1
    for alert in alerts or []:
        event_type = alert.get("event_type") or alert.get("EventType")
        if not event_type:
            continue
        if event_type not in coverage:
            coverage[event_type] = {
                "count": 0,
                "mitre": EVENT_TYPE_TO_MITRE.get(event_type, []),
                "source": "alert",
            }
        coverage[event_type]["count"] += 1
    return coverage
