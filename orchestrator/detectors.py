"""Detection-layer standard: the shared contracts and vocabulary that make
Sigma, YARA, the hardcoded heuristics and the static-analysis signals present
as one uniform detection surface to the rest of the system (the rules catalog
and the verdict).

Phase 1 standardizes the *plumbing*, not the detector logic:
  - one Severity vocabulary, aligned with Sigma rule levels, so every family
    speaks the same scale;
  - a Finding output contract any detector can emit (with to_alert() so
    existing consumers keep working while producers migrate to it);
  - a Detector descriptor every family is catalogued as;
  - one place that maps a fired detection -> (family, severity, weight) for
    the verdict, replacing the per-type branches that used to live in
    verdict.py.

This module deliberately imports nothing from the other detection modules, so
heuristics.py / static_analysis.py / sigma_engine.py / verdict.py can all
depend on it without an import cycle.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# --- families: the five sources that can produce a finding ---
FAMILY_SIGMA = "sigma"
FAMILY_YARA = "yara"
FAMILY_HEURISTIC = "heuristic"
FAMILY_STATIC = "static"
# Track 3.3: behavioral signatures over the MinHook API-trace stream
# (orchestrator/behavioral_signatures.py) -- a distinct family so the rules
# catalog and the report's "Detections applied" section don't mislabel them
# as generic heuristics.
FAMILY_BEHAVIORAL = "behavioral"
# CAPE community signatures over the same API-trace stream
# (orchestrator/cape_engine.py) -- the vendored cape-community corpus.
FAMILY_CAPE = "cape"
FAMILIES = (FAMILY_SIGMA, FAMILY_YARA, FAMILY_HEURISTIC, FAMILY_STATIC, FAMILY_BEHAVIORAL, FAMILY_CAPE)

# --- severity: the five Sigma levels, reused so every family is comparable ---
SEVERITIES = ("informational", "low", "medium", "high", "critical")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}

# --- verdict weights, keyed by what fired ---
# Moved here from verdict.py so the severity model and the catalog share one
# definition. Numbers are unchanged from the original verdict.py.
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "informational": 1}
PROCESS_TAMPERING_WEIGHT = 40  # Sysmon EID 25 -- a single confirmed hollowing/injection
YARA_MATCH_WEIGHT = 20  # DmpYaraMatch / DroppedFileYaraMatch
HEURISTIC_HIGH_PRIORITY_WEIGHT = 12  # heuristics.annotate_priority()'s priority == "high"
HEURISTIC_BASELINE_WEIGHT = 4  # any other heuristic alert
STATIC_PACKED_WEIGHT = 10
STATIC_UNSIGNED_WEIGHT = 5
STATIC_YARA_MATCH_WEIGHT = 15
# capa is mostly informational (a capability isn't inherently malicious), so a
# high-signal capa capability (injection/anti-analysis/ransomware-crypto/C2/...)
# contributes a modest, once-only bump -- not per-capability, to avoid a
# capability-rich binary inflating the score by volume.
STATIC_CAPA_SIGNAL_WEIGHT = 8

# Microsoft Defender's SeverityName -> our severity vocabulary. A Defender
# threat detection (EID 1116) is a confirmed AV catch, scored via the same
# severity->weight table as everything else so it stays comparable; an
# unrecognized/absent severity floors at "high" (an AV detection is never a
# throwaway signal).
_DEFENDER_SEVERITY_MAP = {"severe": "critical", "high": "high", "moderate": "medium", "low": "low"}

# Event types excluded from the generic weight-4 baseline score in
# classify_alert() below. Confirmed via a live-VM run (2026-07-03,
# samples/detection_tests/benign_control.bat -- open Notepad on a file,
# close it, delete a temp file) that all four fire on completely mundane
# activity: sysmonconfig.xml's include filter for RegistryEvent/FileDelete
# is `Image contains \`, which admits every event of that type on the
# system -- there is no pre-filtering to make "it merely occurred"
# meaningful, despite this module's original comment claiming otherwise.
# ProcessAccess's GrantedAccess-mask filter is real but still fired 3x from
# ordinary window/process interaction in that same run. RegistryKeyValueRename
# joins RegistryCreateDelete/RegistryValueSet because Sysmon exposes all
# three as one RegistryEvent capability sharing that identical filter (see
# heuristics.py's comment on _REGISTRY_EVENT_TYPES).
#
# These event types are still selected as report alerts for analyst
# visibility (heuristics.UNCONDITIONAL_ALERT_TYPES is unchanged) and still
# score normally through a real signal: heuristics.annotate_priority()'s
# dangerous-pattern matching (Run keys, Defender tampering, Cobalt Strike
# pipe names, ...) or a matching Sigma rule -- both go through different
# branches above this one. Only the "this event type merely occurred, with
# no other evidence" case is excluded here.
_BASELINE_SCORING_EXCLUDED = {
    "ProcessAccess",
    "RegistryCreateDelete",
    "RegistryValueSet",
    "RegistryKeyValueRename",
    "FileDelete",
}

# Track 3.3: behavioral signatures derived from the MinHook API monitor.
# Severity is the input to the shared SEVERITY_WEIGHTS table; group_key
# dedupes repeated identical chains so volume cannot inflate the verdict.
_APITRACE_SIGNATURE_SEVERITY = {
    "ApitraceInjectionChain": "critical",
    "ApitraceCrossProcessWrite": "high",
    "ApitraceRemoteThread": "high",
    "ApitraceExecProtection": "medium",
    "ApitraceReflectiveLoad": "high",
    "ApitraceAntiSandboxTiming": "medium",
    "ApitraceCryptoBurst": "high",
    "ApitraceTokenManipulation": "high",
    "ApitraceAntiDebug": "medium",
    "ApitraceCrossProcessRead": "medium",
    "ApitraceAntiTamper": "high",
    "ApitraceTransactionAbuse": "medium",
    "ApitracePpidSpoof": "high",
    "ApitraceBlindSpot": "high",
    "ApitraceSilence": "medium",
    # SandboxGuard kernel guardian (source "guardian", EIDs 9401-9405)
    "GuardianProtectedAccess": "high",
    "GuardianProtectedRegistry": "high",
    "GuardianModuleRemap": "high",
    "GuardianInjectionFailed": "medium",
}

# Truncation is transparency-only; do not score it.
_APITRACE_SCORING_EXCLUDED = {"ApiTraceTruncated"}


def apitrace_signature_severity(event_type: Optional[str]) -> Optional[str]:
    """Severity of a synthesized behavioral-signature alert, or None for
    non-signature event types. Single source of truth shared by the verdict
    classifier and the alert enrichment (so the UI never duplicates the map)."""
    return _APITRACE_SIGNATURE_SEVERITY.get(event_type or "")


@dataclass
class Detector:
    """Uniform catalog descriptor for one detector, across all families."""

    id: str
    family: str
    title: str
    severity: Optional[str] = None
    kind: Optional[str] = None
    description: Optional[str] = None
    mitre: List[str] = field(default_factory=list)
    detail: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "family": self.family,
            "title": self.title,
            "severity": self.severity,
            "kind": self.kind,
            "description": self.description,
            "mitre": list(self.mitre),
            "detail": list(self.detail),
        }


@dataclass
class Finding:
    """Standard output contract for a fired detection.

    Producers (the Sigma engine, YARA runners, heuristics, static checks) can
    adopt this incrementally. to_alert() emits the legacy alert dict shape the
    report UI and scripts/harness_assertions.py already read, so a producer can
    switch to Finding without a flag-day change to every consumer.
    """

    detector_id: str
    family: str
    title: str
    severity: str
    source: str
    event_id: Optional[int] = None
    event_type: Optional[str] = None
    timestamp: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    mitre: Dict[str, Any] = field(default_factory=dict)
    in_sample_scope: Optional[bool] = None

    def to_alert(self) -> Dict[str, Any]:
        alert: Dict[str, Any] = {
            "source": self.source,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "data": dict(self.data),
            "mitre": dict(self.mitre),
            "detector": {"id": self.detector_id, "family": self.family, "severity": self.severity},
        }
        if self.in_sample_scope is not None:
            alert["in_sample_scope"] = self.in_sample_scope
        return alert


@dataclass
class AlertClassification:
    """How one alert maps onto the standard vocabulary for scoring."""

    family: str
    severity: str
    weight: int
    group_key: str  # dedupes repeats of the same finding so volume can't inflate the score
    label: str


def classify_alert(alert: Dict[str, Any]) -> Optional[AlertClassification]:
    """Map an alert (in the legacy dict shape) onto (family, severity, weight).
    The single source of truth for "what kind of detection is this and how
    much does it count" -- consumed by verdict.py and available to anything
    else that needs to reason about a finding uniformly. Returns None for an
    alert that shouldn't contribute at all.
    """
    if alert.get("event_id") == 25:
        return AlertClassification(
            FAMILY_HEURISTIC, "critical", PROCESS_TAMPERING_WEIGHT, "event_id:25",
            "Process tampering (hollowing/injection)",
        )

    event_type = alert.get("event_type")
    if event_type in ("DmpYaraMatch", "DroppedFileYaraMatch"):
        rule = (alert.get("data") or {}).get("Rule") or "unknown rule"
        return AlertClassification(FAMILY_YARA, "high", YARA_MATCH_WEIGHT, f"yara:{rule}", f"YARA match: {rule}")

    if event_type == "DefenderThreatDetected":
        data = alert.get("data") or {}
        threat = data.get("Threat Name") or "unknown threat"
        severity = _DEFENDER_SEVERITY_MAP.get((data.get("Severity Name") or "").strip().lower(), "high")
        return AlertClassification(
            FAMILY_HEURISTIC, severity, SEVERITY_WEIGHTS[severity], f"defender:{threat}",
            f"Microsoft Defender detected {threat}",
        )

    sigma = alert.get("sigma")
    if sigma:
        level = (sigma.get("level") or "").lower()
        weight = SEVERITY_WEIGHTS.get(level, SEVERITY_WEIGHTS["informational"])
        rule_id = sigma.get("id") or sigma.get("title")
        return AlertClassification(FAMILY_SIGMA, level or "informational", weight, f"sigma:{rule_id}", f"Sigma: {sigma.get('title')}")

    if alert.get("priority") == "high":
        return AlertClassification(
            FAMILY_HEURISTIC, "high", HEURISTIC_HIGH_PRIORITY_WEIGHT, f"heuristic-high:{event_type}",
            alert.get("priority_reason") or f"{event_type} (high priority)",
        )

    if event_type == "CapeSignature":
        # Verdict gate: cape_signatures.score=false ships matches as
        # enrichment/attribution only until corpus validation passes.
        if not alert.get("cape_score", True):
            return None
        data = alert.get("data") or {}
        severity = (data.get("SeverityStr") or "low").lower()
        if severity not in SEVERITY_WEIGHTS:
            severity = "low"
        name = data.get("Name") or "unknown"
        return AlertClassification(
            FAMILY_CAPE, severity, SEVERITY_WEIGHTS[severity], f"cape:{name}",
            f"CAPE: {data.get('Description') or name}",
        )

    if event_type in _APITRACE_SIGNATURE_SEVERITY:
        severity = _APITRACE_SIGNATURE_SEVERITY[event_type]
        data = alert.get("data") or {}
        actor = data.get("ProcessId")
        target = data.get("TargetProcessId")
        group_key = f"apitrace:{event_type}:{actor}:{target or ''}"
        return AlertClassification(
            FAMILY_BEHAVIORAL, severity, SEVERITY_WEIGHTS[severity], group_key,
            data.get("Type") or event_type,
        )

    if event_type and event_type not in _BASELINE_SCORING_EXCLUDED | _APITRACE_SCORING_EXCLUDED:
        return AlertClassification(FAMILY_HEURISTIC, "low", HEURISTIC_BASELINE_WEIGHT, f"heuristic:{event_type}", event_type)

    return None


def classify_static(static_analysis: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Static-analysis signals that contribute to the verdict, as
    [{weight, label}]. Same signals verdict.py scored inline before, now
    expressed once here alongside the alert classifier.
    """
    sa = static_analysis or {}
    out: List[Dict[str, Any]] = []
    if sa.get("packed_suspected"):
        out.append({"weight": STATIC_PACKED_WEIGHT, "label": "Sample appears packed/encrypted"})
    signature = sa.get("signature") or {}
    # status=="UnknownError" means Get-AuthenticodeSignature couldn't even
    # attempt a check -- e.g. .bat/.vbs/.js have no Authenticode container
    # format at all, so every script sample was scored "unsigned" purely
    # for being a script (confirmed via a live run of a signed-concept-free
    # .bat: status was "UnknownError", not "NotSigned"). Only score the
    # negative signal when the check actually ran on a checkable format and
    # came back negative -- "NotSigned"/"HashMismatch"/"NotTrusted" etc.
    if signature.get("status") not in (None, "", "UnknownError") and not signature.get("signed"):
        out.append({"weight": STATIC_UNSIGNED_WEIGHT, "label": "Sample binary is unsigned"})
    static_yara = [m for m in (sa.get("yara") or []) if "error" not in m]
    if static_yara:
        rule_names = ", ".join(m.get("rule", "?") for m in static_yara[:3])
        out.append({"weight": STATIC_YARA_MATCH_WEIGHT, "label": f"Static YARA match on sample: {rule_names}"})
    # capa high-signal capabilities -- read the summary dict directly (no import
    # of capa_analysis, keeping this module a leaf). Scored once regardless of
    # how many high-signal capabilities matched.
    capa = sa.get("capa") or {}
    if capa.get("available"):
        high = [c for c in capa.get("capabilities", []) if c.get("high_signal")]
        if high:
            names = ", ".join(c.get("name", "?") for c in high[:3])
            out.append({"weight": STATIC_CAPA_SIGNAL_WEIGHT, "label": f"capa high-signal capability: {names}"})
    return out
