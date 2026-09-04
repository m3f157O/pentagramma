"""Sigma rule evaluation engine.

Evaluates SigmaHQ-format detection rules (YAML, community-maintained,
https://github.com/SigmaHQ/sigma) directly against this project's own
Sysmon-derived telemetry event dicts -- an additional, parallel alert
source alongside orchestrator/heuristics.py's hardcoded detectors, not a
replacement. Sigma rules use Sysmon field names as their native schema,
which is why this is viable without a translation layer for most fields.

pySigma (the official SigmaHQ library) is a rule-parsing and query-language
-conversion framework -- its Backend machinery is designed for building
query strings (Splunk/Elastic/etc.), not boolean evaluation. This module
uses pySigma only to parse rule YAML into a walkable condition AST
(rule.detection.parsed_condition[i].parsed), then evaluates that AST
directly against a plain event dict with its own small recursive walker
below. Every SigmaType branch here (SigmaString.convert(), SigmaRegularExpression,
SigmaCIDRExpression.expand(), etc.) was verified against the actual
installed pysigma 1.4.0 source before being written -- see scratchpad
test scripts from this session for the empirical checks.
"""

import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SigmaType,
)

logger = logging.getLogger(__name__)

# logsource.category -> candidate event_type(s) this project's telemetry
# actually produces (see agent/windows/sysmon_parser.py's _classify()).
# Categories not listed here (e.g. "builtin", "create_stream_hash") have no
# matching telemetry source and are excluded at vendoring time -- see
# scripts/vendor_sigma_rules.py. Also deliberately excluded, confirmed (not
# "pending"): "file_access" and "file_rename" -- agent/windows/
# sysmon_parser.py::_classify()'s EventID table has no corresponding Sysmon
# event type for either (Sysmon has no native file-rename event, and
# file-access auditing is a distinct, uncollected EID); there is nothing to
# bucket rules from either category against.
CATEGORY_TO_EVENT_TYPES: Dict[str, List[str]] = {
    "process_creation": ["ProcessCreate"],
    "network_connection": ["NetworkConnect"],
    "dns_query": ["DnsQuery"],
    "image_load": ["ImageLoad"],
    "driver_load": ["DriverLoad"],
    "create_remote_thread": ["CreateRemoteThread"],
    "raw_access_thread": ["RawAccessRead"],
    "process_access": ["ProcessAccess"],
    "process_tampering": ["ProcessTampering"],
    "pipe_created": ["PipeCreated", "PipeConnected"],
    "wmi_event": ["WmiEventFilter", "WmiEventConsumer", "WmiEventConsumerToFilter"],
    "file_event": ["FileCreate"],
    "file_delete": ["FileDelete", "FileDeleteDetected"],
    "file_change": ["FileCreateTime"],
    # EID 29 is its own distinct event_type ("FileExecutableDetected"), NOT
    # a subset of FileCreate (EID 11) -- confirmed via sysmon_parser.py's
    # _classify() table. Fixed here after finding rules in this category
    # were being bucketed against the wrong event population entirely.
    "file_executable_detected": ["FileExecutableDetected"],
    "registry_add": ["RegistryCreateDelete"],
    "registry_delete": ["RegistryCreateDelete"],
    "registry_set": ["RegistryValueSet"],
    "registry_event": ["RegistryCreateDelete", "RegistryValueSet", "RegistryKeyValueRename"],
    # SigmaHQ's real logsource.category value for rules/windows/powershell/
    # powershell_script/ is "ps_script", NOT "powershell_script" (the
    # directory name) -- confirmed by grepping every vendored file's actual
    # category: field. The wrong key here silently zeroed out this entire
    # category (158 rules, ~10% of the active ruleset) since it was first
    # written; found while investigating overall rule-repository coverage.
    "ps_script": ["ScriptBlockLogged"],
    # Not a standard SigmaHQ category -- used by this project's own custom
    # rules under sigma_rules_custom/ (e.g. amsi_detection.yml), which migrated
    # the former hardcoded AMSI heuristic into a declarative Sigma rule.
    "amsi": ["AmsiScanDetected"],
}

_LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_ATTACK_TECHNIQUE_RE = re.compile(r"^t(\d{4})(\.\d{3})?$", re.IGNORECASE)

# Matches SigmaString.to_regex()'s own internal call exactly (verified
# against pysigma 1.4.0 source, sigma/types.py) -- called directly on
# .convert() rather than through to_regex() because to_regex() wraps the
# result in a SigmaRegularExpression whose .regexp is itself a SigmaString,
# requiring an extra .to_plain_regex() unwrap for no benefit here.
_SIGMASTRING_ESCAPE_KWARGS = dict(
    escape_char="\\",
    wildcard_multi=".*",
    wildcard_single=".",
    add_escaped=".*+?^$[](){}\\|",
)


class CompiledRule:
    __slots__ = ("rule", "event_types", "conditions", "anchors")

    def __init__(self, rule: SigmaRule, event_types: List[str]):
        self.rule = rule
        self.event_types = event_types
        # rule.detection.parsed_condition[i].parsed is a property that
        # RE-PARSES the condition string (including a copy.deepcopy of the
        # detection items) on every single access -- confirmed via
        # profiling, this alone was ~60% of total evaluation time before
        # being hoisted here to run once at load time instead of once per
        # (event, rule) pair.
        self.conditions = [c.parsed for c in rule.detection.parsed_condition]
        # Must-match literal anchors for the prefilter (see _harvest_anchors'
        # Boolean-algebra soundness spec; empty tuple = always evaluate fully).
        self.anchors: Tuple[Tuple[str, str], ...] = tuple(_harvest_anchors(self.conditions))


class CorrelationDetector:
    """A loaded Sigma event_count correlation rule ready to evaluate: its
    metadata rule, the compiled base rule(s) whose matches it counts, and the
    group-by / timespan / threshold that define when it fires.
    """

    __slots__ = ("rule", "bases", "group_by", "timespan_seconds", "op", "count")

    def __init__(self, rule, bases, group_by, timespan_seconds, op, count):
        self.rule = rule
        self.bases: List[CompiledRule] = bases
        self.group_by: List[str] = group_by
        self.timespan_seconds: float = timespan_seconds
        self.op = op
        self.count = count


class SigmaEngine:
    """Loads a directory of Sigma rule YAML once and evaluates them against
    telemetry events. Construct once per process (see
    SandboxExecutor.__init__) -- rule parsing is not cheap enough to redo
    per report, mirroring how StaticAnalyzer loads YARA rules once at
    construction time.
    """

    def __init__(
        self,
        rules_dir: Path,
        min_level: str = "medium",
        excluded_categories: Optional[List[str]] = None,
        disabled_rule_ids: Optional[List[str]] = None,
        custom_rules_dirs: Optional[List[Path]] = None,
    ):
        self.rules_dir = Path(rules_dir)
        # This project's own rules (LOLBin/AMSI single-event rules, the
        # file-change correlation rule, ...) live OUTSIDE rules_dir because
        # scripts/vendor_sigma_rules.py rmtree's rules_dir on every re-vendor.
        # They're loaded into the same collection so correlation references
        # across the two resolve.
        self.custom_rules_dirs = [Path(d) for d in (custom_rules_dirs or [])]
        self.min_level = min_level
        self.excluded_categories = set(excluded_categories or [])
        self.disabled_rule_ids = set(disabled_rule_ids or [])
        self._by_event_type: Dict[str, List[CompiledRule]] = {}
        # Rules keyed by logsource.service (e.g. "sysmon"/"security"/
        # "system"/"windefend", as opposed to .category) reference a numeric
        # EventID inside their OWN detection logic rather than a single
        # static category -- there's no event_type to index them under the
        # way category-based rules are. Two-level dispatch: first by
        # event["source"] (every parser stamps this -- matches Sigma's own
        # service value exactly, e.g. security_log_parser.py's source=
        # "security" vs. sigma_rules/builtin/security/*.yml's service:
        # security), then within a service bucket, by a statically-extracted
        # EventID (see _extract_rule_event_ids) so e.g. a Security-log event
        # only checks the handful of Security rules keyed to its own
        # EventID, not all ~140. Rules whose EventID condition isn't a clean
        # literal/OR-of-literals (no EventID reference at all, a regex, a
        # NOT, etc.) fall back to a small per-service full-pass list here --
        # this was the ENTIRE mechanism before Security/System/Defender
        # (~217 rules) were added on top of sysmon's original 6-rule bucket,
        # and unconditional full-pass no longer scales at that size (same
        # O(rules x events) problem already found and fixed once this
        # session for category-based rules, 152s -> 13s).
        self._service_rules: Dict[str, List[CompiledRule]] = {}
        self._service_event_id_index: Dict[str, Dict[int, List[CompiledRule]]] = {}
        self._rule_count = 0
        self._load_errors: List[str] = []
        # Coverage-gap visibility -- both were previously silent. See
        # correlation_rules_skipped/unsupported_modifier_rule_ids properties.
        self._correlation_rules_skipped = 0
        self._unsupported_modifier_rule_ids: List[str] = []
        # Browseable metadata for every rule that actually made it into the
        # active set (post level/category/disabled filtering) -- backs the
        # rules-catalog UI (GET /api/rules). Kept separate from the
        # evaluation indexes so listing rules never has to walk them.
        self._rules_meta: List[Dict[str, Any]] = []
        # rule id -> source .yml path, for lazily serving a rule's raw YAML
        # (GET /api/rules/sigma/{id}/raw) without embedding ~2000 YAMLs in the
        # catalog payload.
        self._rule_source_by_id: Dict[str, str] = {}
        # Resolved ruleset roots (rules_dir + custom dirs), filled by _load;
        # get_rule_yaml only reads files inside one of these.
        self._rule_roots: List[Path] = []
        # event_count correlation rules (see CorrelationDetector). Their base
        # rules are compiled into each detector and kept out of the single-event
        # indexes, so a base rule never alerts on its own -- it only feeds its
        # correlation.
        self._correlations: List[CorrelationDetector] = []
        # Per-instance compiled-pattern caches (see _MatchCaches / _match_string
        # etc. below) -- created fresh per engine so id()-based keys, which are
        # only unique among currently-alive objects, can never collide with a
        # different (garbage-collected) engine's rule objects. A single shared
        # module-level cache -- the ORIGINAL version of this -- caused
        # completely unrelated Sigma rules to fire on unrelated events once
        # many analyses started running back-to-back via the job queue
        # (confirmed live, 2026-07-03). A pure value-keyed cache (the first
        # fix attempted) closed that hole but reintroduced the O(rules x
        # events) cost this caching exists to avoid, by recomputing each
        # pattern's string form on every lookup instead of once per unique
        # object -- confirmed live as well (orchestrator became unresponsive,
        # CPU climbing continuously rather than idling on a lock). This is
        # instance-scoped so it's both correct AND back to O(1) id() lookups.
        self._match_caches = _MatchCaches()
        # Literal-anchor prefilter (CompiledRule.anchors, checked in
        # _matches). On by default; SANDBOX_SIGMA_PREFILTER=0 disables for
        # A/B byte-identical-output validation.
        import os
        self._prefilter_enabled = os.environ.get("SANDBOX_SIGMA_PREFILTER", "1") != "0"
        self._load()

    def _load(self) -> None:
        roots = [self.rules_dir, *self.custom_rules_dirs]
        # Roots that actually exist, resolved -- also used by get_rule_yaml to
        # confirm a rule's source path is inside a known ruleset before reading.
        self._rule_roots = [r.resolve() for r in roots if r.exists()]
        existing = [str(r) for r in roots if r.exists()]
        if not existing:
            logger.warning("No Sigma rules directories found: %s", roots)
            return

        collection = SigmaCollection.load_ruleset(existing, collect_errors=True)
        self._load_errors = [str(e) for e in collection.errors]
        min_level_value = _LEVEL_ORDER.get(self.min_level.lower(), 0)

        rules = list(collection.rules)
        # SigmaCollection also yields SigmaCorrelationRule (multi-event/stateful
        # rules, e.g. ">= 20 file events in 5s"). event_count correlations are
        # now evaluated (see _register_correlation / _evaluate_correlations);
        # other correlation types remain unsupported and counted as skipped.
        correlation_rules = [r for r in rules if isinstance(r, SigmaCorrelationRule)]
        # Rule objects a correlation references exist only to feed it; they must
        # NOT be indexed as standalone single-event rules (a base like "any file
        # event" would otherwise alert on every single file event).
        base_rule_ids = {id(ref.rule) for cr in correlation_rules for ref in cr.rules if ref.rule is not None}

        for rule in rules:
            if isinstance(rule, SigmaCorrelationRule):
                continue  # registered after the single-event rules (see below)
            if not isinstance(rule, SigmaRule):
                continue
            if id(rule) in base_rule_ids:
                continue  # correlation base -- compiled in _register_correlation, never alerts alone
            if rule.level is not None and _LEVEL_ORDER.get(rule.level.name.lower(), 0) < min_level_value:
                continue
            if self.disabled_rule_ids and str(rule.id) in self.disabled_rule_ids:
                continue

            category = rule.logsource.category
            service = rule.logsource.service

            source = getattr(rule, "source", None)
            source_path = str(source.path) if source is not None and getattr(source, "path", None) else None

            if category is not None:
                if category in self.excluded_categories:
                    continue
                event_types = CATEGORY_TO_EVENT_TYPES.get(category)
                if not event_types:
                    continue
                compiled = CompiledRule(rule, event_types)
                self._rule_count += 1
                self._rules_meta.append(_rule_meta(rule, category=category, service=None))
                if source_path and rule.id:
                    self._rule_source_by_id[str(rule.id)] = source_path
                for event_type in event_types:
                    self._by_event_type.setdefault(event_type, []).append(compiled)
            elif service is not None and service not in self.excluded_categories:
                compiled = CompiledRule(rule, [])
                self._rule_count += 1
                self._rules_meta.append(_rule_meta(rule, category=None, service=service))
                if source_path and rule.id:
                    self._rule_source_by_id[str(rule.id)] = source_path
                event_ids = _extract_rule_event_ids(compiled.conditions)
                if event_ids:
                    index = self._service_event_id_index.setdefault(service, {})
                    for event_id in event_ids:
                        index.setdefault(event_id, []).append(compiled)
                else:
                    self._service_rules.setdefault(service, []).append(compiled)

        for correlation in correlation_rules:
            self._register_correlation(correlation)

        anchored = 0
        total = 0
        for bucket in list(self._by_event_type.values()) + list(self._service_rules.values()):
            for cr in bucket:
                total += 1
                if cr.anchors:
                    anchored += 1
        for idx in self._service_event_id_index.values():
            seen_ids = set()
            for rules in idx.values():
                for cr in rules:
                    if id(cr) in seen_ids:
                        continue
                    seen_ids.add(id(cr))
                    total += 1
                    if cr.anchors:
                        anchored += 1
        logger.info("Sigma prefilter: %d/%d rules carry literal anchors", anchored, total)

    def _register_correlation(self, cr: SigmaCorrelationRule) -> None:
        """Register one correlation rule for evaluation. Only event_count is
        supported (the type our temporal detectors need); other types are
        counted as skipped rather than silently ignored.
        """
        if cr.type != SigmaCorrelationType.EVENT_COUNT:
            self._correlation_rules_skipped += 1
            return
        bases = [CompiledRule(ref.rule, []) for ref in cr.rules if ref.rule is not None]
        if not bases or cr.condition is None or cr.timespan is None:
            self._correlation_rules_skipped += 1
            return
        self._correlations.append(
            CorrelationDetector(
                rule=cr,
                bases=bases,
                group_by=list(cr.group_by or []),
                timespan_seconds=cr.timespan.seconds,
                op=cr.condition.op,
                count=cr.condition.count,
            )
        )
        self._rule_count += 1
        self._rules_meta.append(
            {
                "id": str(cr.id) if cr.id else None,
                "family": "sigma",
                "title": cr.title,
                "level": cr.level.name.lower() if cr.level else None,
                "severity": cr.level.name.lower() if cr.level else None,
                "status": cr.status.name.lower() if cr.status else None,
                "description": cr.description,
                "category": None,
                "service": None,
                "product": None,
                "correlation": cr.type.name.lower(),
                "tags": [str(t) for t in cr.tags],
            }
        )
        source = getattr(cr, "source", None)
        source_path = str(source.path) if source is not None and getattr(source, "path", None) else None
        if source_path and cr.id:
            self._rule_source_by_id[str(cr.id)] = source_path

    @property
    def rule_count(self) -> int:
        return self._rule_count

    def list_rules(self) -> List[Dict[str, Any]]:
        """Browseable metadata for every active rule (backs GET /api/rules)."""
        return list(self._rules_meta)

    def get_rule_yaml(self, rule_id: str) -> Optional[str]:
        """Raw YAML source for one rule, read from its vendored .yml file on
        demand. Returns None for an unknown id. The path comes from our own
        load (not the caller), and is re-checked to be inside rules_dir before
        reading -- defence in depth against a path escaping the ruleset.
        """
        path = self._rule_source_by_id.get(rule_id)
        if not path:
            return None
        resolved = Path(path).resolve()
        if not any(_is_within(resolved, root) for root in self._rule_roots):
            return None
        try:
            return resolved.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    @property
    def correlation_rules_skipped(self) -> int:
        return self._correlation_rules_skipped

    @property
    def unsupported_modifier_rule_ids(self) -> List[str]:
        return list(self._unsupported_modifier_rule_ids)

    @property
    def load_errors(self) -> List[str]:
        return self._load_errors

    def evaluate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Returns one alert dict per (event, matching rule) pair, each
        already MITRE-enriched (see orchestrator/mitre_mapping.py::enrich_alert,
        which merges in each rule's own ATT&CK tags alongside the existing
        blanket per-event-type mapping).
        """
        from orchestrator.mitre_mapping import enrich_alert  # local import: avoids a hard dependency for callers that never evaluate

        alerts: List[Dict[str, Any]] = []
        for event in events:
            event_type = event.get("event_type") or event.get("EventType")
            candidates = list(self._by_event_type.get(event_type, ()))

            source = event.get("source")
            if source:
                # Second-level dispatch by EventID within this event's
                # service bucket -- see _service_event_id_index's comment.
                event_id = event.get("event_id")
                if event_id is not None:
                    candidates += self._service_event_id_index.get(source, {}).get(event_id, ())
                # Rules whose EventID couldn't be statically resolved (no
                # EventID reference, a regex/NOT on it, etc.) still need a
                # full-pass check against every event from that service.
                candidates += self._service_rules.get(source, [])

            lowered: Dict[str, str] = {}  # per-event anchor-check field cache
            for compiled in candidates:
                try:
                    if self._matches(compiled, event, lowered):
                        alerts.append(enrich_alert(_build_alert(compiled.rule, event)))
                except Exception as exc:
                    # A single malformed/unsupported rule must never break
                    # evaluation of the rest of the ruleset.
                    logger.debug("Sigma rule %s failed to evaluate: %s", compiled.rule.id, exc)

        alerts.extend(self._evaluate_correlations(events, enrich_alert))
        return alerts

    def _evaluate_correlations(self, events, enrich_alert) -> List[Dict[str, Any]]:
        """Stateful pass for event_count correlation rules: count base-rule
        matches per group within a sliding timespan window and fire when the
        threshold condition is met. Runs after the single-event pass; the base
        rules are matched against every event (they aren't in the per-event
        indexes), which is fine at our correlation-rule count.
        """
        alerts: List[Dict[str, Any]] = []
        for corr in self._correlations:
            try:
                matched = [ev for ev in events if any(self._matches(base, ev) for base in corr.bases)]
                if not matched:
                    continue
                groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
                for ev in matched:
                    key = tuple(_resolve_field_value(f, ev) for f in corr.group_by) if corr.group_by else ()
                    # Disambiguate by ProcessGuid too, when resolvable --
                    # Windows can recycle a PID within the same analysis
                    # window (confirmed live, 2026-07-03: a `timeout /t 3`
                    # child's PID was handed to an unrelated wermgr.exe
                    # milliseconds after it exited), which would otherwise
                    # merge two different processes' events into one
                    # correlation group just because they share the rule's
                    # group-by field VALUES (typically just ProcessId).
                    guid = (ev.get("data") or {}).get("ProcessGuid")
                    bucket_key = (key, guid)
                    groups[bucket_key].append(ev)
                for bucket_key, group_events in groups.items():
                    key, _guid = bucket_key
                    count = _max_window_count(group_events, corr.timespan_seconds)
                    if _correlation_condition_met(corr.op, count, corr.count):
                        alerts.append(enrich_alert(_build_correlation_alert(corr, group_events, count, key)))
            except Exception as exc:
                logger.debug("Correlation rule %s failed to evaluate: %s", getattr(corr.rule, "id", "?"), exc)
        return alerts

    def _matches(
        self,
        compiled: CompiledRule,
        event: Dict[str, Any],
        lowered: Optional[Dict[str, str]] = None,
    ) -> bool:
        # Literal-anchor prefilter: for rules whose condition provably
        # REQUIRES certain literal substrings (see _harvest_anchors'
        # soundness spec), a missing anchor means the rule cannot match, so
        # skip the full condition walk. Case-insensitive containment is
        # implied by the engine's exact-equality literal match (convert()
        # escapes all regex metachars, then fullmatch), so this can never
        # skip a true positive. Toggleable for A/B validation of exactly
        # that claim (SANDBOX_SIGMA_PREFILTER=0).
        # `lowered` is a per-event cache of already-lowercased field values --
        # without it the anchor check itself becomes O(rules x field-lower)
        # on the big buckets (measured: uncached it eats most of the win).
        if compiled.anchors and self._prefilter_enabled:
            if lowered is None:
                lowered = {}
            for field, anchor in compiled.anchors:
                lv = lowered.get(field)
                if lv is None:
                    value = _resolve_field_value(field, event)
                    if value is None:
                        return False
                    lv = str(value).lower()
                    lowered[field] = lv
                if anchor not in lv:
                    return False
        # detection.condition may be a list of independent condition
        # strings -- each is an alternative match criterion, OR'd together
        # for whether the rule fires overall.
        for condition in compiled.conditions:
            if _evaluate_node(condition, event, self._match_caches):
                return True
        return False


# ---------------------------------------------------------------------------
# Literal-anchor prefilter
# ---------------------------------------------------------------------------

def _anchors_of(node: ConditionItem) -> frozenset:
    """Must-match anchor set for one condition subtree, as a Boolean-algebra
    constraint propagation:

    - AND  -> union of children (every child's constraints are necessary)
    - OR   -> intersection of children (only constraints shared by ALL
      branches are necessary overall)
    - NOT  -> empty (a negated condition constrains nothing)
    - field==literal leaf -> {(field, longest-literal-part)} when the value
      is a SigmaString whose longest plain-text part is >= 4 chars
      (wildcards fine: fullmatch of `.*lit1.*lit2.*` requires every literal
      part present in order, so each part is a necessary substring; this
      covers the |contains/|startswith/|endswith modifier forms, which
      pySigma models as implicit wildcards)
    - everything else (regex/cidr/compare/number/exists/null/expansion/
      keyword/field-ref) -> empty

    A rule's anchor set is the intersection across its alternative
    conditions (detection.condition can be a list, OR'd). Soundness: an
    anchor (field, s) is only ever produced where a match provably requires
    `s` (case-insensitively) in the event's field value; the engine's
    literal match is exact-equality after convert() escaping (see
    _match_string), optionally case-sensitive (SigmaCasedString), and
    case-insensitive containment is implied either way.
    """
    if isinstance(node, ConditionAND):
        out: set = set()
        for child in node.args:
            out |= _anchors_of(child)
        return frozenset(out)
    if isinstance(node, ConditionOR):
        child_sets = [set(_anchors_of(c)) for c in node.args]
        if not child_sets:
            return frozenset()
        return frozenset(set.intersection(*child_sets))
    if isinstance(node, ConditionNOT):
        return frozenset()
    if isinstance(node, ConditionFieldEqualsValueExpression):
        value = node.value
        if isinstance(value, SigmaString) and not value.contains_placeholder():
            parts = [p for p in value.s if isinstance(p, str)]
            if parts:
                longest = max(parts, key=len)
                if len(longest) >= 4:
                    return frozenset({(node.field, longest.lower())})
        return frozenset()
    # ConditionValueExpression (keywords) and anything else: no constraint.
    return frozenset()


def _harvest_anchors(conditions: List[ConditionItem]) -> List[Tuple[str, str]]:
    """Anchor set for a whole rule: intersection across its alternative
    conditions (see _anchors_of for the soundness algebra)."""
    if not conditions:
        return []
    sets = [set(_anchors_of(c)) for c in conditions]
    return sorted(set.intersection(*sets))


# ---------------------------------------------------------------------------
# Condition-tree evaluation
# ---------------------------------------------------------------------------

def _evaluate_node(node: ConditionItem, event: Dict[str, Any], caches: "_MatchCaches") -> bool:
    if isinstance(node, ConditionAND):
        return all(_evaluate_node(child, event, caches) for child in node.args)
    if isinstance(node, ConditionOR):
        return any(_evaluate_node(child, event, caches) for child in node.args)
    if isinstance(node, ConditionNOT):
        return not _evaluate_node(node.args[0], event, caches)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        # |fieldref modifier: compare this field to ANOTHER field's value on
        # the same event (e.g. TargetProcessId == CallingProcessId), rather
        # than to a literal. Handled here (not in _match_value) because it
        # needs the whole event to resolve the referenced field.
        if isinstance(node.value, SigmaFieldReference):
            return _match_field_reference(node.field, node.value, event)
        return _match_value(node.value, _resolve_field_value(node.field, event), caches)
    if isinstance(node, ConditionValueExpression):
        # Fieldless "keyword" match -- no clean equivalent for structured
        # JSON events (Sigma's keyword detection assumes raw log lines).
        # Pragmatic fallback: match if any field's value matches.
        data = event.get("data") or {}
        return any(_match_value(node.value, v, caches) for v in data.values())
    logger.debug("Unhandled Sigma condition node type: %s", type(node).__name__)
    return False


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _rule_meta(rule: SigmaRule, category: Optional[str], service: Optional[str]) -> Dict[str, Any]:
    """Flatten one SigmaRule to the small, JSON-serializable shape the
    rules-catalog UI needs -- deliberately not the whole rule (no detection
    AST, no raw YAML), just what's useful to browse and filter by.
    """
    return {
        "id": str(rule.id) if rule.id else None,
        "family": "sigma",
        "title": rule.title,
        "level": rule.level.name.lower() if rule.level else None,
        # "severity" mirrors "level" under the standardized detector schema
        # (orchestrator/detectors.py) so every family exposes the same field.
        "severity": rule.level.name.lower() if rule.level else None,
        "status": rule.status.name.lower() if rule.status else None,
        "description": rule.description,
        "category": category,
        "service": service,
        "product": rule.logsource.product,
        "tags": [str(t) for t in rule.tags],
    }


def _match_field_reference(field: str, ref: SigmaFieldReference, event: Dict[str, Any]) -> bool:
    """Evaluate a |fieldref comparison: this field equals the value of the
    referenced field on the same event. Both absent -> no match (rather than
    a vacuous True). Compared as strings, matching how _match_value coerces
    field values elsewhere.
    """
    left = _resolve_field_value(field, event)
    right = _resolve_field_value(ref.field, event)
    if left is None or right is None:
        return False
    return str(left) == str(right)


def _extract_rule_event_ids(conditions: List[ConditionItem]) -> Optional[Set[int]]:
    """One-time, load-time walk (same load-time-introspection pattern used
    elsewhere in this module) that statically determines the complete set
    of EventID values a service-based rule could ever match, so it can be
    indexed by SigmaEngine._service_event_id_index instead of falling back
    to a full per-event pass. detection.condition may be a list of
    independent OR'd condition strings, so every one must resolve for the
    rule as a whole to be indexable -- if even one can't be resolved, the
    whole rule goes to the full-pass fallback list rather than risk
    under-indexing (matching a subset of events it should have matched).
    """
    all_ids: Set[int] = set()
    for condition in conditions:
        ids = _extract_node_event_ids(condition)
        if ids is None:
            return None
        all_ids |= ids
    return all_ids or None


def _extract_node_event_ids(node: ConditionItem) -> Optional[Set[int]]:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        if node.field != "EventID":
            return None
        return _extract_value_event_ids(node.value)
    if isinstance(node, ConditionAND):
        # ALL children must hold, so any single child that resolves a
        # static EventID set is a valid constraint on the whole AND --
        # intersect every child that does resolve (children that don't,
        # e.g. a CommandLine match, add no EventID information but don't
        # invalidate a sibling's constraint either).
        resolved = [s for s in (_extract_node_event_ids(c) for c in node.args) if s is not None]
        if not resolved:
            return None
        result = resolved[0]
        for s in resolved[1:]:
            result = result & s
        return result or None
    if isinstance(node, ConditionOR):
        # For OR, every branch must resolve -- an unresolvable branch could
        # match any EventID, which would make the overall set unbounded.
        child_sets = [_extract_node_event_ids(c) for c in node.args]
        if any(s is None for s in child_sets):
            return None
        union: Set[int] = set()
        for s in child_sets:
            union |= s
        return union or None
    # ConditionNOT and fieldless ConditionValueExpression carry no positive
    # EventID membership constraint -- unresolvable, use the fallback list.
    return None


def _extract_value_event_ids(value: SigmaType) -> Optional[Set[int]]:
    if isinstance(value, SigmaNumber):
        try:
            return {int(value.to_plain())}
        except (TypeError, ValueError):
            return None
    if isinstance(value, SigmaExpansion):
        ids: Set[int] = set()
        for v in value.values:
            sub = _extract_value_event_ids(v)
            if sub is None:
                return None
            ids |= sub
        return ids
    return None


def _resolve_field_value(field: str, event: Dict[str, Any]) -> Any:
    # The numeric Sysmon EventID lives at the event's top level
    # (event["event_id"]), never inside event["data"] -- confirmed via
    # agent/windows/sysmon_parser.py's _classify(), which builds `data`
    # purely from <EventData> child elements.
    if field == "EventID":
        return event.get("event_id")
    data = event.get("data") or {}
    return data.get(field)


def _match_value(value: SigmaType, field_value: Any, caches: "_MatchCaches") -> bool:
    if isinstance(value, SigmaExists):
        return (field_value is not None) == value.exists
    if isinstance(value, SigmaNull):
        return field_value is None or field_value == ""
    if isinstance(value, SigmaExpansion):
        return any(_match_value(v, field_value, caches) for v in value.values)
    if isinstance(value, SigmaCIDRExpression):
        return _match_cidr(value, field_value, caches)
    if isinstance(value, SigmaCompareExpression):
        return _match_compare(value, field_value)
    if isinstance(value, SigmaNumber):
        # Plain numeric literal (e.g. "EventID: 16", "DestinationPort: 4444")
        # -- exact-equality, not a |gt/|lt range comparison (SigmaCompareExpression).
        if field_value is None:
            return False
        try:
            return float(field_value) == float(value.to_plain())
        except (TypeError, ValueError):
            return False
    if isinstance(value, SigmaRegularExpression):
        return _match_regex(value, field_value, caches)
    if isinstance(value, SigmaFieldReference):
        # Field-vs-field comparison -- rare in Windows process/registry
        # rules, deliberately unsupported in v1 rather than guessed wrong.
        return False
    if isinstance(value, SigmaString):
        return _match_string(value, field_value, caches)
    logger.debug("Unhandled SigmaType: %s", type(value).__name__)
    return False


# SigmaString/SigmaRegularExpression aren't hashable (confirmed
# empirically), so these are cached by id(value) rather than by value.
# id() is only guaranteed unique among CURRENTLY-ALIVE objects, so this is
# only safe when the cache's lifetime can never outlive the objects it
# indexes.
#
# Two versions of this were tried and rejected before landing here (both
# confirmed live, 2026-07-03, via the job queue running many analyses
# back-to-back):
#   1. A module-level cache keyed by id(value) -- outlives any single
#      SigmaEngine, so once an engine's rule AST objects are garbage
#      collected, Python can reuse that memory address for a totally
#      unrelated pattern object in the NEXT engine, and the cache serves
#      the wrong compiled regex for it. Surfaced as completely unrelated
#      Sigma rules ("Renamed AdFind Execution", "Potential SMB Relay Attack
#      Tool Execution") firing on a plain `notepad.exe "file.txt"` call.
#   2. A module-level cache keyed by VALUE (pattern string + flags) instead
#      of identity -- correct, but forces recomputing value.convert() /
#      str(value.regexp) on EVERY match attempt just to know the cache key,
#      not only on a cache miss. Across tens of thousands of events against
#      ~1600 rules that's a severe regression (the orchestrator became
#      unresponsive -- CPU climbing continuously rather than idling on a
#      lock, consistent with slow-but-real progress, not a deadlock).
#
# This version keeps id()-based O(1) lookups (no recompute needed just to
# check the cache) but scopes each cache to ONE SigmaEngine instance (see
# SigmaEngine._match_caches) instead of a module global. CompiledRule.conditions
# holds the ONE persistent AST built at load time, so the same leaf objects
# are reused across every evaluate() call for THAT ENGINE's lifetime, and the
# cache is garbage collected together with the engine and its objects --
# id() collisions with a different engine's (dead) objects are structurally
# impossible since there is no cross-instance sharing at all.
#
# Caching the COMPILED re.Pattern (not just the pattern string) still
# matters: profiling showed re._compile() was ~75% of total evaluation time
# even after caching the pattern *string* -- re.fullmatch(pattern_str, ...)
# still round-trips through Python's own internal regex cache every call,
# which only holds 512 entries (re._MAXCACHE) and was thrashing constantly
# against the thousands of distinct patterns across ~1600 rules. Holding our
# own unbounded reference to each compiled Pattern avoids that churn.
class _MatchCaches:
    __slots__ = ("string", "regex", "cidr")

    def __init__(self) -> None:
        self.string: Dict[int, "re.Pattern[str]"] = {}
        self.regex: Dict[int, "re.Pattern[str]"] = {}
        self.cidr: Dict[int, List["re.Pattern[str]"]] = {}


def _match_string(value: SigmaString, field_value: Any, caches: "_MatchCaches") -> bool:
    if field_value is None:
        return False
    key = id(value)
    compiled = caches.string.get(key)
    if compiled is None:
        pattern = value.convert(**_SIGMASTRING_ESCAPE_KWARGS)
        flags = 0 if isinstance(value, SigmaCasedString) else re.IGNORECASE
        compiled = re.compile(pattern, flags)
        caches.string[key] = compiled
    return compiled.fullmatch(str(field_value)) is not None


def _match_regex(value: SigmaRegularExpression, field_value: Any, caches: "_MatchCaches") -> bool:
    if field_value is None:
        return False
    key = id(value)
    compiled = caches.regex.get(key)
    if compiled is None:
        flags = 0
        for flag in value.flags:
            flags |= value.sigma_to_python_flags.get(flag, 0)
        compiled = re.compile(str(value.regexp), flags)
        caches.regex[key] = compiled
    return compiled.search(str(field_value)) is not None


def _match_cidr(value: SigmaCIDRExpression, field_value: Any, caches: "_MatchCaches") -> bool:
    if field_value is None:
        return False
    field_str = str(field_value)
    key = id(value)
    compiled_patterns = caches.cidr.get(key)
    if compiled_patterns is None:
        # CIDRExpression.expand() converts the range into dotted wildcard
        # patterns (e.g. "10.*") rather than exposing an ipaddress.IPv4Network
        # for containment checks -- following pySigma's own intended usage
        # (this is exactly how its query backends consume CIDR values) rather
        # than reimplementing IP arithmetic separately.
        compiled_patterns = [
            re.compile(re.escape(wildcard_pattern).replace(r"\*", ".*")) for wildcard_pattern in value.expand()
        ]
        caches.cidr[key] = compiled_patterns
    return any(pattern.fullmatch(field_str) for pattern in compiled_patterns)


def _match_compare(value: SigmaCompareExpression, field_value: Any) -> bool:
    if field_value is None:
        return False
    try:
        field_num = float(field_value)
        target_num = float(value.number.to_plain())
    except (TypeError, ValueError):
        return False
    ops = SigmaCompareExpression.CompareOperators
    if value.op == ops.LT:
        return field_num < target_num
    if value.op == ops.LTE:
        return field_num <= target_num
    if value.op == ops.GT:
        return field_num > target_num
    if value.op == ops.GTE:
        return field_num >= target_num
    if value.op == ops.NEQ:
        return field_num != target_num
    return False


# ---------------------------------------------------------------------------
# Alert construction
# ---------------------------------------------------------------------------

def _build_alert(rule: SigmaRule, event: Dict[str, Any]) -> Dict[str, Any]:
    """Preserves the matched event's own event_id/event_type/data (a Sigma
    match on a real ProcessTampering event legitimately keeps event_id==25 --
    this can't collide with the synthetic 9101-9104 range in heuristics.py,
    and doesn't disturb scripts/harness_assertions.py's event_id==25 filter).
    """
    alert = dict(event)
    alert["sigma"] = {
        "id": str(rule.id) if rule.id else None,
        "title": rule.title,
        "level": rule.level.name.lower() if rule.level else None,
        "tags": [str(t) for t in rule.tags],
        "falsepositives": list(rule.falsepositives) if rule.falsepositives else [],
        "logsource": {"category": rule.logsource.category, "product": rule.logsource.product},
        "mitre_candidates": _mitre_candidates_from_tags(rule.tags),
    }
    alert["source"] = "sigma"
    return alert


def _mitre_candidates_from_tags(tags) -> List[Dict[str, Any]]:
    from orchestrator.mitre_mapping import lookup_technique_name, lookup_technique_tactic  # local import: avoid a hard dependency for callers that never build alerts

    candidates: List[Dict[str, Any]] = []
    for tag in tags:
        namespace, _, name = str(tag).partition(".")
        if namespace.lower() != "attack":
            continue
        match = _ATTACK_TECHNIQUE_RE.match(name)
        if match:
            technique_id = ("T" + match.group(1) + (match.group(2) or "")).upper()
            # Resolved from the vendored MITRE ATT&CK snapshot (None for any ID
            # not in it) -- report_detail.js renders None as an empty string.
            candidates.append(
                {
                    "technique_id": technique_id,
                    "technique_name": lookup_technique_name(technique_id),
                    "tactic": lookup_technique_tactic(technique_id),
                }
            )
    return candidates


def _parse_ts(event: Dict[str, Any]) -> Optional[datetime]:
    raw = event.get("timestamp") or (event.get("data") or {}).get("UtcTime")
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    # Normalize to naive-UTC so tz-aware and naive telemetry timestamps
    # subtract cleanly during windowing.
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _max_window_count(events: List[Dict[str, Any]], window_seconds: float) -> int:
    """Largest number of events falling within any window of `window_seconds`
    -- a sliding two-pointer pass over the sorted timestamps. Mirrors
    heuristics._densest_window's peak-count semantics.
    """
    times = sorted(t for t in (_parse_ts(e) for e in events) if t is not None)
    if not times:
        return 0
    best = 0
    j = 0
    for i in range(len(times)):
        while (times[i] - times[j]).total_seconds() > window_seconds:
            j += 1
        best = max(best, i - j + 1)
    return best


def _correlation_condition_met(op: SigmaCorrelationConditionOperator, actual: int, threshold: int) -> bool:
    ops = SigmaCorrelationConditionOperator
    if op == ops.GT:
        return actual > threshold
    if op == ops.GTE:
        return actual >= threshold
    if op == ops.LT:
        return actual < threshold
    if op == ops.LTE:
        return actual <= threshold
    if op == ops.EQ:
        return actual == threshold
    return False


def _build_correlation_alert(
    corr: "CorrelationDetector", group_events: List[Dict[str, Any]], count: int, key: Tuple
) -> Dict[str, Any]:
    cr = corr.rule
    latest = None
    for ev in group_events:
        ts = _parse_ts(ev)
        if ts is not None and (latest is None or ts > latest):
            latest = ts
    timestamp = latest.isoformat() if latest is not None else None
    group_repr = ", ".join(str(v) for v in key) if key else None

    data: Dict[str, Any] = {
        "UtcTime": timestamp,
        "correlation_type": cr.type.name.lower(),
        "matched_events": count,
        "timespan_seconds": corr.timespan_seconds,
        "Type": f"{count} matches within {corr.timespan_seconds}s"
        + (f" (group {group_repr})" if group_repr else ""),
    }
    # Surface the group-by values as their own fields (e.g. ProcessId) so alert
    # scope classification can attribute the correlation to the sample lineage.
    for field, value in zip(corr.group_by, key):
        data[field] = value
    # Also surface ProcessGuid when every event in the group agrees on one
    # (guaranteed after the guid-disambiguated grouping above, when the
    # events carry it) -- lets pid_lineage.py::classify_alert_scope prefer
    # the PID-reuse-immune guid check over a bare ProcessId comparison.
    guids = {(ev.get("data") or {}).get("ProcessGuid") for ev in group_events}
    guids.discard(None)
    if len(guids) == 1:
        data["ProcessGuid"] = next(iter(guids))

    return {
        "source": "sigma",
        "provider_name": "SigmaCorrelation",
        "event_id": None,
        "event_type": "SigmaCorrelation",
        "timestamp": timestamp,
        "data": data,
        "sigma": {
            "id": str(cr.id) if cr.id else None,
            "title": cr.title,
            "level": cr.level.name.lower() if cr.level else None,
            "tags": [str(t) for t in cr.tags],
            "falsepositives": list(cr.falsepositives) if cr.falsepositives else [],
            "logsource": {"category": None, "product": None},
            "correlation": cr.type.name.lower(),
            "mitre_candidates": _mitre_candidates_from_tags(cr.tags),
        },
    }
