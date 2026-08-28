"""Overall verdict/score for a report -- the single highest-value gap
flagged since the very first CAPE/Cuckoo comparison this project ran
against. Purely a derived view over data reporting.py already has in
hand (alerts, static_analysis); no new collection, mirrors how
compute_coverage()/build_process_tree()/build_ioc_summary() already work.

Only considers alerts already classified in_sample_scope=True (see
orchestrator/pid_lineage.py) -- reusing the noise-reduction work rather
than re-solving "what's actually the sample's fault" from scratch.

Deliberately transparent rather than precisely calibrated: like this
project's other heuristic outputs (packing_reasons, priority_reason), the
score comes with the specific findings that produced it, not just a bare
number -- a security analyst should be able to see why, not just trust it.
"""

from typing import Any, Dict, List, Optional

from orchestrator import detectors

# Weight/severity model now lives in orchestrator/detectors.py (the detection
# standard) so the catalog and the verdict share one definition. Re-exported
# here for any caller that still imports them from verdict.
SEVERITY_WEIGHTS = detectors.SEVERITY_WEIGHTS
PROCESS_TAMPERING_WEIGHT = detectors.PROCESS_TAMPERING_WEIGHT
YARA_MATCH_WEIGHT = detectors.YARA_MATCH_WEIGHT

# Verdict *policy* (as opposed to per-detector weights) stays here.
MAX_SCORE = 100
ALERT_CONTRIBUTION_CAP = 70  # leaves room for static-analysis contributions without exceeding MAX_SCORE

# (minimum score, level), checked highest-first.
LEVEL_THRESHOLDS = [(40, "malicious"), (10, "suspicious"), (0, "clean")]

TOP_REASONS_LIMIT = 5


def _level_for_score(score: int) -> str:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return LEVEL_THRESHOLDS[-1][1]


def compute_verdict(
    alerts: List[Dict[str, Any]],
    static_analysis: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    best_by_group: Dict[str, tuple] = {}  # group_key -> (weight, label)
    for alert in alerts:
        if not alert.get("in_sample_scope"):
            continue
        # One shared classifier turns any alert into (family, severity, weight)
        # -- see orchestrator/detectors.py. group_key dedupes repeats of the
        # same finding so a noisy rule can't inflate the score by volume; only
        # the highest-weighted instance of each distinct finding counts.
        result = detectors.classify_alert(alert)
        if result is None:
            continue
        existing = best_by_group.get(result.group_key)
        if existing is None or result.weight > existing[0]:
            best_by_group[result.group_key] = (result.weight, result.label)

    alert_score = min(sum(weight for weight, _ in best_by_group.values()), ALERT_CONTRIBUTION_CAP)

    static_reasons = detectors.classify_static(static_analysis)
    static_score = sum(r["weight"] for r in static_reasons)

    score = min(alert_score + static_score, MAX_SCORE)
    level = _level_for_score(score)

    all_reasons = [{"weight": w, "reason": label} for w, label in best_by_group.values()] + [
        {"weight": r["weight"], "reason": r["label"]} for r in static_reasons
    ]
    all_reasons.sort(key=lambda r: r["weight"], reverse=True)

    return {
        "score": score,
        "level": level,
        "top_reasons": all_reasons[:TOP_REASONS_LIMIT],
    }
