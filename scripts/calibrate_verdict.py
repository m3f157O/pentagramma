"""Verdict-threshold calibration against the labeled corpus.

Keeps the transparent additive scoring model (orchestrator/detectors.py weights)
untouched and tunes only where the malicious / suspicious decision lines sit
(orchestrator/verdict.py::LEVEL_THRESHOLDS) -- the cleanest, least-overfit knob
for the precision/recall/FPR tradeoff. It:

  1. replays each labeled report ONCE to a numeric verdict score (the score is
     independent of the thresholds, so a threshold sweep needs no re-replay),
  2. sweeps candidate (malicious, suspicious) cutoffs, computing metrics for
     each by re-bucketing the cached scores,
  3. recommends the cutoffs maximizing F1 at the malicious decision subject to
     an FPR budget on the benign set,
  4. prints baseline-vs-recommended metrics and the exact one-line change to
     make -- it NEVER writes verdict.py itself.

    python scripts/calibrate_verdict.py
    python scripts/calibrate_verdict.py --fpr-budget 0.05

NOTE: calibration is only as trustworthy as the corpus. With a thin benign set
the FPR estimate is high-variance -- grow tests/corpus/labels.json with real
goodware before trusting a retune (a warning is printed when the benign set is
small).
"""

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import verdict as verdict_mod  # noqa: E402
from orchestrator.config import get_config  # noqa: E402
from scripts.detection_metrics import compute_metrics, load_labels, load_split_assignments, _index_labels, _match_label, _report_identity, _split_of  # noqa: E402
from scripts.replay_detection import build_sigma_engine, load_report_file, replay_detection_only  # noqa: E402


def cache_scores(reports_dir: Path, labels: List[Dict[str, Any]], sigma_engine,
                 split: str = "train") -> List[Dict[str, Any]]:
    """Replay each labeled report once -> (label, family, numeric score). The
    score is what the thresholds bucket into clean/suspicious/malicious, and it
    does not depend on the thresholds, so this pass is done exactly once.

    split: calibration is TRAIN-ONLY by default -- tuning thresholds on the
    test split would make test metrics meaningless (in-sample fit). Pass
    'all' to override explicitly."""
    labels_index = _index_labels(labels)
    assignments = load_split_assignments() if split != "all" else {}
    cached: List[Dict[str, Any]] = []
    for path in sorted(reports_dir.glob("*.json")):
        report = load_report_file(path)
        if report is None:
            continue
        rid, sha, fn = _report_identity(report, path.stem)
        label = _match_label(labels_index, rid, sha, fn)
        if label is None:
            continue
        try:
            det = replay_detection_only(report, sigma_engine)
        except Exception:
            continue
        entry = {
            "id": rid, "filename": fn, "sha256": sha, "label": label["label"], "family": label.get("family"),
            "score": (det.get("verdict") or {}).get("score", 0),
        }
        if split != "all" and assignments and _split_of(entry, assignments) != split:
            continue
        cached.append(entry)
    return cached


def _level_for(score: int, thresholds: List[Tuple[int, str]]) -> str:
    for cutoff, level in thresholds:
        if score >= cutoff:
            return level
    return thresholds[-1][1]


def _metrics_for_thresholds(cached: List[Dict[str, Any]], malicious: int, suspicious: int) -> Dict[str, Any]:
    thresholds = [(malicious, "malicious"), (suspicious, "suspicious"), (0, "clean")]
    scored = [
        {"label": c["label"], "family": c.get("family"), "predicted": _level_for(c["score"], thresholds), "top_reasons": []}
        for c in cached
    ]
    return compute_metrics(scored)


def sweep(cached: List[Dict[str, Any]], fpr_budget: float) -> Dict[str, Any]:
    baseline_thresholds = verdict_mod.LEVEL_THRESHOLDS
    base_mal = next(c for c, l in baseline_thresholds if l == "malicious")
    base_susp = next(c for c, l in baseline_thresholds if l == "suspicious")

    baseline = _metrics_for_thresholds(cached, base_mal, base_susp)

    candidates = []
    for malicious in range(15, 71, 5):
        for suspicious in range(5, malicious, 5):
            m = _metrics_for_thresholds(cached, malicious, suspicious)
            mal = m["thresholds"]["malicious-only"]
            candidates.append({
                "malicious": malicious, "suspicious": suspicious,
                "f1": mal["f1"], "precision": mal["precision"], "recall": mal["recall"], "fpr": mal["fpr"],
            })

    # Best F1 at the malicious decision subject to the FPR budget (treat
    # unknown FPR -- no benign samples -- as within budget but flag it).
    def _ok(c):
        return c["f1"] is not None and (c["fpr"] is None or c["fpr"] <= fpr_budget)

    eligible = [c for c in candidates if _ok(c)]
    best = max(eligible, key=lambda c: (c["f1"], -c["malicious"]), default=None)
    return {"baseline": {"malicious": base_mal, "suspicious": base_susp, "metrics": baseline},
            "best": best, "candidates": candidates}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fpr-budget", type=float, default=0.10, help="Max acceptable false-positive rate on benign (default 0.10)")
    parser.add_argument("--split", choices=["train", "all"], default="train",
                        help="corpus subset to calibrate on (default train -- test stays held out)")
    args = parser.parse_args()

    cfg = get_config()
    reports_dir = Path(cfg.paths["reports_dir"])
    labels = load_labels()
    sigma_engine = build_sigma_engine(cfg)

    cached = cache_scores(reports_dir, labels, sigma_engine, split=args.split)
    n_benign = sum(1 for c in cached if c["label"] == "benign")
    n_mal = sum(1 for c in cached if c["label"] == "malicious")

    result = sweep(cached, args.fpr_budget)
    base = result["baseline"]
    best = result["best"]

    def _fmt(x):
        return "n/a" if x is None else f"{x:.3f}"

    bm = base["metrics"]["thresholds"]["malicious-only"]
    print("=" * 70)
    print("VERDICT THRESHOLD CALIBRATION")
    print("=" * 70)
    print(f"corpus: {n_mal} malicious + {n_benign} benign runs (split={args.split}) | FPR budget: {args.fpr_budget}")
    if n_benign < 10:
        print(f"WARNING: only {n_benign} benign run(s) -- FPR estimate is high-variance. "
              "Add real goodware to tests/corpus/labels.json before trusting a retune.")
    print()
    print(f"baseline thresholds: malicious>={base['malicious']} suspicious>={base['suspicious']}")
    print(f"  malicious-decision: precision={_fmt(bm['precision'])} recall={_fmt(bm['recall'])} "
          f"fpr={_fmt(bm['fpr'])} f1={_fmt(bm['f1'])}")
    print()
    if best is None:
        print("No candidate met the FPR budget. Loosen --fpr-budget or grow the corpus.")
    else:
        print(f"recommended thresholds: malicious>={best['malicious']} suspicious>={best['suspicious']}")
        print(f"  malicious-decision: precision={_fmt(best['precision'])} recall={_fmt(best['recall'])} "
              f"fpr={_fmt(best['fpr'])} f1={_fmt(best['f1'])}")
        if (best["malicious"], best["suspicious"]) == (base["malicious"], base["suspicious"]):
            print("\n  -> current thresholds are already optimal for this corpus; no change recommended.")
        else:
            print("\n  To apply, edit orchestrator/verdict.py::LEVEL_THRESHOLDS to:")
            print(f"    LEVEL_THRESHOLDS = [({best['malicious']}, \"malicious\"), ({best['suspicious']}, \"suspicious\"), (0, \"clean\")]")
            print("  (review against a larger corpus first; this script never edits verdict.py)")
    print("=" * 70)


if __name__ == "__main__":
    main()
