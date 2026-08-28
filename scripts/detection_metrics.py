"""Detection-quality metrics over a labeled corpus.

Resolves the labels in tests/corpus/labels.json to reports in reports/, replays
the CURRENT detection pipeline over each (scripts/replay_detection.py), and
measures how well today's rules/weights separate malicious from benign:

  - a confusion matrix (true label x predicted verdict band),
  - precision / recall / FPR / F1 at two decision thresholds
    ("malicious-only" and "suspicious-or-worse"),
  - per-family detection rate,
  - false-positive drivers (which verdict reasons fire on benign samples) --
    the actionable output for the calibration step (scripts/calibrate_verdict.py).

Because it replays with the live pipeline, the numbers reflect the current
detectors.py weights + verdict.py thresholds -- rerun after any change to see
the effect. Use --bootstrap to turn unlabeled reports into a labeling worklist.

    python scripts/detection_metrics.py
    python scripts/detection_metrics.py --json
    python scripts/detection_metrics.py --markdown reports/scorecard.md
    python scripts/detection_metrics.py --bootstrap
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.config import get_config  # noqa: E402
from scripts.replay_detection import build_sigma_engine, load_report_file, replay_detection_only  # noqa: E402

LABELS_PATH = PROJECT_ROOT / "tests" / "corpus" / "labels.json"
SPLITS_PATH = PROJECT_ROOT / "tests" / "corpus" / "splits.json"

# Verdict bands, worst-first.
BANDS = ["malicious", "suspicious", "clean"]
# "flagged" thresholds: which predicted bands count as a positive detection.
THRESHOLDS = {
    "malicious-only": {"malicious"},
    "suspicious-or-worse": {"malicious", "suspicious"},
}


# ---------------------------------------------------------------------------
# Label resolution
# ---------------------------------------------------------------------------

def load_labels(path: Path = LABELS_PATH) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("labels", [])


def load_split_assignments(path: Path = SPLITS_PATH) -> Dict[str, str]:
    """sha256/filename/report-id -> 'train'|'test' (empty when not split yet)."""
    if not path.exists():
        return {}
    return (json.loads(path.read_text(encoding="utf-8")) or {}).get("assignments", {})


def _split_of(scored_entry: Dict[str, Any], assignments: Dict[str, str]) -> Optional[str]:
    """Split membership of a scored run, using the same precedence as labels."""
    for key in (scored_entry.get("sha256"), scored_entry.get("filename"), scored_entry.get("id")):
        if key and key in assignments:
            return assignments[key]
    return None


def _report_identity(report: Dict[str, Any], fallback_id: str) -> Tuple[str, Optional[str], Optional[str]]:
    sample = report.get("sample", {}) or {}
    rid = report.get("analysis_id", fallback_id)
    sha = (sample.get("hashes") or {}).get("sha256")
    fn = sample.get("filename")
    return rid, sha, fn


def _match_label(labels_index: Dict[str, Dict[str, Any]], rid: str, sha: Optional[str], fn: Optional[str]) -> Optional[Dict[str, Any]]:
    """Resolve a report to its label. Precedence: explicit report id, then
    sample sha256, then filename (broadest)."""
    if rid in labels_index["report"]:
        return labels_index["report"][rid]
    if sha and sha in labels_index["sha256"]:
        return labels_index["sha256"][sha]
    if fn and fn in labels_index["filename"]:
        return labels_index["filename"][fn]
    return None


def _index_labels(labels: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {"report": {}, "sha256": {}, "filename": {}}
    for label in labels:
        match = label.get("match", {})
        for key in ("report", "sha256", "filename"):
            if key in match:
                index[key][match[key]] = label
    return index


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_corpus(reports_dir: Path, labels: List[Dict[str, Any]], sigma_engine) -> List[Dict[str, Any]]:
    """Replay every labeled report (detection-only fast path) and record
    (label, predicted level, reasons)."""
    labels_index = _index_labels(labels)
    scored: List[Dict[str, Any]] = []
    for path in sorted(reports_dir.glob("*.json")):
        report = load_report_file(path)
        if report is None:
            continue
        rid, sha, fn = _report_identity(report, path.stem)
        label = _match_label(labels_index, rid, sha, fn)
        if label is None:
            continue  # unlabeled -> not part of the measured corpus
        try:
            det = replay_detection_only(report, sigma_engine)
        except Exception as exc:
            scored.append({"id": rid, "filename": fn, "label": label["label"], "error": str(exc)})
            continue
        verdict = det.get("verdict", {}) or {}
        scored.append({
            "id": rid,
            "filename": fn,
            "sha256": sha,
            "label": label["label"],
            "family": label.get("family"),
            "predicted": verdict.get("level"),
            "score": verdict.get("score"),
            "top_reasons": [r.get("reason") for r in verdict.get("top_reasons", [])],
        })
    return scored


def _wilson(k: int, n: int, z: float = 1.96) -> Optional[Tuple[float, float]]:
    """Wilson score interval for a binomial proportion k/n at ~95% confidence.

    The honest way to report precision/recall/FPR on a small corpus: a bare
    '1.000' on 19 samples says almost nothing -- the CI does. Accurate at
    small n and at extreme proportions, unlike the normal approximation.
    """
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * ((p * (1 - p) / n) + z * z / (4 * n * n)) ** 0.5
    return (max(0.0, center - margin), min(1.0, center + margin))


def _rates(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Any]:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall) else None
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "fpr": fpr, "f1": f1,
        "precision_ci": _wilson(tp, tp + fp),
        "recall_ci": _wilson(tp, tp + fn),
        "fpr_ci": _wilson(fp, fp + tn),
    }


def compute_metrics(scored: List[Dict[str, Any]]) -> Dict[str, Any]:
    valid = [s for s in scored if "error" not in s and s.get("predicted")]
    errors = [s for s in scored if "error" in s]

    # Confusion matrix: true label x predicted band.
    confusion: Dict[str, Counter] = {"malicious": Counter(), "benign": Counter()}
    for s in valid:
        confusion[s["label"]][s["predicted"]] += 1

    # Precision/recall/FPR at each threshold.
    threshold_metrics: Dict[str, Any] = {}
    for name, flagged_bands in THRESHOLDS.items():
        tp = fp = fn = tn = 0
        for s in valid:
            flagged = s["predicted"] in flagged_bands
            if s["label"] == "malicious":
                tp += flagged
                fn += not flagged
            else:
                fp += flagged
                tn += not flagged
        threshold_metrics[name] = _rates(tp, fp, fn, tn)

    # Per-family detection (fraction reaching at least "suspicious").
    family_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "detected": 0})
    for s in valid:
        if s["label"] != "malicious":
            continue
        fam = s.get("family") or "unlabeled"
        family_stats[fam]["total"] += 1
        if s["predicted"] in THRESHOLDS["suspicious-or-worse"]:
            family_stats[fam]["detected"] += 1

    # False-positive drivers: reasons that fired on benign samples flagged >= suspicious.
    fp_drivers: Counter = Counter()
    for s in valid:
        if s["label"] == "benign" and s["predicted"] in THRESHOLDS["suspicious-or-worse"]:
            for reason in s["top_reasons"]:
                fp_drivers[reason] += 1

    return {
        "counts": {
            "total_scored": len(valid),
            "malicious": sum(1 for s in valid if s["label"] == "malicious"),
            "benign": sum(1 for s in valid if s["label"] == "benign"),
            "errors": len(errors),
        },
        "confusion": {k: dict(v) for k, v in confusion.items()},
        "thresholds": threshold_metrics,
        "families": {k: v for k, v in sorted(family_stats.items())},
        "fp_drivers": fp_drivers.most_common(),
        "errors": [{"id": e["id"], "error": e["error"]} for e in errors],
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _fmt(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def _fmt_ci(ci: Optional[Tuple[float, float]]) -> str:
    return "" if not ci else f" [{ci[0]:.2f}–{ci[1]:.2f}]"


def render_text(m: Dict[str, Any]) -> str:
    c = m["counts"]
    lines = [
        "=" * 68,
        "DETECTION METRICS (current pipeline, replayed over labeled corpus)",
        "=" * 68,
        f"scored: {c['total_scored']} runs  ({c['malicious']} malicious, {c['benign']} benign)  errors: {c['errors']}",
        "",
        "Confusion (true label -> predicted band):",
        f"  {'':10} {'malicious':>10} {'suspicious':>11} {'clean':>7}",
    ]
    for label in ("malicious", "benign"):
        row = m["confusion"].get(label, {})
        lines.append(f"  {label:10} {row.get('malicious',0):>10} {row.get('suspicious',0):>11} {row.get('clean',0):>7}")
    lines += ["", "Decision metrics (95% Wilson CIs in brackets):"]
    for name, r in m["thresholds"].items():
        lines.append(
            f"  [{name:20}] precision={_fmt(r['precision'])}{_fmt_ci(r['precision_ci'])} "
            f"recall={_fmt(r['recall'])}{_fmt_ci(r['recall_ci'])} "
            f"fpr={_fmt(r['fpr'])}{_fmt_ci(r['fpr_ci'])} f1={_fmt(r['f1'])}  "
            f"(tp={r['tp']} fp={r['fp']} fn={r['fn']} tn={r['tn']})"
        )
    if c["total_scored"] < 50:
        lines.append("  NOTE: small corpus -- CIs are wide; treat point values as indicative only.")
    lines += ["", "Per-family detection (reached >= suspicious):"]
    for fam, st in m["families"].items():
        rate = st["detected"] / st["total"] if st["total"] else 0
        lines.append(f"  {fam:22} {st['detected']}/{st['total']}  ({rate:.0%})")
    if m["fp_drivers"]:
        lines += ["", "False-positive drivers (reasons on flagged benign runs):"]
        for reason, n in m["fp_drivers"]:
            lines.append(f"  {n:>3}x  {reason}")
    if m["errors"]:
        lines += ["", f"Replay errors: {len(m['errors'])}"]
        for e in m["errors"][:10]:
            lines.append(f"  {e['id']}: {e['error']}")
    lines.append("=" * 68)
    return "\n".join(lines)


def render_markdown(m: Dict[str, Any]) -> str:
    c = m["counts"]
    out = ["# Detection metrics scorecard", "",
           f"Scored **{c['total_scored']}** runs ({c['malicious']} malicious, {c['benign']} benign); errors: {c['errors']}.", "",
           "## Decision metrics", "", "| threshold | precision | recall | FPR | F1 | tp | fp | fn | tn |",
           "|---|---|---|---|---|---|---|---|---|"]
    for name, r in m["thresholds"].items():
        out.append(
            f"| {name} | {_fmt(r['precision'])}{_fmt_ci(r['precision_ci'])} | "
            f"{_fmt(r['recall'])}{_fmt_ci(r['recall_ci'])} | {_fmt(r['fpr'])}{_fmt_ci(r['fpr_ci'])} | "
            f"{_fmt(r['f1'])} | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} |"
        )
    out += ["", "## Per-family detection", "", "| family | detected/total | rate |", "|---|---|---|"]
    for fam, st in m["families"].items():
        rate = st["detected"] / st["total"] if st["total"] else 0
        out.append(f"| {fam} | {st['detected']}/{st['total']} | {rate:.0%} |")
    if m["fp_drivers"]:
        out += ["", "## False-positive drivers", "", "| count | reason |", "|---|---|"]
        for reason, n in m["fp_drivers"]:
            out.append(f"| {n} | {reason} |")
    return "\n".join(out) + "\n"


def render_bootstrap(reports_dir: Path, labels: List[Dict[str, Any]]) -> str:
    """List reports NOT covered by any label, with their stored verdict, as a
    labeling worklist (no replay -- fast)."""
    labels_index = _index_labels(labels)
    rows = []
    for path in sorted(reports_dir.glob("*.json")):
        report = load_report_file(path)
        if report is None:
            continue
        rid, sha, fn = _report_identity(report, path.stem)
        if _match_label(labels_index, rid, sha, fn):
            continue
        verdict = (report.get("verdict") or {})
        rows.append((rid, str(fn), verdict.get("level"), verdict.get("score")))
    lines = [f"{len(rows)} unlabeled reports (add matching entries to tests/corpus/labels.json):", ""]
    for rid, fn, lvl, score in rows:
        lines.append(f"  {rid}  {fn[:34]:34}  stored_verdict={lvl}/{score}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="Emit metrics as JSON")
    parser.add_argument("--markdown", type=Path, help="Write a markdown scorecard to this path")
    parser.add_argument("--bootstrap", action="store_true", help="List unlabeled reports as a labeling worklist (no replay)")
    parser.add_argument("--split", choices=["all", "train", "test"], default="all",
                        help="restrict to one split from tests/corpus/splits.json (default all)")
    args = parser.parse_args()

    cfg = get_config()
    reports_dir = Path(cfg.paths["reports_dir"])
    labels = load_labels()

    if args.bootstrap:
        print(render_bootstrap(reports_dir, labels))
        return

    sigma_engine = build_sigma_engine(cfg)
    scored = score_corpus(reports_dir, labels, sigma_engine)

    if args.split != "all":
        assignments = load_split_assignments()
        if not assignments:
            print(f"WARNING: --split {args.split} requested but {SPLITS_PATH} is missing/empty; "
              "run scripts/corpus_split.py first. Reporting ALL runs.", file=sys.stderr)
        else:
            before = len(scored)
            scored = [s for s in scored if _split_of(s, assignments) == args.split]
            print(f"[split={args.split}] {len(scored)}/{before} labeled runs in this split", file=sys.stderr)

    metrics = compute_metrics(scored)

    if args.markdown:
        args.markdown.write_text(render_markdown(metrics), encoding="utf-8")
        print(f"wrote scorecard to {args.markdown}")
    if args.json:
        print(json.dumps(metrics, indent=2, default=str))
    else:
        print(render_text(metrics))


if __name__ == "__main__":
    main()
