"""Detection regression gate.

Replays the labeled corpus (tests/corpus/labels.json) through the CURRENT
detection pipeline and asserts detection quality hasn't regressed -- so a future
rule/weight/threshold change that silently tanks recall or spikes false
positives fails here instead of in production.

SLOW (~1-2 min: it replays every labeled report, each ~40k events through the
Sigma engine). Not a fast unit test -- run it explicitly before shipping a
detection change:

    .venv/Scripts/python.exe tests/test_corpus_metrics.py

Floors are conservative gross-regression catchers, well below the current
pipeline's numbers (recall(susp+)=1.0, precision(mal)=1.0, FPR=0.0 as of the
detection_tests corpus). Tighten them as the corpus grows with real goodware.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.config import get_config  # noqa: E402
from scripts.detection_metrics import compute_metrics, load_labels, load_split_assignments, score_corpus, _split_of, _fmt_ci  # noqa: E402
from scripts.replay_detection import build_sigma_engine  # noqa: E402

# Gate floors (see module docstring).
MIN_RECALL_SUSPICIOUS_PLUS = 0.90   # every malicious sample should reach >= suspicious
MIN_PRECISION_MALICIOUS = 0.90      # a "malicious" verdict should almost never be a benign
MAX_FPR_SUSPICIOUS_PLUS = 0.20      # benign flagged >= suspicious should be rare
MIN_CORPUS = 20                     # below this, skip rather than assert on noise


def main() -> None:
    cfg = get_config()
    reports_dir = Path(cfg.paths["reports_dir"])
    labels = load_labels()
    sigma_engine = build_sigma_engine(cfg)

    scored = score_corpus(reports_dir, labels, sigma_engine)

    # The gate runs on the FROZEN TEST SPLIT: calibration never sees these
    # runs, so the floors mean something. Falls back to the full corpus (with
    # a loud note) while the test split is too small to gate on.
    assignments = load_split_assignments()
    test_scored = [s for s in scored if _split_of(s, assignments) == "test"] if assignments else []
    split_name = "test"
    if len([s for s in test_scored if "error" not in s and s.get("predicted")]) >= MIN_CORPUS:
        scored = test_scored
    else:
        print(f"NOTE: test split too small (< {MIN_CORPUS} runs); gating on the FULL corpus instead. "
              "Numbers are in-sample until the test split grows.")
        split_name = "all (in-sample)"

    valid = [s for s in scored if "error" not in s and s.get("predicted")]
    if len(valid) < MIN_CORPUS:
        print(f"SKIP: only {len(valid)} labeled runs on disk (< {MIN_CORPUS}). "
              "Detonate the detection_tests corpus (scripts/bulk_verify_detection_tests.py) first.")
        return

    m = compute_metrics(scored)
    sp = m["thresholds"]["suspicious-or-worse"]
    mo = m["thresholds"]["malicious-only"]
    recall_sp = sp["recall"] if sp["recall"] is not None else 0.0
    fpr_sp = sp["fpr"] if sp["fpr"] is not None else 0.0
    precision_mo = mo["precision"] if mo["precision"] is not None else 1.0

    assert recall_sp >= MIN_RECALL_SUSPICIOUS_PLUS, \
        f"recall(suspicious+) {recall_sp:.3f} < floor {MIN_RECALL_SUSPICIOUS_PLUS} -- detection regressed"
    assert fpr_sp <= MAX_FPR_SUSPICIOUS_PLUS, \
        f"fpr(suspicious+) {fpr_sp:.3f} > ceiling {MAX_FPR_SUSPICIOUS_PLUS} -- false positives spiked"
    assert precision_mo >= MIN_PRECISION_MALICIOUS, \
        f"precision(malicious) {precision_mo:.3f} < floor {MIN_PRECISION_MALICIOUS} -- benign mislabeled malicious"

    print(f"PASS [{split_name}]: {len(valid)} runs | recall(susp+)={recall_sp:.3f}{_fmt_ci(sp['recall_ci'])} "
          f"fpr(susp+)={fpr_sp:.3f}{_fmt_ci(sp['fpr_ci'])} precision(mal)={precision_mo:.3f}{_fmt_ci(mo['precision_ci'])}")


if __name__ == "__main__":
    main()
