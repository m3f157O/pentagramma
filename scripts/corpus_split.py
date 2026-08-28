"""Seeded, stratified train/test splitter for the labeled corpus.

Assigns every label in tests/corpus/labels.json to `train` or `test` and
persists the assignment to tests/corpus/splits.json so it is FROZEN:

  * Idempotent -- existing assignments are never moved; only new labels get
    assigned. Re-running after corpus growth is safe.
  * Deterministic -- assignment order comes from sha256(seed + key), not
    wall-clock randomness, so the split is reproducible from scratch.
  * Stratified by (label, family) -- each stratum contributes ~20% to test,
    so no family ends up measured-only or tuned-only.
  * Tiny strata (n < MIN_STRATUM) go all-train: with 1-3 members a test
    share would be 0 or 1 samples, which measures nothing.

Key choice matches detection_metrics label matching precedence: sha256 when
the label has one, else filename, else report id.

    python scripts/corpus_split.py            # assign + report
    python scripts/corpus_split.py --show     # just print current split stats
"""

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

LABELS_PATH = PROJECT_ROOT / "tests" / "corpus" / "labels.json"
SPLITS_PATH = PROJECT_ROOT / "tests" / "corpus" / "splits.json"

SEED = "sandbox-corpus-v1"
TEST_RATIO = 0.2
MIN_STRATUM = 4


def label_key(label: Dict[str, Any]) -> str:
    match = label.get("match", {})
    for k in ("sha256", "filename", "report"):
        if match.get(k):
            return str(match[k])
    return ""


def load_splits(path: Path = SPLITS_PATH) -> Dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"seed": SEED, "test_ratio": TEST_RATIO, "assignments": {}}


def save_splits(splits: Dict[str, Any], path: Path = SPLITS_PATH) -> None:
    path.write_text(json.dumps(splits, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _stratum(label: Dict[str, Any]) -> str:
    return f"{label.get('label', '?')}|{label.get('family') or 'unlabeled'}"


def assign(labels: List[Dict[str, Any]], splits: Dict[str, Any]) -> int:
    """Assign unassigned labels. Returns number of NEW assignments made."""
    assignments: Dict[str, str] = splits["assignments"]
    strata: Dict[str, List[str]] = defaultdict(list)
    for label in labels:
        key = label_key(label)
        if key and key not in assignments:
            strata[_stratum(label)].append(key)

    new = 0
    for stratum, keys in strata.items():
        # Deterministic pseudo-random order for THIS stratum's new keys.
        keys.sort(key=lambda k: hashlib.sha256(f"{SEED}|{stratum}|{k}".encode()).hexdigest())
        if len(keys) < MIN_STRATUM:
            for k in keys:
                assignments[k] = "train"
                new += 1
            continue
        n_test = max(1, round(len(keys) * TEST_RATIO))
        for i, k in enumerate(keys):
            assignments[k] = "test" if i < n_test else "train"
            new += 1
    return new


def stats(labels: List[Dict[str, Any]], splits: Dict[str, Any]) -> str:
    assignments = splits["assignments"]
    counts = defaultdict(lambda: {"train": 0, "test": 0, "unassigned": 0})
    for label in labels:
        key = label_key(label)
        split = assignments.get(key, "unassigned")
        counts[_stratum(label)][split] += 1
    lines = [f"splits.json: {len(assignments)} assignments (seed={splits['seed']}, ratio={splits['test_ratio']})", ""]
    for stratum in sorted(counts):
        c = counts[stratum]
        lines.append(f"  {stratum:40} train={c['train']:>3} test={c['test']:>3} unassigned={c['unassigned']}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--show", action="store_true", help="print current split stats without assigning")
    args = parser.parse_args()

    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8")).get("labels", [])
    splits = load_splits()
    if not args.show:
        new = assign(labels, splits)
        if new:
            save_splits(splits)
        print(f"assigned {new} new label(s)")
    print(stats(labels, splits))


if __name__ == "__main__":
    main()
