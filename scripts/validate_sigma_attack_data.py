"""Validate the Sigma rule corpus against Splunk Attack Data -- offline, no VM.

Splunk Attack Data (github.com/splunk/attack_data) ships real Sysmon captures
of attacker techniques as one XML <Event> per line (wevtutil format). This
script downloads selected datasets (cached under out/attack_data/), parses
them with the SAME normalizer the guest agent uses
(agent/windows/sysmon_parser.py), runs our production SigmaEngine over the
events, and reports:

  * per-dataset: how many of our Sigma rules fired (0 = recall gap on that
    technique's telemetry);
  * per-technique: covered / total datasets;
  * rule usage: which of our rules NEVER fired on any dataset (dead-weight
    candidates, or techniques absent from the selected set).

This validates the Sigma layer's BREADTH the same way
scripts/verify_atomic_coverage.py validates the live pipeline -- but with no
VM time and 342 real attack captures across 143 ATT&CK techniques.

    .venv/Scripts/python.exe scripts/validate_sigma_attack_data.py [--max N]
        [--techniques T1003,T1055] [--all]
"""

import argparse
import json
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "agent" / "windows"))

from orchestrator.config import get_config  # noqa: E402
from scripts.replay_detection import build_sigma_engine  # noqa: E402
from sysmon_parser import SysmonParser  # noqa: E402  (agent-side module)

TREE_CACHE = PROJECT_ROOT / "out" / "_ad_tree.json"
TREE_API = "https://api.github.com/repos/splunk/attack_data/git/trees/master?recursive=1"
RAW_BASE = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
CACHE_DIR = PROJECT_ROOT / "out" / "attack_data"
DATASET_RE = re.compile(r"datasets/attack_techniques/(T[0-9]+(?:\.[0-9]+)?)/(.+\.log)$")


def load_tree() -> list:
    if TREE_CACHE.exists():
        tree = json.loads(TREE_CACHE.read_text(encoding="utf-8"))
    else:
        with urllib.request.urlopen(TREE_API, timeout=60) as resp:
            tree = json.loads(resp.read().decode("utf-8"))
        TREE_CACHE.write_text(json.dumps(tree), encoding="utf-8")
    out = []
    for item in tree.get("tree", []):
        m = DATASET_RE.match(item.get("path", ""))
        if m and "sysmon" in item["path"].lower() and "linux" not in item["path"].lower():
            out.append((m.group(1), item["path"]))
    return out


def fetch(path: str) -> Path:
    local = CACHE_DIR / path
    if not local.exists():
        local.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(RAW_BASE + path, timeout=300) as resp:
            local.write_bytes(resp.read())
    return local


def parse_log(path: Path, parser: SysmonParser) -> list:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    return parser._parse_xml(f'<?xml version="1.0" encoding="UTF-8"?><Events>{text}</Events>')


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max", type=int, default=40, help="max datasets to download (default 40)")
    ap.add_argument("--techniques", type=str, default="", help="comma-separated ATT&CK ids to include")
    ap.add_argument("--all", action="store_true", help="all indexed datasets (large download)")
    args = ap.parse_args()

    datasets = load_tree()
    if args.techniques:
        want = {t.strip() for t in args.techniques.split(",") if t.strip()}
        datasets = [(t, p) for t, p in datasets if t in want]
    # one dataset per technique first (breadth), then fill by path order
    by_tech = defaultdict(list)
    for t, p in datasets:
        by_tech[t].append(p)
    ordered = []
    for t in sorted(by_tech):
        ordered.append((t, sorted(by_tech[t])[0]))
    for t in sorted(by_tech):
        for p in sorted(by_tech[t])[1:]:
            ordered.append((t, p))
    if not args.all:
        ordered = ordered[: args.max]

    cfg = get_config()
    engine = build_sigma_engine(cfg)
    parser = SysmonParser()

    tech_stats = defaultdict(lambda: {"total": 0, "covered": 0})
    zero_datasets = []
    rule_hits = Counter()
    for i, (tech, path) in enumerate(ordered, 1):
        try:
            local = fetch(path)
            events = parse_log(local, parser)
        except Exception as exc:  # noqa: BLE001 -- report and continue over the corpus
            print(f"  [{i}/{len(ordered)}] {tech} {path}: ERROR {exc}")
            continue
        alerts = engine.evaluate(events) if events else []
        rules = {((a.get("sigma") or {}).get("title") or "?") for a in alerts}
        rule_hits.update(rules)
        tech_stats[tech]["total"] += 1
        tech_stats[tech]["covered"] += bool(alerts)
        mark = f"{len(alerts)} alerts / {len(rules)} rules" if alerts else "** ZERO **"
        if not alerts:
            zero_datasets.append((tech, path, len(events)))
        print(f"  [{i}/{len(ordered)}] {tech:<11} {len(events):>6} events -> {mark}  ({Path(path).parent.name})")

    print(f"\n{'technique':<11} {'datasets':>8} {'covered':>8}")
    print("-" * 30)
    for tech in sorted(tech_stats):
        st = tech_stats[tech]
        print(f"{tech:<11} {st['total']:>8} {st['covered']:>8}")
    total = sum(s['total'] for s in tech_stats.values())
    covered = sum(s['covered'] for s in tech_stats.values())
    print(f"\nTOTAL: {covered}/{total} datasets produced >=1 Sigma alert "
          f"({100*covered/total:.0f}%)" if total else "no datasets")
    print(f"distinct rules fired: {len(rule_hits)}")
    if zero_datasets:
        print(f"\nZERO-match datasets (recall gaps to review): {len(zero_datasets)}")
        for tech, path, nev in zero_datasets[:30]:
            print(f"  {tech:<11} {nev:>6} ev  {path}")


if __name__ == "__main__":
    main()
