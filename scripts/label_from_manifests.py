"""Auto-label detonated incoming-corpus samples into tests/corpus/labels.json.

Maps each detonated MalwareBazaar sample (sha256, found via reports' sample
hashes) to a labels.json entry keyed by sha256 with its Bazaar family.
Idempotent: existing entries for the same sha256 are never touched. After
running, use scripts/corpus_split.py to assign train/test splits.

    .venv/Scripts/python.exe scripts/label_from_manifests.py [--dry-run]
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INCOMING = PROJECT_ROOT / "samples" / "incoming" / "malwarebazaar"
REPORTS = PROJECT_ROOT / "reports"
LABELS = PROJECT_ROOT / "tests" / "corpus" / "labels.json"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    # manifest sha256 -> family
    manifest = {}
    for mf in sorted(INCOMING.glob("*/manifest.jsonl")):
        for line in mf.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("sha256"):
                    manifest[row["sha256"].lower()] = row.get("family") or mf.parent.name

    labels_doc = json.loads(LABELS.read_text(encoding="utf-8"))
    entries = labels_doc.setdefault("labels", [])
    known = set()
    for e in entries:
        m = e.get("match") or {}
        if "sha256" in m:
            known.add(m["sha256"].lower())

    # report id -> sample sha256 (only reports whose sample is in the manifest)
    report_sha = {}
    for rp in sorted(REPORTS.glob("*.json")):
        if rp.stem.endswith(".summary"):
            continue
        try:
            head = json.loads(rp.read_text(encoding="utf-8", errors="replace")[:200000])
        except Exception:
            continue
        sha = (((head.get("sample") or {}).get("hashes") or {}).get("sha256") or "").lower()
        if sha in manifest:
            report_sha[rp.stem] = sha

    added = skipped = 0
    for report_id, sha in sorted(report_sha.items()):
        if sha in known:
            skipped += 1
            continue
        entries.append({
            "match": {"sha256": sha},
            "label": "malicious",
            "family": manifest[sha],
            "note": "abuse.ch ground truth (malwarebazaar family + threatfox IOCs)",
        })
        known.add(sha)
        added += 1
        print(f"  + {manifest[sha]:12s} {sha[:16]} (report {report_id[:8]})")

    print(f"\nadded {added}, already-labeled {skipped}, detonated manifest samples: {len(report_sha)}")
    if added and not args.dry_run:
        LABELS.write_text(json.dumps(labels_doc, indent=2) + "\n", encoding="utf-8")
        print(f"labels.json updated -> {len(entries)} entries total; now run scripts/corpus_split.py")
    elif added:
        print("(dry run -- labels.json untouched)")


if __name__ == "__main__":
    main()
