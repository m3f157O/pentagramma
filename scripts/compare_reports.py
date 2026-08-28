#!/usr/bin/env python3
"""Compare two sandbox analysis reports and show new/missing telemetry."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def load_report(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def event_counts(report: Dict[str, Any]) -> Dict[str, int]:
    return dict(report.get("summary", {}).get("event_counts", {}))


def eid_breakdown(report: Dict[str, Any]) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    for alert in report.get("alerts", []):
        eid = alert.get("event_id")
        if eid:
            counts[eid] = counts.get(eid, 0) + 1
    return counts


def unique_images(report: Dict[str, Any], eid: int) -> List[str]:
    images = set()
    for alert in report.get("alerts", []):
        if alert.get("event_id") == eid:
            data = alert.get("data", {})
            for key in ("Image", "SourceImage", "TargetImage"):
                if key in data and data[key]:
                    images.add(data[key])
    return sorted(images)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <old_report.json> <new_report.json>")
        return 1

    old_path, new_path = sys.argv[1], sys.argv[2]
    old = load_report(old_path)
    new = load_report(new_path)

    old_counts = event_counts(old)
    new_counts = event_counts(new)
    all_keys = sorted(set(old_counts) | set(new_counts))

    print(f"Comparing:\n  OLD: {old_path}\n  NEW: {new_path}\n")
    print("=== Event-count delta ===")
    print(f"{'Event':<25} {'Old':>8} {'New':>8} {'Delta':>8}")
    print("-" * 52)
    for key in all_keys:
        old_val = old_counts.get(key, 0)
        new_val = new_counts.get(key, 0)
        delta = new_val - old_val
        marker = ""
        if delta > 0:
            marker = "  <-- NEW"
        print(f"{key:<25} {old_val:>8} {new_val:>8} {delta:>+8}{marker}")

    old_eids = set(eid_breakdown(old).keys())
    new_eids = set(eid_breakdown(new).keys())
    appeared = new_eids - old_eids
    disappeared = old_eids - new_eids

    if appeared:
        print("\n=== New EIDs observed ===")
        for eid in sorted(appeared):
            print(f"  EID {eid}")
            for img in unique_images(new, eid):
                print(f"    - {img}")
    if disappeared:
        print("\n=== EIDs no longer observed ===")
        for eid in sorted(disappeared):
            print(f"  EID {eid}")

    old_total = old.get("summary", {}).get("total_events", 0)
    new_total = new.get("summary", {}).get("total_events", 0)
    print(f"\nTotal events: {old_total} -> {new_total} ({new_total - old_total:+,})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
