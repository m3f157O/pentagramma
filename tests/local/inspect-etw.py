"""Inspect raw ETW JSONL to see field names and sample events per type."""

import json
import sys
from collections import defaultdict
from pathlib import Path


def main(jsonl_path: Path) -> None:
    by_type = defaultdict(list)
    field_names = defaultdict(set)

    with jsonl_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            et = ev.get("event_type", "Unknown")
            by_type[et].append(ev)
            data = ev.get("data") or {}
            field_names[et].update(data.keys())

    for et in sorted(by_type.keys()):
        events = by_type[et]
        print("=" * 70)
        print(f"{et}  ({len(events)} events)")
        print("=" * 70)
        print("Fields:", ", ".join(sorted(field_names[et])))

        # Show up to 3 non-empty sample events
        shown = 0
        for ev in events:
            data = ev.get("data") or {}
            if not data:
                continue
            print(json.dumps(ev, indent=2, ensure_ascii=False))
            shown += 1
            if shown >= 3:
                break
        if shown == 0:
            print("(all events have empty data)")
        print()


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs/etw_test.jsonl")
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)
    main(path)
