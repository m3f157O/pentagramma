"""Summarize a JSONL ETW event log produced by etw_collector.py."""

import json
import sys
from collections import Counter
from pathlib import Path


def _hex_int(value):
    if value is None:
        return None
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return value


def main(jsonl_path: Path) -> None:
    event_types = Counter()
    process_starts = []
    process_stops = []
    registry_sets = []
    registry_creates = []
    file_creates = []
    network_events = []
    services = []

    with jsonl_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            et = ev.get("event_type", "Unknown")
            event_types[et] += 1
            data = ev.get("data") or {}

            if et == "ProcessStart":
                process_starts.append({
                    "ts": ev.get("timestamp"),
                    "pid": _hex_int(data.get("ProcessId")),
                    "ppid": _hex_int(data.get("ParentId")),
                    "image": data.get("ImageFileName"),
                    "cmd": data.get("CommandLine"),
                    "user": data.get("UserSID"),
                })
            elif et == "ProcessStop":
                process_stops.append({
                    "ts": ev.get("timestamp"),
                    "pid": _hex_int(data.get("ProcessId")),
                    "image": data.get("ImageFileName"),
                    "cmd": data.get("CommandLine"),
                })
            elif et == "Registry":
                opcode = (ev.get("opcode") or "").lower()
                entry = {
                    "ts": ev.get("timestamp"),
                    "opcode": opcode,
                    "key": data.get("KeyName"),
                    "pid": _hex_int(data.get("ProcessId")),
                }
                if opcode in ("setvalue",):
                    registry_sets.append(entry)
                elif opcode in ("create", "createkey"):
                    registry_creates.append(entry)
            elif et == "FileIo":
                file_creates.append({
                    "ts": ev.get("timestamp"),
                    "opcode": ev.get("opcode"),
                    "path": data.get("FileName") or data.get("KeyName"),
                })
            elif et == "Network":
                network_events.append({
                    "ts": ev.get("timestamp"),
                    "opcode": ev.get("opcode"),
                    "data": data,
                })
            elif et == "Services":
                services.append({
                    "ts": ev.get("timestamp"),
                    "name": data.get("ServiceName"),
                    "state": data.get("ServiceState"),
                    "pid": _hex_int(data.get("ProcessId")),
                })

    print("=" * 70)
    print(f"ETW event summary for {jsonl_path}")
    print("=" * 70)
    print("\nEvent type counts:")
    for et, count in event_types.most_common():
        print(f"  {et:20s} {count:>8d}")

    def nonempty(items, key):
        return [x for x in items if x.get(key) not in (None, "")]

    proc_starts_ne = nonempty(process_starts, "image")
    proc_stops_ne = nonempty(process_stops, "image")
    reg_sets_ne = nonempty(registry_sets, "key")
    reg_creates_ne = nonempty(registry_creates, "key")
    file_ne = nonempty(file_creates, "path")
    net_ne = nonempty(network_events, "data")

    print(f"\n--- Process starts ({len(proc_starts_ne)} with image, first 10) ---")
    for p in proc_starts_ne[:10]:
        print(f"  pid={p['pid']} ppid={p['ppid']} user={p['user']} image={p['image']}")
        print(f"       cmd={p['cmd']}")

    print(f"\n--- Process stops ({len(proc_stops_ne)} with image, first 10) ---")
    for p in proc_stops_ne[:10]:
        print(f"  pid={p['pid']} image={p['image']} cmd={p['cmd']}")

    print(f"\n--- Registry writes ({len(reg_sets_ne)} with key, first 10) ---")
    for r in reg_sets_ne[:10]:
        print(f"  pid={r['pid']} key={r['key']}")

    print(f"\n--- Registry creates ({len(reg_creates_ne)} with key, first 10) ---")
    for r in reg_creates_ne[:10]:
        print(f"  pid={r['pid']} key={r['key']}")

    print(f"\n--- File I/O ({len(file_ne)} with path, first 10) ---")
    for f in file_ne[:10]:
        print(f"  opcode={f['opcode']} path={f['path']}")

    print(f"\n--- Network events ({len(net_ne)} with data, first 10) ---")
    for n in net_ne[:10]:
        print(f"  opcode={n['opcode']} data={n['data']}")

    print(f"\n--- Services (first 5) ---")
    for s in services[:5]:
        print(f"  name={s['name']} state={s['state']} pid={s['pid']}")


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs/etw_test.jsonl")
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)
    main(path)
