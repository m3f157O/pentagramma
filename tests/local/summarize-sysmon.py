"""Summarize a JSONL Sysmon event log."""

import json
import sys
from collections import Counter
from pathlib import Path


def main(jsonl_path: Path) -> None:
    event_types = Counter()
    process_creates = []
    network_connections = []
    dns_queries = []
    file_creates = []
    registry_sets = []
    remote_threads = []

    with jsonl_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            et = ev.get("event_type", "Unknown")
            event_types[et] += 1
            data = ev.get("data") or {}

            if et == "ProcessCreate":
                process_creates.append({
                    "ts": ev.get("timestamp"),
                    "pid": data.get("ProcessId"),
                    "ppid": data.get("ParentProcessId"),
                    "image": data.get("Image"),
                    "cmd": data.get("CommandLine"),
                    "user": data.get("User"),
                    "hash": data.get("Hashes"),
                })
            elif et == "NetworkConnect":
                network_connections.append({
                    "ts": ev.get("timestamp"),
                    "image": data.get("Image"),
                    "pid": data.get("ProcessId"),
                    "src": f"{data.get('SourceIp')}:{data.get('SourcePort')}",
                    "dst": f"{data.get('DestinationIp')}:{data.get('DestinationPort')}",
                    "proto": data.get("Protocol"),
                })
            elif et == "DnsQuery":
                dns_queries.append({
                    "ts": ev.get("timestamp"),
                    "image": data.get("Image"),
                    "pid": data.get("ProcessId"),
                    "query": data.get("QueryName"),
                    "response": data.get("QueryResults"),
                })
            elif et == "FileCreate":
                file_creates.append({
                    "ts": ev.get("timestamp"),
                    "image": data.get("Image"),
                    "pid": data.get("ProcessId"),
                    "path": data.get("TargetFilename"),
                    "hash": data.get("Hashes"),
                })
            elif et == "RegistryValueSet":
                registry_sets.append({
                    "ts": ev.get("timestamp"),
                    "image": data.get("Image"),
                    "pid": data.get("ProcessId"),
                    "key": data.get("TargetObject"),
                    "value": data.get("Details"),
                })
            elif et == "CreateRemoteThread":
                remote_threads.append({
                    "ts": ev.get("timestamp"),
                    "source": data.get("SourceImage"),
                    "target": data.get("TargetImage"),
                    "src_pid": data.get("SourceProcessId"),
                    "tgt_pid": data.get("TargetProcessId"),
                })

    print("=" * 70)
    print(f"Sysmon event summary for {jsonl_path}")
    print("=" * 70)
    print("\nEvent type counts:")
    for et, count in event_types.most_common():
        print(f"  {et:25s} {count:>8d}")

    print(f"\n--- Process creates (first 10) ---")
    for p in process_creates[:10]:
        print(f"  pid={p['pid']} ppid={p['ppid']} image={p['image']}")
        print(f"       cmd={p['cmd']}")
        print(f"       hash={p['hash']}")

    print(f"\n--- Network connects (first 10) ---")
    for n in network_connections[:10]:
        print(f"  {n['src']} -> {n['dst']} proto={n['proto']} image={n['image']}")

    print(f"\n--- DNS queries (first 10) ---")
    for d in dns_queries[:10]:
        print(f"  {d['query']} (pid={d['pid']} image={d['image']})")

    print(f"\n--- File creates (first 10) ---")
    for f in file_creates[:10]:
        print(f"  {f['path']} (pid={f['pid']} image={f['image']})")

    print(f"\n--- Registry value sets (first 10) ---")
    for r in registry_sets[:10]:
        print(f"  {r['key']} = {r['value']} (pid={r['pid']} image={r['image']})")

    print(f"\n--- Remote threads (all) ---")
    for r in remote_threads:
        print(f"  {r['source']}({r['src_pid']}) -> {r['target']}({r['tgt_pid']})")


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs/sysmon_test.jsonl")
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)
    main(path)
