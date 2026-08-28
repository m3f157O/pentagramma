"""Build a process tree from Sysmon ProcessCreate / ProcessTerminate events."""
from typing import Any, Dict, List, Optional


def build_process_tree(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return a forest of processes from EID 1 and EID 5 events.

    Each node contains:
      - pid, ppid, image, command_line, start_time, end_time (if terminated)
      - children: list of child nodes
    """
    processes: Dict[int, Dict[str, Any]] = {}

    for event in events:
        event_type = event.get("event_type") or event.get("EventType")
        data = event.get("data") or {}
        if event_type not in ("ProcessCreate", "ProcessTerminate"):
            continue

        try:
            pid = int(data.get("ProcessId", -1))
        except (TypeError, ValueError):
            continue
        if pid < 0:
            continue

        if event_type == "ProcessCreate":
            try:
                ppid = int(data.get("ParentProcessId", 0))
            except (TypeError, ValueError):
                ppid = 0

            existing = processes.get(pid)
            if existing:
                existing.update(
                    {
                        "pid": pid,
                        "ppid": ppid,
                        "image": data.get("Image"),
                        "command_line": data.get("CommandLine"),
                        "start_time": event.get("timestamp"),
                        "user": data.get("User"),
                    }
                )
            else:
                processes[pid] = {
                    "pid": pid,
                    "ppid": ppid,
                    "image": data.get("Image"),
                    "command_line": data.get("CommandLine"),
                    "start_time": event.get("timestamp"),
                    "end_time": None,
                    "user": data.get("User"),
                    "children": [],
                }

        elif event_type == "ProcessTerminate":
            if pid in processes:
                processes[pid]["end_time"] = event.get("timestamp")
            else:
                processes[pid] = {
                    "pid": pid,
                    "ppid": None,
                    "image": data.get("Image"),
                    "command_line": None,
                    "start_time": None,
                    "end_time": event.get("timestamp"),
                    "user": data.get("User"),
                    "children": [],
                }

    # Link children to parents.
    roots: List[Dict[str, Any]] = []
    for pid, node in processes.items():
        ppid = node.get("ppid")
        if ppid and ppid in processes and ppid != pid:
            processes[ppid]["children"].append(node)
        else:
            roots.append(node)

    # Sort roots by start_time for a stable view.
    roots.sort(key=lambda n: n.get("start_time") or "")
    return roots
