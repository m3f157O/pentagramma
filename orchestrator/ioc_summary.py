"""Consolidated Indicators-of-Compromise summary, aggregated purely from
already-collected report data (Sysmon telemetry, the pcap capture if one
exists, dropped files, static analysis, priority-tagged alerts). No new
data collection -- mirrors how compute_coverage()/build_process_tree()
already derive report sections from data reporting.py already has in
hand.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from orchestrator import pcap_view
from orchestrator.pid_lineage import PidLineage


def build_ioc_summary(
    telemetry_events: List[Dict[str, Any]],
    network_capture: Optional[Dict[str, Any]],
    dropped_files: Optional[Dict[str, Any]],
    static_analysis: Optional[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    lineage: Optional[PidLineage] = None,
) -> Dict[str, Any]:
    # Loaded once and reused for both domains and http_requests -- summarize_capture()'s
    # row-flattening is cached by pcap_view, but its aggregation pass is not, so calling
    # it twice would redo that work for no reason.
    pcap_summary = _load_pcap_summary(network_capture)

    return {
        "network_connections": _extract_network_connections(telemetry_events, lineage),
        "domains": _extract_domains(telemetry_events, pcap_summary),
        "http_requests": pcap_summary.get("http_requests", []) if pcap_summary else [],
        "dropped_files": _extract_dropped_files(dropped_files),
        "sample_hashes": (static_analysis or {}).get("hashes", {}),
        "registry_persistence": _extract_registry_persistence(alerts),
    }


def _load_pcap_summary(network_capture: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Absence (disabled/failed/missing file) is normal, not an error --
    same philosophy as main.py's _resolve_capture.
    """
    host_path = (network_capture or {}).get("HostPath")
    if not host_path or not Path(host_path).exists():
        return None
    try:
        return pcap_view.summarize_capture(host_path)
    except Exception:
        return None


def _extract_network_connections(
    events: List[Dict[str, Any]], lineage: Optional[PidLineage]
) -> List[Dict[str, Any]]:
    """Annotates (does not filter -- same "never silently hide, just
    classify" approach as orchestrator/pid_lineage.py::classify_alert_scope)
    each connection with in_sample_scope, so e.g. the agent's own telemetry/
    health-check traffic doesn't read as indistinguishable from what the
    sample itself did. If the same (ip, port) pair is seen from more than
    one PID, it's sample-scoped if ANY occurrence was -- a connection the
    sample made is still worth surfacing as sample-attributed even if some
    unrelated process also happened to hit the same endpoint.
    """
    connections: Dict[Any, Dict[str, Any]] = {}
    for event in events:
        event_type = event.get("event_type") or event.get("EventType")
        if event_type != "NetworkConnect":
            continue
        data = event.get("data") or {}
        dest_ip = data.get("DestinationIp")
        dest_port = data.get("DestinationPort")
        if not dest_ip:
            continue
        key = (dest_ip, dest_port)
        # Prefer ProcessGuid over ProcessId (immune to PID reuse) via the
        # shared lineage precedence -- see PidLineage.contains_event.
        in_scope = lineage is not None and lineage.contains_event(data)
        existing = connections.get(key)
        if existing is None:
            connections[key] = {"destination_ip": dest_ip, "destination_port": dest_port, "in_sample_scope": in_scope}
        elif in_scope:
            existing["in_sample_scope"] = True
    return list(connections.values())


def _extract_domains(events: List[Dict[str, Any]], pcap_summary: Optional[Dict[str, Any]]) -> List[str]:
    """Deduped union of two vantage points on the same traffic -- Sysmon's
    own DnsQuery hook and raw-packet DNS parsing -- presence-only, not
    double-counted frequencies from measuring the same thing twice.
    """
    domains = set()
    for event in events:
        event_type = event.get("event_type") or event.get("EventType")
        if event_type != "DnsQuery":
            continue
        data = event.get("data") or {}
        qname = data.get("QueryName")
        if qname:
            domains.add(qname)

    if pcap_summary:
        for entry in pcap_summary.get("dns_queries") or []:
            qname = entry.get("qname")
            if qname:
                domains.add(qname)

    return sorted(domains)


def _extract_dropped_files(dropped_files: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not dropped_files or not dropped_files.get("enabled"):
        return []
    result = []
    for item in dropped_files.get("items") or []:
        if item.get("status") != "retrieved":
            continue
        result.append(
            {
                "filename": item.get("filename"),
                "original_path": item.get("original_path"),
                "sha256": item.get("sha256"),
            }
        )
    return result


def _extract_registry_persistence(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Reuses heuristics.annotate_priority()'s existing priority="high"
    tagging (Run/RunOnce/Winlogon/IFEO/etc.) rather than recomputing it.
    """
    registry_types = {"RegistryCreateDelete", "RegistryValueSet", "RegistryKeyValueRename"}
    result = []
    for alert in alerts:
        if alert.get("event_type") not in registry_types:
            continue
        if alert.get("priority") != "high":
            continue
        data = alert.get("data") or {}
        result.append(
            {
                "target_object": data.get("TargetObject"),
                "details": data.get("Details"),
                "priority_reason": alert.get("priority_reason"),
            }
        )
    return result
