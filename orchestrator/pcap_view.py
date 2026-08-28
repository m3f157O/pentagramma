"""Parses pcapng network captures (see agent/windows/network_capture.py,
copied to logs/<analysis_id>.pcapng after each run) via scapy.

Unlike report_view.py (pure, no file I/O by design), this module's whole
purpose IS file I/O -- dissecting a capture is not free the way parsing a
report's JSON is (benchmarked at ~36MB/s), so results are cached in memory
per file rather than re-parsed on every call. This is a deliberate, scoped
exception to the "just re-read from disk every call" approach used
elsewhere in this codebase.
"""

import threading
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader, hexdump

# Packet-count based, not MB: CPU cost tracks per-packet object construction
# more than raw bytes. Bounds worst-case latency for the 256MB capture
# ceiling in config.yaml (network_capture.max_file_size_mb) to a few seconds.
MAX_PACKETS_SUMMARY = 200_000
TOP_CONVERSATIONS_N = 10
DEFAULT_PAGE_LIMIT = 100

_CACHE_MAX_ENTRIES = 3
_cache_lock = threading.Lock()
_CacheKey = Tuple[str, float, int]
_cache: "OrderedDict[_CacheKey, Tuple[List[Dict[str, Any]], bool]]" = OrderedDict()


def _cache_key(path: Path) -> _CacheKey:
    stat = path.stat()
    return (str(path), stat.st_mtime, stat.st_size)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def _protocol_label(pkt: Any) -> str:
    if ARP in pkt:
        return "ARP"
    if DNS in pkt:
        return "DNS"
    if ICMP in pkt:
        return "ICMP"
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if IP in pkt or IPv6 in pkt:
        return "IP-other"
    return "Other"


def _endpoints(pkt: Any) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[int]]:
    src = dst = None
    sport = dport = None
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    if TCP in pkt:
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif UDP in pkt:
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
    return src, sport, dst, dport


def _flatten_packet(pkt: Any, index: int) -> Dict[str, Any]:
    protocol = _protocol_label(pkt)
    src, sport, dst, dport = _endpoints(pkt)
    row: Dict[str, Any] = {
        "index": index,
        "timestamp": _iso(pkt.time),
        "protocol": protocol,
        "src": src,
        "sport": sport,
        "dst": dst,
        "dport": dport,
        "length": len(pkt),
        "summary": pkt.summary(),
    }
    if protocol == "DNS" and DNSQR in pkt and pkt[DNS].qr == 0:
        try:
            row["dns_qname"] = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        except Exception:
            pass
    if HTTPRequest in pkt:
        # Plaintext HTTP only -- TLS-encrypted traffic (the overwhelming
        # majority of real C2 today) is invisible at this layer, same
        # inherent limitation as the rest of this capture.
        try:
            req = pkt[HTTPRequest]
            host = req.Host.decode(errors="replace") if req.Host else None
            path = req.Path.decode(errors="replace") if req.Path else None
            method = req.Method.decode(errors="replace") if req.Method else None
            if host or path:
                row["http_host"] = host
                row["http_path"] = path
                row["http_method"] = method
        except Exception:
            pass
    return row


def _build_rows(path: Path) -> Tuple[List[Dict[str, Any]], bool]:
    """Stream-parse path into flattened rows, capped at MAX_PACKETS_SUMMARY."""
    rows: List[Dict[str, Any]] = []
    truncated = False
    with PcapReader(str(path)) as reader:
        for index, pkt in enumerate(reader):
            if index >= MAX_PACKETS_SUMMARY:
                truncated = True
                break
            rows.append(_flatten_packet(pkt, index))
    return rows, truncated


def _get_rows(path: str) -> Tuple[List[Dict[str, Any]], bool]:
    """Build-or-fetch the cached flattened rows for path."""
    p = Path(path)
    key = _cache_key(p)
    with _cache_lock:
        cached = _cache.get(key)
        if cached is not None:
            _cache.move_to_end(key)
            return cached

    result = _build_rows(p)

    with _cache_lock:
        _cache[key] = result
        _cache.move_to_end(key)
        while len(_cache) > _CACHE_MAX_ENTRIES:
            _cache.popitem(last=False)
    return result


def summarize_capture(path: str) -> Dict[str, Any]:
    """Protocol breakdown, top conversations, DNS queries, and totals."""
    rows, truncated = _get_rows(path)

    total_packets = len(rows)
    total_bytes = sum(r["length"] for r in rows)
    start_time = rows[0]["timestamp"] if rows else None
    end_time = rows[-1]["timestamp"] if rows else None
    duration_seconds = None
    if rows:
        duration_seconds = round(
            (datetime.fromisoformat(end_time) - datetime.fromisoformat(start_time)).total_seconds(), 3
        )

    protocol_counts: Dict[str, int] = {}
    # Conversation key includes protocol so a TCP and UDP conversation that
    # happen to reuse the same IP:port pairing don't get merged.
    convo_bytes: Dict[Tuple[str, str, str], int] = {}
    convo_packets: Dict[Tuple[str, str, str], int] = {}
    dns_counts: Dict[str, int] = {}
    http_counts: Dict[Tuple[str, str, str], int] = {}

    for r in rows:
        protocol_counts[r["protocol"]] = protocol_counts.get(r["protocol"], 0) + 1

        if r["src"] and r["dst"]:
            a = f"{r['src']}:{r['sport']}" if r["sport"] is not None else r["src"]
            b = f"{r['dst']}:{r['dport']}" if r["dport"] is not None else r["dst"]
            key = (r["protocol"], *sorted([a, b]))
            convo_bytes[key] = convo_bytes.get(key, 0) + r["length"]
            convo_packets[key] = convo_packets.get(key, 0) + 1

        qname = r.get("dns_qname")
        if qname:
            dns_counts[qname] = dns_counts.get(qname, 0) + 1

        http_host = r.get("http_host")
        if http_host or r.get("http_path"):
            http_key = (r.get("http_method") or "", http_host or "", r.get("http_path") or "")
            http_counts[http_key] = http_counts.get(http_key, 0) + 1

    top_conversations = [
        {"protocol": key[0], "a": key[1], "b": key[2], "bytes": nbytes, "packets": convo_packets[key]}
        for key, nbytes in sorted(convo_bytes.items(), key=lambda kv: kv[1], reverse=True)[:TOP_CONVERSATIONS_N]
    ]
    dns_queries = [
        {"qname": qname, "count": count}
        for qname, count in sorted(dns_counts.items(), key=lambda kv: kv[1], reverse=True)
    ]
    # Plaintext HTTP only -- see the http_host/http_path extraction note in
    # _flatten_packet(); TLS-encrypted traffic is invisible at this layer.
    http_requests = [
        {"method": key[0], "host": key[1], "path": key[2], "count": count}
        for key, count in sorted(http_counts.items(), key=lambda kv: kv[1], reverse=True)
    ]

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "start_time": start_time,
        "end_time": end_time,
        "duration_seconds": duration_seconds,
        "packets_scanned": total_packets,
        "truncated": truncated,
        "protocol_counts": protocol_counts,
        "top_conversations": top_conversations,
        "http_requests": http_requests,
        "dns_queries": dns_queries,
    }


def packet_detail(path: str, index: int) -> Optional[Dict[str, Any]]:
    """Full dissection + hex dump for a single packet, by capture index.

    The flattened rows served by paginate_packets() deliberately carry only
    metadata (raw bytes would bloat the cache); this re-reads the pcapng on
    demand and walks to `index` -- cheap for one packet even at 200k rows.
    Returns None if the index is out of range.
    """
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader):
            if i == index:
                return {
                    "index": index,
                    "timestamp": _iso(pkt.time),
                    "summary": pkt.summary(),
                    # scapy's own renderings: the layer tree and the classic
                    # offset/hex/ascii dump.
                    "layers": pkt.show(dump=True),
                    "hex": hexdump(pkt, dump=True),
                }
            if i > index:
                break
    return None


def paginate_packets(
    path: str,
    offset: int = 0,
    limit: int = DEFAULT_PAGE_LIMIT,
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    port: Optional[int] = None,
    q: Optional[str] = None,
) -> Dict[str, Any]:
    """Slice/filter the flattened packet stream for on-demand browsing."""
    rows, truncated = _get_rows(path)
    total = len(rows)

    filtered = rows
    if protocol:
        filtered = [r for r in filtered if r["protocol"] == protocol]
    if ip:
        filtered = [r for r in filtered if r["src"] == ip or r["dst"] == ip]
    if port is not None:
        filtered = [r for r in filtered if r["sport"] == port or r["dport"] == port]
    if q:
        needle = q.lower()
        filtered = [
            r
            for r in filtered
            if needle in r["summary"].lower() or needle in (r.get("dns_qname") or "").lower()
        ]

    filtered_total = len(filtered)
    page = filtered[offset : offset + limit]

    return {
        "total": total,
        "filtered_total": filtered_total,
        # If the cache build hit MAX_PACKETS_SUMMARY before finishing the
        # file, filtered_total is a lower bound over the scanned prefix, not
        # a fact about the whole file -- say so rather than presenting a
        # falsely-precise number.
        "filtered_total_is_exact": not truncated,
        "packets_scanned": total,
        "truncated": truncated,
        "offset": offset,
        "limit": limit,
        "packets": page,
    }
