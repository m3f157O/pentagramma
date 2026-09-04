"""Unit tests for heuristics._detect_network_bursts (NetworkBurstDetected).

Synthetic Sysmon-style EID 3/22 event lists; asserts each burst kind fires,
benign volumes stay quiet, and verdict classification scores the kinds as
intended. Run directly:

    .venv/Scripts/python.exe tests/test_network_burst.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import detectors, heuristics  # noqa: E402

BASE = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)


def _connects(pid, n, step_seconds=0.1, dest_ip="10.0.0.9", ports=None, initiated="true"):
    evs = []
    for i in range(n):
        ts = (BASE + timedelta(seconds=i * step_seconds)).isoformat()
        port = ports[i] if ports else "443"
        evs.append({
            "event_type": "NetworkConnect", "event_id": 3, "source": "sysmon", "timestamp": ts,
            "data": {"UtcTime": ts, "ProcessId": str(pid), "Image": "C:\\x\\sample.exe",
                     "DestinationIp": dest_ip, "DestinationPort": str(port), "Initiated": initiated},
        })
    return evs


def _dns(pid, names, step_seconds=0.2):
    evs = []
    for i, name in enumerate(names):
        ts = (BASE + timedelta(seconds=i * step_seconds)).isoformat()
        evs.append({
            "event_type": "DnsQuery", "event_id": 22, "source": "sysmon", "timestamp": ts,
            "data": {"UtcTime": ts, "ProcessId": str(pid), "Image": "C:\\x\\sample.exe", "QueryName": name},
        })
    return evs


def main() -> None:
    # 1. Port scan: 20 distinct ports to one host inside 2s -> port_scan alert.
    alerts = heuristics.detect_bursts(_connects(4242, 20, ports=list(range(1000, 1020))))
    kinds = [a["data"]["BurstKind"] for a in alerts]
    assert kinds == ["port_scan"], kinds
    a = alerts[0]
    assert a["event_id"] == 9105 and a["event_type"] == "NetworkBurstDetected"
    assert a["data"]["ProcessId"] == "4242"  # str, for scope attribution
    assert a["data"]["DestinationIp"] == "10.0.0.9"
    assert a["data"]["Count"] == 20
    print("PASS port_scan fires")

    # 2. Connection flood: 45 connects to one port inside ~4.5s -> flood alert.
    alerts = heuristics.detect_bursts(_connects(4242, 45, ports=["443"] * 45))
    kinds = [a["data"]["BurstKind"] for a in alerts]
    assert kinds == ["connection_flood"], kinds
    print("PASS connection_flood fires")

    # 3. Port scan suppresses the redundant flood alert for the same window.
    alerts = heuristics.detect_bursts(_connects(4242, 45, ports=list(range(2000, 2045))))
    kinds = sorted(a["data"]["BurstKind"] for a in alerts)
    assert kinds == ["port_scan"], kinds
    print("PASS port_scan suppresses connection_flood")

    # 4. DNS tunneling: 25 mostly-unique long names -> dns_tunnel_suspect.
    names = [f"{('a%02x' % i) * 16}.tunnel.example.com" for i in range(25)]  # 32-hex-char labels
    alerts = heuristics.detect_bursts(_dns(4242, names))
    kinds = [a["data"]["BurstKind"] for a in alerts]
    assert kinds == ["dns_tunnel_suspect"], kinds
    print("PASS dns_tunnel_suspect fires")

    # 5. DNS flood: 60 short repeated queries -> dns_flood (not tunnel).
    alerts = heuristics.detect_bursts(_dns(4242, ["www.example.com"] * 60))
    kinds = [a["data"]["BurstKind"] for a in alerts]
    assert kinds == ["dns_flood"], kinds
    print("PASS dns_flood fires")

    # 6. Benign volumes: ~59 connects + 24 queries spread over the run -> nothing.
    benign = _connects(1000, 30, step_seconds=5.0, dest_ip="20.190.160.17") \
        + _connects(1001, 29, step_seconds=6.0, dest_ip="8.8.8.8") \
        + _dns(1000, ["time.windows.com", "login.live.com"] * 12)
    assert heuristics.detect_bursts(benign) == []
    print("PASS benign volumes stay silent")

    # 7. Inbound-only connects never count.
    assert heuristics.detect_bursts(_connects(4242, 50, initiated="false")) == []
    print("PASS inbound-only ignored")

    # 8. Spread-out port touches (20 ports over 200s) don't fire.
    assert heuristics.detect_bursts(_connects(4242, 20, step_seconds=10.0, ports=list(range(1000, 1020)))) == []
    print("PASS slow scan below window")

    # 9. Verdict classification: port_scan/dns_tunnel_suspect = high, floods = medium.
    for kind, sev in [("port_scan", "high"), ("dns_tunnel_suspect", "high"),
                      ("connection_flood", "medium"), ("dns_flood", "medium")]:
        c = detectors.classify_alert({
            "event_type": "NetworkBurstDetected", "event_id": 9105,
            "data": {"BurstKind": kind, "ProcessId": "4242", "Type": "x"},
        })
        assert c is not None and c.severity == sev, (kind, c)
    print("PASS verdict severity mapping")

    # 10. MITRE mapping present.
    from orchestrator.mitre_mapping import enrich_alert
    a = enrich_alert({"event_type": "NetworkBurstDetected", "data": {"BurstKind": "port_scan"}})
    mitre = a.get("mitre") or {}
    assert mitre.get("primary", {}).get("technique_id") == "T1046", mitre
    assert len(mitre.get("candidates")) == 3, mitre
    print("PASS MITRE mapping:", mitre["primary"], "+", [c["technique_id"] for c in mitre["candidates"]])

    print("ALL NETWORK BURST TESTS PASSED")


if __name__ == "__main__":
    main()
