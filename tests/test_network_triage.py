"""Unit tests for network triage annotation (DGA raising + OS-noise lowering)
in heuristics.annotate_priority. Run directly:

    .venv/Scripts/python.exe tests/test_network_triage.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import heuristics  # noqa: E402


def _dns_alert(name):
    return {"event_type": "DnsQuery", "data": {"QueryName": name, "ProcessId": "100"}}


def _connect_alert(host):
    return {"event_type": "NetworkConnect", "data": {"DestinationHostname": host, "ProcessId": "100"}}


def main() -> None:
    # 1. DGA-looking domains are raised to priority=high.
    for dga in ["xjkqvzbnmwtpqrldfg.com", "qzxwvtrpnmlkjhgfdcb.net", "zqxjkvbnpdfghjklmwq.org"]:
        out = heuristics.annotate_priority([_dns_alert(dga)])[0]
        assert out.get("priority") == "high", (dga, out.get("priority"))
        assert "DGA" in out.get("priority_reason", "")
    print("PASS DGA-suspect domains raised")

    # 2. Normal-looking domains are untouched (no annotation at all).
    for ok in ["github.com", "pypi.org", "cdn.discordapp.com", "update.googleapis.com"]:
        out = heuristics.annotate_priority([_dns_alert(ok)])[0]
        assert "priority" not in out, (ok, out.get("priority"), out.get("priority_reason"))
    print("PASS normal domains unannotated")

    # 3. OS background traffic marked priority=low (annotation only, still present).
    for noise in ["time.windows.com", "login.live.com", "ocsp.digicert.com", "www.msftconnecttest.com"]:
        out = heuristics.annotate_priority([_dns_alert(noise)])[0]
        assert out.get("priority") == "low", (noise, out.get("priority"))
        assert "background" in out.get("priority_reason", "")
    print("PASS OS noise lowered")

    # 4. Suffix boundary: notwindows.com / windows.com.evil.tld must NOT match.
    for tricky in ["notwindows.com", "windows.com.evil-example.net", "fakedigicert.com"]:
        out = heuristics.annotate_priority([_dns_alert(tricky)])[0]
        assert out.get("priority") != "low", (tricky, out.get("priority"))
    print("PASS suffix boundary respected")

    # 5. Reverse-DNS and single labels skipped.
    for skip in ["1.0.0.127.in-addr.arpa", "localhost", ""]:
        out = heuristics.annotate_priority([_dns_alert(skip)])[0]
        assert "priority" not in out, skip
    print("PASS reverse-DNS / single-label skipped")

    # 6. NetworkConnect honored via DestinationHostname.
    out = heuristics.annotate_priority([_connect_alert("xjkqvzbnmwtpqrldfg.com")])[0]
    assert out.get("priority") == "high"
    out = heuristics.annotate_priority([_connect_alert("")])[0]
    assert "priority" not in out
    print("PASS NetworkConnect hostname annotation")

    # 7. Never downgrade an already-high alert.
    high = _dns_alert("time.windows.com")
    high["priority"] = "high"
    high["priority_reason"] = "something else"
    out = heuristics.annotate_priority([high])[0]
    assert out["priority"] == "high" and out["priority_reason"] == "something else"
    print("PASS existing high never downgraded")

    # 8. Non-network alerts unaffected; annotation never drops alerts.
    alerts = [{"event_type": "RegistryValueSet", "data": {"TargetObject": r"\HKLM\Software\Microsoft\Windows\CurrentVersion\Run"}},
              _dns_alert("example.org")]
    out = heuristics.annotate_priority(alerts)
    assert len(out) == 2 and out[0].get("priority") == "high" and "priority" not in out[1]
    print("PASS registry annotation unchanged, no filtering")

    print("ALL NETWORK TRIAGE TESTS PASSED")


if __name__ == "__main__":
    main()
