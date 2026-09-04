"""Unit tests for the WMI-Activity ETW collector's event decoder and its
pipeline wiring (alert selection + MITRE mapping). The logman/ETL half is
guest-side and validated live; the decoder is pure Python.

Run directly:

    .venv/Scripts/python.exe tests/test_wmi_etw.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "agent" / "windows"))

from orchestrator import heuristics  # noqa: E402
from orchestrator.mitre_mapping import enrich_alert  # noqa: E402
from wmi_collector import WMI_EVENT_TYPES, _decode_wmi_event  # noqa: E402


def decode(event_id, **fields):
    ev = {"EventHeader": {"TimeStamp": 133000000000000000, "ProcessId": 1234}}
    ev.update(fields)
    return _decode_wmi_event(event_id, ev)


def main() -> None:
    # 1. Permanent consumer (5861) decodes with the persistence fields.
    e = decode(5861, Namespace="root\\subscription", ESS="SELECT * FROM __InstanceModificationEvent",
               Consumer='ActiveScriptEventConsumer Name="Evil"')
    assert e["event_type"] == "WmiPermanentConsumer"
    assert e["source"] == "wmi_etw"
    assert e["data"]["ProcessId"] == 1234
    assert e["data"]["Consumer"] == 'ActiveScriptEventConsumer Name="Evil"'
    assert e["timestamp"]
    print("PASS 5861 permanent consumer decodes")

    # 2. Temporary consumer (5860).
    e = decode(5860, Namespace="root\\cimv2", Consumer="NTEventLogEventConsumer:Watcher")
    assert e["event_type"] == "WmiTemporaryConsumer"
    print("PASS 5860 temporary consumer decodes")

    # 3. Operation/query-failure kept but typed separately; unknown IDs skipped.
    assert decode(5857, Operation="Start IWbemServices::ExecQuery")["event_type"] == "WmiOperation"
    assert decode(5858, ResultCode="0x80041003")["event_type"] == "WmiQueryFailure"
    assert decode(5999) is None
    print("PASS 5857/5858 typed, unknown IDs skipped")

    # 4. Consumer registrations are unconditionally alert-worthy...
    assert "WmiPermanentConsumer" in heuristics.UNCONDITIONAL_ALERT_TYPES
    assert "WmiTemporaryConsumer" in heuristics.UNCONDITIONAL_ALERT_TYPES
    selected = heuristics.select_alert_events([decode(5861, Consumer="x"), decode(5857, Operation="y")])
    assert [e["event_type"] for e in selected] == ["WmiPermanentConsumer"]
    print("PASS consumer registration alerts, operations don't")

    # 5. MITRE T1546.003 mapping on both consumer types.
    for et in ("WmiTemporaryConsumer", "WmiPermanentConsumer"):
        a = enrich_alert({"event_type": et, "data": {}})
        assert a["mitre"]["primary"]["technique_id"] == "T1546.003", a["mitre"]
    print("PASS T1546.003 mapped")

    print("ALL WMI ETW TESTS PASSED")


if __name__ == "__main__":
    main()
