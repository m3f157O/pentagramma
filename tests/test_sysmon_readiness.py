"""Unit test for the Sysmon EID-1 readiness probe (agent/windows/
sysmon_manager.py wait_ready / _canary_seen). No live Sysmon log needed --
the parser is injected. Run directly:

    .venv/Scripts/python.exe tests/test_sysmon_readiness.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "agent" / "windows"))

from sysmon_manager import _canary_seen  # noqa: E402


class FakeParser:
    def __init__(self, events):
        self._events = events

    def query_events(self, since_iso=None):
        return self._events


class BadParser:
    def query_events(self, since_iso=None):
        raise RuntimeError("log unavailable")


MARKER = "sysmon-ready-1a2b3c4d"
MATCH = {"event_type": "ProcessCreate", "data": {"CommandLine": f"cmd.exe /c echo {MARKER}"}}
OTHER = {"event_type": "ProcessCreate", "data": {"CommandLine": "notepad.exe a.txt"}}
NON_PC = {"event_type": "RegistryValueSet", "data": {"CommandLine": MARKER}}


def test_canary_matched():
    assert _canary_seen(FakeParser([MATCH]), MARKER, attempts=1)


def test_canary_not_matched():
    assert not _canary_seen(FakeParser([OTHER]), MARKER, attempts=1)


def test_canary_requires_process_create():
    assert not _canary_seen(FakeParser([NON_PC]), MARKER, attempts=1)


def test_parser_failure_is_not_ready():
    assert not _canary_seen(BadParser(), MARKER, attempts=1)


def test_xpath_record_id_bound():
    # Clock-immune collection: record-id bound wins over time when present.
    from sysmon_parser import _build_xpath

    xp = _build_xpath(since_iso="2026-09-21T10:00:00Z", since_record_id=1344000)
    assert xp == "*[System[EventRecordID > 1344000]]", xp
    xp_time = _build_xpath(since_iso="2026-09-21T10:00:00Z")
    assert "TimeCreated" in xp_time and "EventRecordID" not in xp_time
    xp_default = _build_xpath()
    assert "timediff" in xp_default


def main() -> None:
    test_canary_matched()
    test_canary_not_matched()
    test_canary_requires_process_create()
    test_parser_failure_is_not_ready()
    test_xpath_record_id_bound()
    print("ALL SYSMON-READINESS TESTS PASSED")


if __name__ == "__main__":
    main()
