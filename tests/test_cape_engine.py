"""Unit tests for the CAPE community-signature engine (orchestrator/cape_engine.py).

Synthetic apitrace events -> known community signatures; no VM, no CAPE
deployment. Run: .\\.venv\\Scripts\\python.exe tests\\test_cape_engine.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.cape_engine import CapeEngine, get_engine  # noqa: E402
from orchestrator.detectors import classify_alert  # noqa: E402
from orchestrator.pid_lineage import PidLineage  # noqa: E402

SIG_DIR = Path(__file__).resolve().parent.parent / "cape_signatures"
_ENGINE = None


def engine():
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = CapeEngine(SIG_DIR)
    return _ENGINE


def _api(api, pid, tid, arg0, category=None):
    from orchestrator.cape_engine import _CATEGORY_MAP
    inv = {v: k for k, v in _CATEGORY_MAP.items()}
    return {
        "source": "apitrace",
        "event_id": 9200,
        "event_type": "ApiCall",
        "timestamp": "2026-07-27T18:00:00+00:00",
        "data": {
            "Api": api,
            "Category": category or inv.get({
                "NtAllocateVirtualMemory": "memory", "NtWriteVirtualMemory": "memory",
                "CreateProcessW": "process", "NtCreateUserProcess": "process",
            }.get(api, "misc"), "misc"),
            "ProcessId": pid,
            "ThreadId": tid,
            "Arg0": arg0,
        },
    }


def _proc_create(pid, ppid, image, cmdline=""):
    return {
        "source": "sysmon",
        "event_id": 1,
        "event_type": "ProcessCreate",
        "timestamp": "2026-07-27T18:00:00+00:00",
        "data": {"ProcessId": str(pid), "ParentProcessId": str(ppid), "Image": image, "CommandLine": cmdline},
    }


def names(alerts):
    return sorted(a["data"]["Name"] for a in alerts)


# ---------------------------------------------------------------- loader

def test_loader_loads_corpus():
    eng = engine()
    assert eng.signature_count > 700, f"expected 700+ signatures, got {eng.signature_count}"
    # only network-dependent modules may fail
    assert len(eng.load_errors) <= 6, eng.load_errors
    kinds = {c.name for c in eng._signatures}
    assert "injection_rwx" in kinds and "injection_write_process" in kinds


# ------------------------------------------------------- evented matching

def test_injection_rwx_fires_on_rwx_alloc():
    events = [_api("NtAllocateVirtualMemory", 100, 1, "target_pid=100 base=0x10000 size=4096 protect=0x40 executable=1 cross_process=0")]
    assert "injection_rwx" in names(engine().evaluate(events))


def test_injection_rwx_silent_on_plain_rw():
    events = [_api("NtAllocateVirtualMemory", 100, 1, "target_pid=100 base=0x10000 size=4096 protect=0x4 executable=0 cross_process=0")]
    assert "injection_rwx" not in names(engine().evaluate(events))


def test_write_process_fires_cross_process():
    events = [_api("NtWriteVirtualMemory", 100, 1, "target_pid=200 base=0x10000 len=64")]
    assert "injection_write_process" in names(engine().evaluate(events))


def test_write_process_suppressed_for_own_child():
    """kernel32's CreateProcess parameter-block write into the just-created
    child is spawning noise, not injection (child_pid from the same stream)."""
    events = [
        _api("CreateProcessW", 100, 1, "child_pid=200 suspended=0 wow64=0"),
        _api("NtWriteVirtualMemory", 100, 1, "target_pid=200 base=0x10000 len=4544"),
    ]
    assert "injection_write_process" not in names(engine().evaluate(events))


# ------------------------------------------------------- lineage scoping

def _clears_logs_sig_present(alerts):
    return "clears_logs" in names(alerts)


def test_summary_sigs_scoped_to_sample_lineage():
    """Command-scanning summary sigs must not fire on environment commands
    (sandbox tooling) -- only on the sample's own process tree."""
    wevtutil = _proc_create(500, 400, "C:\\Windows\\System32\\wevtutil.exe", "wevtutil cl security")
    # one in-scope apitrace call so the results model has a process at all
    anchor = _api("NtAllocateVirtualMemory", 500, 1, "target_pid=500 base=0x10000 size=4096 protect=0x4 executable=0 cross_process=0")
    scoped_out = engine().evaluate([wevtutil, anchor], PidLineage(pids={999}, guids=set()))
    assert not _clears_logs_sig_present(scoped_out)

    scoped_in = engine().evaluate([wevtutil, anchor], PidLineage(pids={500}, guids=set()))
    # wevtutil cl IS the classic log-clearing command; the sig should see it
    # when the command belongs to the sample's own tree.
    assert _clears_logs_sig_present(scoped_in)


def test_no_lineage_includes_everything():
    wevtutil = _proc_create(500, 400, "C:\\Windows\\System32\\wevtutil.exe", "wevtutil cl security")
    anchor = _api("NtAllocateVirtualMemory", 500, 1, "target_pid=500 base=0x10000 size=4096 protect=0x4 executable=0 cross_process=0")
    assert _clears_logs_sig_present(engine().evaluate([wevtutil, anchor]))


# ------------------------------------------------------- alert shaping

def test_alert_carries_severity_and_score_gate():
    events = [_api("NtAllocateVirtualMemory", 100, 1, "target_pid=100 base=0x10000 size=4096 protect=0x40 executable=1 cross_process=0")]
    alert = next(a for a in engine().evaluate(events) if a["data"]["Name"] == "injection_rwx")
    assert alert["severity"] in ("low", "medium", "high")
    assert alert["data"]["SeverityStr"] == alert["severity"]
    assert alert["data"]["ProcessId"] == 100
    assert "cape_score" in alert


def test_verdict_gate_score_off():
    """cape_score=False must exclude the match from verdict classification."""
    events = [_api("NtAllocateVirtualMemory", 100, 1, "target_pid=100 base=0x10000 size=4096 protect=0x40 executable=1 cross_process=0")]
    alert = next(a for a in engine().evaluate(events) if a["data"]["Name"] == "injection_rwx")
    alert["cape_score"] = False
    assert classify_alert(alert) is None


def test_verdict_classification_score_on():
    events = [_api("NtAllocateVirtualMemory", 100, 1, "target_pid=100 base=0x10000 size=4096 protect=0x40 executable=1 cross_process=0")]
    alert = next(a for a in engine().evaluate(events) if a["data"]["Name"] == "injection_rwx")
    alert["cape_score"] = True
    cls = classify_alert(alert)
    assert cls is not None
    assert cls.family == "cape"
    assert cls.severity == "medium"  # injection_rwx is CAPE severity 2
    assert cls.group_key == "cape:injection_rwx"


# ------------------------------------------------------- config singleton

def test_get_engine_disabled_by_default_when_no_section():
    class _Cfg:
        cape_signatures = {}
    assert get_engine(_Cfg()) is None


def main():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
            passed += 1
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}")
            failed += 1
        except Exception as exc:
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
            failed += 1
    print("-" * 70)
    print(f"{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
    print("ALL CAPE-ENGINE TESTS PASSED")


if __name__ == "__main__":
    main()
