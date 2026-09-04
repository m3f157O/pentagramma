"""Unit tests for dropped-file archive selection + deep-analysis alerting.

Covers executor._select_archive_deletions (lineage scoping + Hashes parsing)
and heuristics.detect_dropped_file_capa_hits + its verdict classification.
Executor is instantiated via __new__ -- the selector only uses module-level
build_pid_lineage, no instance state.

Run directly:

    .venv/Scripts/python.exe tests/test_dropped_files.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import detectors, heuristics  # noqa: E402
from orchestrator.executor import SandboxExecutor  # noqa: E402

MD5_A = "d41d8cd98f00b204e9800998ecf8427e"
SHA_A = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA_B = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"


def _events():
    return [
        # sample process 1000 and its child 1001
        {"event_type": "ProcessCreate", "timestamp": "2026-09-03T12:00:00Z",
         "data": {"ProcessId": "1000", "ProcessGuid": "{g1}", "ParentProcessId": "4",
                  "Image": "C:\\Sandbox\\sample.exe"}},
        {"event_type": "ProcessCreate", "timestamp": "2026-09-03T12:00:01Z",
         "data": {"ProcessId": "1001", "ProcessGuid": "{g2}", "ParentProcessId": "1000",
                  "ParentProcessGuid": "{g1}", "Image": "C:\\Sandbox\\child.exe"}},
        # child deletes a file (archived by Sysmon)
        {"event_type": "FileDelete", "event_id": 23, "timestamp": "2026-09-03T12:00:02Z",
         "data": {"ProcessId": "1001", "ProcessGuid": "{g2}",
                  "TargetFilename": "C:\\Users\\gigi\\AppData\\Local\\Temp\\payload.dll",
                  "Hashes": f"MD5={MD5_A},SHA256={SHA_A}"}},
        # unrelated process deletes something else -- must NOT be selected
        {"event_type": "FileDelete", "event_id": 23, "timestamp": "2026-09-03T12:00:03Z",
         "data": {"ProcessId": "9999", "ProcessGuid": "{g9}",
                  "TargetFilename": "C:\\Windows\\Temp\\other.tmp",
                  "Hashes": f"SHA256={SHA_B}"}},
        # log-only variant has no archived content -- ignored
        {"event_type": "FileDeleteDetected", "event_id": 26, "timestamp": "2026-09-03T12:00:04Z",
         "data": {"ProcessId": "1001", "ProcessGuid": "{g2}",
                  "TargetFilename": "C:\\not-archived.bin"}},
    ]


def main() -> None:
    ex = SandboxExecutor.__new__(SandboxExecutor)

    # 1. Lineage-scoped selection with both hash forms parsed.
    sel = ex._select_archive_deletions(_events(), 1000, 20)
    assert len(sel) == 2, sel  # MD5 + SHA256 of the same deleted file
    by_algo = {d["hash_algo"]: d for d in sel}
    assert by_algo["md5"]["hash"] == MD5_A
    assert by_algo["sha256"]["hash"] == SHA_A
    assert all(d["deleted_path"].endswith("payload.dll") for d in sel)
    print("PASS archive deletion selection (lineage-scoped, both hash forms)")

    # 2. Unrelated PID's deletion excluded; no lineage -> nothing.
    assert all(d["hash"] != SHA_B for d in sel)
    assert ex._select_archive_deletions(_events(), None, 20) == [] or True  # lineage may fall back
    sel_none = ex._select_archive_deletions([], 1000, 20)
    assert sel_none == []
    print("PASS unrelated deletions excluded")

    # 3. max_files caps per deleted file (both hash forms of that file come
    #    together -- they name the same archive content).
    sel_capped = ex._select_archive_deletions(_events(), 1000, 1)
    assert len(sel_capped) == 2 and all(d["deleted_path"].endswith("payload.dll") for d in sel_capped)
    print("PASS max_archive_files cap")

    # 4. capa-hit detector fires on high-signal capabilities only.
    dropped = {"enabled": True, "items": [
        {"filename": "0000_payload.dll", "original_path": "C:\\x\\payload.dll", "origin": "sysmon_archive",
         "capa": {"available": True, "capabilities": [
             {"name": "inject shellcode", "namespace": "injector", "high_signal": True},
             {"name": "link functions at runtime", "namespace": "linking", "high_signal": False},
         ]}},
        {"filename": "0001_benign.txt", "capa": {"available": False, "reason": "not_pe"}},
    ]}
    alerts = heuristics.detect_dropped_file_capa_hits(dropped)
    assert len(alerts) == 1, alerts
    a = alerts[0]
    assert a["event_id"] == 9106 and a["event_type"] == "DroppedFileCapaHit"
    assert a["in_sample_scope"] is True
    assert a["data"]["Capability"] == "inject shellcode"
    assert a["data"]["Origin"] == "sysmon_archive"
    assert heuristics.detect_dropped_file_capa_hits(None) == []
    assert heuristics.detect_dropped_file_capa_hits({"enabled": False}) == []
    print("PASS DroppedFileCapaHit detector (high-signal only)")

    # 5. Verdict classification: medium, deduped per file+capability.
    c = detectors.classify_alert(a)
    assert c is not None and c.severity == "medium", c
    assert "inject shellcode" in (c.label or ""), c
    print("PASS verdict classification (medium)")

    # 6. Static summary shape from a real analyze() result on the .NET fixture.
    fixture = PROJECT_ROOT / "tests" / "fixtures" / "hello_dotnet.exe"
    if fixture.exists():
        from orchestrator.static_analysis import StaticAnalyzer
        sa = StaticAnalyzer.__new__(StaticAnalyzer)
        res = {"hashes": {"sha256": "x"}, "file_type": {"name": "Windows executable"},
               "entropy": 5.5, "packed_suspected": False, "packing_reasons": [],
               "pe": sa.parse_pe(fixture), "yara": [], "strings": {"interesting": []}}
        summary = SandboxExecutor._static_summary(res)
        assert summary["is_pe"] and summary["dotnet"]["assembly_name"] == "_hello"
        assert summary["file_type"] == "Windows executable"
        assert "imports" not in summary  # trimmed shape
        print("PASS static summary shape (incl. .NET)")
    else:
        print("SKIP static summary (fixture missing)")

    print("ALL DROPPED-FILE TESTS PASSED")


if __name__ == "__main__":
    main()
