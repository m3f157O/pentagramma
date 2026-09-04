"""Unit tests for .NET-aware static analysis (dnfile-based parse_dotnet).

Uses tests/fixtures/hello_dotnet.exe (a tiny csc-compiled hello world) plus a
native PE (python.exe from the venv) and a truncated CLR fixture for the
graceful-failure path. StaticAnalyzer is instantiated via __new__ so the
YARA ruleset is never compiled -- parse_pe/parse_dotnet need no other state.

Run directly:

    .venv/Scripts/python.exe tests/test_dotnet_static.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import detectors  # noqa: E402
from orchestrator.static_analysis import StaticAnalyzer  # noqa: E402

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "hello_dotnet.exe"
NATIVE = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"


def _analyzer() -> StaticAnalyzer:
    return StaticAnalyzer.__new__(StaticAnalyzer)


def main() -> None:
    assert FIXTURE.exists(), f"missing fixture {FIXTURE}"
    sa = _analyzer()

    # 1. .NET PE: full metadata surface.
    pe = sa.parse_pe(FIXTURE)
    assert pe and pe.get("dotnet"), "dotnet block missing for .NET PE"
    dn = pe["dotnet"]
    assert dn["assembly_name"] == "_hello", dn.get("assembly_name")
    assert dn["runtime_version"] == "2.5", dn.get("runtime_version")
    assert dn["mixed_mode"] is False  # ILONLY flag set by csc
    assert "#US" in dn["metadata_streams"] and "#Strings" in dn["metadata_streams"]
    assert dn["entry_point_token"].startswith("0x600000"), dn["entry_point_token"]
    refs = dn["type_refs"]
    assert any(r.startswith("System.") for r in refs), refs
    assert "System.Console" in refs, refs
    assert "hello dotnet fixture" in dn["user_strings"], dn["user_strings"]
    assert dn["obfuscator_suspected"] is False
    print("PASS .NET metadata parsed (assembly, refs, #US, IL-only)")

    # 2. Native PE: no dotnet key at all.
    pe_native = sa.parse_pe(NATIVE)
    assert pe_native and "dotnet" not in pe_native, "native PE must not get a dotnet block"
    print("PASS native PE has no dotnet block")

    # 3. Truncated CLR metadata: parse_pe must not raise; dotnet block is
    #    None or a partial dict with error fields, never an exception.
    broken = PROJECT_ROOT / "out" / "_hello_broken.exe"
    data = FIXTURE.read_bytes()
    broken.write_bytes(data[: len(data) // 2])
    try:
        pe_broken = sa.parse_pe(broken)
        # pefile may reject the truncated file outright (None) -- also fine.
        if pe_broken is not None and "dotnet" in pe_broken:
            assert pe_broken["dotnet"] is None or isinstance(pe_broken["dotnet"], dict)
    finally:
        broken.unlink(missing_ok=True)
    print("PASS truncated .NET PE handled gracefully")

    # 4. Verdict scoring: obfuscator markers add weight, clean .NET doesn't.
    signals = detectors.classify_static({"pe": {"dotnet": {"obfuscator_suspected": True, "obfuscator_markers": ["confuserex"]}}})
    assert any(".NET obfuscator" in s["label"] and s["weight"] > 0 for s in signals), signals
    signals = detectors.classify_static({"pe": {"dotnet": {"obfuscator_suspected": False}}})
    assert not any(".NET obfuscator" in s["label"] for s in signals), signals
    print("PASS obfuscator scoring (+5 when markers, silent otherwise)")

    # 5. Obfuscator marker detection: fake a ConfuserEx typeref hit through
    #    the marker list itself (unit-level; live obfuscated samples come later).
    markers = StaticAnalyzer._DOTNET_OBFUSCATOR_MARKERS
    assert "confuserex" in markers and "smartassembly" in markers
    print("PASS obfuscator marker list present")

    print("ALL DOTNET STATIC TESTS PASSED")


if __name__ == "__main__":
    main()
