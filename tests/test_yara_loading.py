"""Standalone assert-based test for orchestrator/static_analysis.py's hardened
YARA loading (compile-error isolation, externals, multi-dir, scale-safe
catalog).

Same plain-script convention as tests/test_verdict.py. Run directly:

    .venv/Scripts/python.exe tests/test_yara_loading.py
"""

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import static_analysis  # noqa: E402
from orchestrator.static_analysis import (  # noqa: E402
    StaticAnalyzer,
    describe_yara_rules,
    get_yara_rule_source,
)


def _write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_broken_rule_isolation() -> None:
    """A single uncompilable rule file must NOT disable the whole ruleset --
    the good rules still compile and match, and the failure is recorded."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write(d, "good.yar", 'rule good_rule { strings: $a = "malware_marker" condition: $a }')
        _write(d, "broken.yar", "rule broken_rule { condition: not_valid_yara_syntax( }")

        sa = StaticAnalyzer(yara_rules_dir=d)
        assert sa.yara_rule_count == 1, sa.yara_rule_count
        assert sa._yara_rules is None and sa._yara_rules_list, "should have fallen back to per-file"
        assert any("broken" in e["scope"] for e in sa.yara_load_errors), sa.yara_load_errors

        probe = _write(d, "probe.bin", "xx malware_marker xx")
        hits = [m["rule"] for m in sa.match_yara(probe)]
        assert hits == ["good_rule"], hits
    print("PASS: one broken rule file is isolated; good rules survive and match")


def test_externals_declared() -> None:
    """Rules that gate on external vars (filename/extension/...) must compile
    and match -- proves _YARA_EXTERNALS is wired at both compile and match."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write(d, "fn.yar", 'rule fn_rule { condition: filename == "evil.exe" }')
        sa = StaticAnalyzer(yara_rules_dir=d)
        assert sa.yara_rule_count == 1 and not sa.yara_load_errors, sa.yara_load_errors

        evil = _write(d, "evil.exe", "anything")
        benign = _write(d, "benign.txt", "anything")
        assert [m["rule"] for m in sa.match_yara(evil)] == ["fn_rule"]
        assert sa.match_yara(benign) == []
    print("PASS: external-variable rule compiles and matches on filename")


def test_multi_dir_and_missing_dir() -> None:
    """Vendored + custom dirs compile together; a missing dir is tolerated."""
    with tempfile.TemporaryDirectory() as tmp:
        vendored = Path(tmp) / "vendored"
        custom = Path(tmp) / "custom"
        _write(vendored, "v.yar", 'rule vendored_rule { strings: $a = "AAA" condition: $a }')
        _write(custom, "c.yar", 'rule custom_rule { strings: $b = "BBB" condition: $b }')

        sa = StaticAnalyzer(yara_rules_dir=vendored, custom_rules_dirs=[custom])
        assert sa.yara_rule_count == 2, sa.yara_rule_count
        probe = _write(Path(tmp), "p.bin", "AAA BBB")
        assert sorted(m["rule"] for m in sa.match_yara(probe)) == ["custom_rule", "vendored_rule"]

        # Missing vendored dir -> only custom loads, no crash.
        sa2 = StaticAnalyzer(yara_rules_dir=Path(tmp) / "does_not_exist", custom_rules_dirs=[custom])
        assert sa2.yara_rule_count == 1, sa2.yara_rule_count
    print("PASS: vendored + custom dirs compile together; missing dir tolerated")


def test_catalog_scale_safe_source() -> None:
    """describe_yara_rules embeds source for small sets, drops it past the
    inline cap (fetched lazily via get_yara_rule_source)."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        # Small: source is inlined.
        _write(d, "one.yar", 'rule alpha { strings: $a = "x" condition: $a }')
        cat = describe_yara_rules([d])
        assert len(cat) == 1 and cat[0]["source"] is not None
        assert get_yara_rule_source("alpha", [d]) is not None
        assert get_yara_rule_source("nope", [d]) is None

        # Large: exceed the inline cap -> source dropped, lazy lookup still works.
        big = "\n".join(f'rule r{i} {{ strings: $a = "x{i}" condition: $a }}'
                        for i in range(static_analysis._YARA_CATALOG_INLINE_SOURCE_MAX + 5))
        _write(d, "many.yar", big)
        cat2 = describe_yara_rules([d])
        assert all(r["source"] is None for r in cat2), "source should be dropped past the cap"
        assert get_yara_rule_source("r3", [d]) is not None
    print("PASS: catalog inlines source when small, drops + lazy-fetches at scale")


def main() -> None:
    test_broken_rule_isolation()
    test_externals_declared()
    test_multi_dir_and_missing_dir()
    test_catalog_scale_safe_source()
    print("\nAll YARA-loading tests passed.")


if __name__ == "__main__":
    main()
