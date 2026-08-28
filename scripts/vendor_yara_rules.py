"""Vendors a curated YARA ruleset into yara_rules/, the at-scale companion to
the project-owned custom rules in yara/ (mirrors the sigma_rules vs
sigma_rules_custom split, and scripts/vendor_sigma_rules.py's approach).

Not a live submodule -- a periodic, manually re-run vendoring pass. The source
can be either:
  - a single combined release file (e.g. YARA-Forge's `yara-forge-rules-core.yar`), or
  - a directory tree of .yar/.yara files (copied preserving structure).

Recommended source: a YARA-Forge release (https://github.com/YARAHQ/yara-forge/releases).
Prefer the **core** package first -- it's the most broadly-compatible tier and
least likely to trip the loader's per-file compile fallback. `extended`/`full`
add coverage at the cost of more rules that reference modules a stock
yara-python build doesn't ship (magic/cuckoo/androguard), which the loader will
skip and report rather than fail on.

After copying, this validates the result by compiling it through the SAME
hardened loader the orchestrator uses (orchestrator/static_analysis.py), so the
kept-rule count and any per-file compile errors reported here are exactly what
the sandbox will see at runtime.

Usage:
    # From a single combined release file:
    python scripts/vendor_yara_rules.py path/to/yara-forge-rules-core.yar yara_rules \
        --source-label yara-forge-core-v<release>
    # From a directory tree:
    python scripts/vendor_yara_rules.py path/to/rules_dir yara_rules --source-label <label>

Review the diff before committing.
"""

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.static_analysis import StaticAnalyzer  # noqa: E402

LICENSE_NOTE = """This directory contains YARA rules vendored from an external
source (e.g. YARA-Forge, https://github.com/YARAHQ/yara-forge).

These rules are NOT this project's own work and retain their original authors'
licenses and attribution. YARA-Forge aggregates rules under a range of licenses
(see its LICENSE / the per-rule `license` metadata). See .source_label for what
was vendored here.
"""


def _copy_source(source: Path, dest: Path) -> int:
    """Copy .yar/.yara files from source (a file or a dir tree) into dest,
    preserving relative structure for a dir. Returns the number of files copied."""
    copied = 0
    if source.is_file():
        shutil.copy2(source, dest / source.name)
        return 1
    for path in sorted(source.rglob("*.yar")) + sorted(source.rglob("*.yara")):
        if not path.is_file():
            continue
        rel = path.relative_to(source)
        dest_file = dest / rel
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest_file)
        copied += 1
    return copied


def vendor(source: Path, dest: Path, source_label: str) -> int:
    if not source.exists():
        print(f"error: source not found: {source}", file=sys.stderr)
        return 2

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    copied = _copy_source(source, dest)
    if copied == 0:
        print(f"error: no .yar/.yara files found under {source}", file=sys.stderr)
        return 2

    (dest / ".source_label").write_text(source_label + "\n", encoding="utf-8")
    (dest / "LICENSE").write_text(LICENSE_NOTE, encoding="utf-8")

    # Validate through the real loader: this is exactly what the sandbox will
    # compile at runtime, so the numbers here are authoritative.
    analyzer = StaticAnalyzer(yara_rules_dir=dest)
    kept = analyzer.yara_rule_count
    errors = analyzer.yara_load_errors

    print(f"vendored {copied} file(s) from '{source_label}' -> {dest}")
    print(f"compiled rules active: {kept}")
    if errors:
        print(f"compile issues: {len(errors)} (rules in these scopes were skipped):", file=sys.stderr)
        for err in errors[:20]:
            print(f"  - [{err.get('scope')}] {err.get('error')}", file=sys.stderr)
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more", file=sys.stderr)
        if kept == 0:
            print(
                "error: zero rules compiled. If you vendored a single combined file, one "
                "incompatible rule can take the whole file down -- try the 'core' tier, or "
                "vendor a per-file tree so the loader can isolate the bad rules.",
                file=sys.stderr,
            )
            return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", type=Path, help="A combined .yar release file OR a directory of .yar/.yara files")
    parser.add_argument("dest", type=Path, help="Destination vendored dir (e.g. yara_rules)")
    parser.add_argument("--source-label", required=True, help="Release tag / commit / description, recorded for reproducibility")
    args = parser.parse_args()
    sys.exit(vendor(args.source, args.dest, args.source_label))


if __name__ == "__main__":
    main()
