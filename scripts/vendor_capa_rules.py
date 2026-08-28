"""Vendors capa detection rules + FLIRT signatures into capa_rules/ and
capa_sigs/, the way scripts/vendor_sigma_rules.py / vendor_yara_rules.py vendor
their rulesets.

flare-capa's PyPI wheel does NOT bundle the detection rules or the library-code
signatures (only the rule *engine*), so both must be vendored here, version-
matched to the installed capa (`capa --version`), or capa either finds no rules
or errors on an incompatible rule format.

Get the sources (match the tag to the installed capa version, e.g. v9.4.0):
    git clone --depth 1 --branch vX.Y.Z https://github.com/mandiant/capa-rules <rules_src>
    git clone --depth 1 --branch vX.Y.Z --filter=blob:none --sparse https://github.com/mandiant/capa <capa_src>
    cd <capa_src> && git sparse-checkout set sigs

Usage:
    python scripts/vendor_capa_rules.py <rules_src> <capa_src>/sigs \
        --rules-dest capa_rules --sigs-dest capa_sigs --source-label v9.4.0

Review the diff before committing.
"""

import argparse
import shutil
import sys
from pathlib import Path

# capa-rules is Apache-2.0; the FLIRT sigs ship with capa (also Apache-2.0).
LICENSE_NOTE = """capa_rules/ contains detection rules vendored from
mandiant/capa-rules (https://github.com/mandiant/capa-rules), Apache-2.0.
capa_sigs/ contains FLIRT library signatures vendored from mandiant/capa
(https://github.com/mandiant/capa/tree/master/sigs), Apache-2.0.

Neither is this project's own work; both retain their original license and
attribution. See .source_label for the exact version vendored here, which must
match the installed flare-capa version.
"""

# Directory parts that are repo scaffolding, not capa rules -- a stray non-rule
# .yml (e.g. a GitHub workflow) in the rules dir breaks capa's rule loader.
_SKIP_PARTS = {".git", ".github", "tests", "doc", "scripts"}


def _is_rule_file(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    if any(part in _SKIP_PARTS or part.startswith(".") for part in rel_parts):
        return False
    return path.suffix == ".yml"


def vendor(rules_src: Path, sigs_src: Path, rules_dest: Path, sigs_dest: Path, source_label: str) -> int:
    if not rules_src.is_dir():
        print(f"error: rules source dir not found: {rules_src}", file=sys.stderr)
        return 2

    # Rules
    if rules_dest.exists():
        shutil.rmtree(rules_dest)
    rules_dest.mkdir(parents=True)
    rule_count = 0
    for path in sorted(rules_src.rglob("*.yml")):
        if not _is_rule_file(path, rules_src):
            continue
        dest_file = rules_dest / path.relative_to(rules_src)
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest_file)
        rule_count += 1

    # Signatures (optional but strongly recommended -- capa errors on a missing
    # default sig path, and without them library code is mis-attributed).
    sig_count = 0
    if sigs_src and sigs_src.is_dir():
        if sigs_dest.exists():
            shutil.rmtree(sigs_dest)
        sigs_dest.mkdir(parents=True)
        for path in sorted(sigs_src.iterdir()):
            if path.is_file() and path.suffix.lower() in (".sig", ".pat"):
                shutil.copy2(path, sigs_dest / path.name)
                sig_count += 1
    else:
        print(f"warning: sigs source dir not found ({sigs_src}); capa needs -s to point at FLIRT sigs", file=sys.stderr)

    (rules_dest / ".source_label").write_text(source_label + "\n", encoding="utf-8")
    (rules_dest / "LICENSE").write_text(LICENSE_NOTE, encoding="utf-8")

    print(f"vendored {rule_count} capa rules -> {rules_dest}")
    print(f"vendored {sig_count} FLIRT signature file(s) -> {sigs_dest}")
    if rule_count == 0:
        print("error: no rules vendored", file=sys.stderr)
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rules_src", type=Path, help="Path to a capa-rules checkout")
    parser.add_argument("sigs_src", type=Path, help="Path to capa's sigs/ dir (FLIRT signatures)")
    parser.add_argument("--rules-dest", type=Path, default=Path("capa_rules"))
    parser.add_argument("--sigs-dest", type=Path, default=Path("capa_sigs"))
    parser.add_argument("--source-label", required=True, help="Version tag (must match installed flare-capa), recorded for reproducibility")
    args = parser.parse_args()
    sys.exit(vendor(args.rules_src, args.sigs_src, args.rules_dest, args.sigs_dest, args.source_label))


if __name__ == "__main__":
    main()
