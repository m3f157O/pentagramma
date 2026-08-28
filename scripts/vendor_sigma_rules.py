"""Vendors a curated subset of SigmaHQ/sigma's rules/windows/ tree into
sigma_rules/, matching the categories orchestrator/sigma_engine.py knows
how to evaluate against this project's own Sysmon-derived telemetry (see
CATEGORY_TO_EVENT_TYPES there for why each included category is viable).

Not a live git submodule -- a periodic, manually re-run vendoring/filtering
pass, since SigmaHQ's upstream evolves faster than this project's sparse
yara/-style static-file precedent assumed. Re-run this after a fresh
sparse-checkout of upstream to pick up new/updated rules; review the diff
before committing.

Usage:
    git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git <tmp>
    cd <tmp> && git config core.longpaths true && git sparse-checkout set rules/windows
    python scripts/vendor_sigma_rules.py <tmp>/rules/windows sigma_rules --source-commit <tmp's git rev-parse HEAD>
"""

import argparse
import shutil
import sys
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

# Some rules/windows/ top-level directories contain further category
# subdirectories (file/, registry/, powershell/, builtin/) -- only the
# usable ones are listed. create_stream_hash (confirmed zero real events in
# this project's captures) is deliberately excluded entirely. Also
# excluded, confirmed (not "pending"): file/file_access and file/file_rename
# -- agent/windows/sysmon_parser.py::_classify()'s EventID table has no
# corresponding Sysmon event type for either.
#
# builtin/security, builtin/system, builtin/windefend added after a
# live-VM check confirmed: Security and System logs are both readable with
# the current guest credentials (no permission blocker), and Windows
# Defender is actually active in the golden image (service Running,
# RealTimeProtectionEnabled=True) -- these are keyed to
# agent/windows/security_log_parser.py / system_log_parser.py /
# defender_log_parser.py, not Sysmon. The other ~26 builtin/ subdirectories
# (ldap, msexchange, iis-configuration, terminalservices, bits_client,
# appxdeployment_server, etc.) stay excluded -- each 1-9 rules targeting
# services this single-workstation, non-domain-joined VM doesn't run.
INCLUDED_RELATIVE_DIRS = [
    "process_creation",
    "network_connection",
    "dns_query",
    "image_load",
    "driver_load",
    "create_remote_thread",
    "raw_access_thread",
    "process_access",
    "process_tampering",
    "pipe_created",
    "wmi_event",
    "file/file_event",
    "file/file_delete",
    "file/file_change",
    "file/file_executable_detected",
    "registry/registry_add",
    "registry/registry_delete",
    "registry/registry_set",
    "registry/registry_event",
    "powershell/powershell_script",
    "sysmon",
    "builtin/security",
    "builtin/system",
    "builtin/windefend",
]

# Subdirectories nested under an otherwise-included tree that are still
# specific to Active-Directory/domain-controller roles this single-
# workstation, non-domain-joined VM doesn't run -- found while vendoring:
# builtin/system's rules are entirely one level deeper than the directory
# names in INCLUDED_RELATIVE_DIRS suggested (0 rules directly under
# builtin/system/, all under e.g. builtin/system/service_control_manager/),
# so the walk below is recursive and these are excluded explicitly rather
# than by directory-depth omission.
EXCLUDED_RELATIVE_DIRS = [
    "builtin/system/netlogon",
    "builtin/system/microsoft_windows_kerberos_key_distribution_center",
    "builtin/system/microsoft_windows_dhcp_server",
    "builtin/system/microsoft_windows_certification_authority",
]

ALLOWED_STATUS = {"stable", "test"}

LICENSE_NOTE = """This directory contains rules vendored from SigmaHQ/sigma
(https://github.com/SigmaHQ/sigma), licensed under the Detection Rule
License (DRL) 1.1: https://github.com/SigmaHQ/sigma/blob/master/LICENSE

Not this project's own license -- these rules retain their original
license and attribution. See .source_commit for the exact upstream commit
these were vendored from.
"""


def _iter_candidate_files(source_root: Path) -> Iterable[Path]:
    excluded_dirs = [source_root / rel for rel in EXCLUDED_RELATIVE_DIRS]
    for rel_dir in INCLUDED_RELATIVE_DIRS:
        directory = source_root / rel_dir
        if not directory.is_dir():
            print(f"warning: expected directory not found, skipping: {directory}", file=sys.stderr)
            continue
        # Recursive: some included trees (builtin/security, builtin/system)
        # have their actual rule files one or more levels deeper than the
        # directory name suggests -- a flat glob here previously missed
        # builtin/system entirely (0 direct children, 63 nested) and 17 of
        # builtin/security's 144 rules.
        for path in sorted(directory.glob("**/*.yml")):
            if any(excluded == path or excluded in path.parents for excluded in excluded_dirs):
                continue
            yield path


def vendor(source_root: Path, dest_root: Path, source_commit: str) -> None:
    if dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True)

    kept = 0
    skipped_status = 0
    skipped_correlation = 0
    skipped_parse_error = 0

    for src_file in _iter_candidate_files(source_root):
        text = src_file.read_text(encoding="utf-8")
        try:
            rule = SigmaRule.from_yaml(text)
        except SigmaError as exc:
            skipped_parse_error += 1
            print(f"skip (parse error) {src_file}: {exc}", file=sys.stderr)
            continue

        if isinstance(rule, SigmaCorrelationRule):
            skipped_correlation += 1
            continue

        status = rule.status.name.lower() if rule.status else "test"
        if status not in ALLOWED_STATUS:
            skipped_status += 1
            continue

        rel = src_file.relative_to(source_root)
        dest_file = dest_root / rel
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        dest_file.write_text(text, encoding="utf-8")
        kept += 1

    (dest_root / ".source_commit").write_text(source_commit + "\n", encoding="utf-8")
    (dest_root / "LICENSE").write_text(LICENSE_NOTE, encoding="utf-8")

    print(
        f"vendored {kept} rules from commit {source_commit[:12]} "
        f"(skipped: {skipped_status} status, {skipped_correlation} correlation, {skipped_parse_error} parse errors)"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root", type=Path, help="Path to upstream's rules/windows/ directory")
    parser.add_argument("dest_root", type=Path, help="Destination directory (e.g. sigma_rules/)")
    parser.add_argument("--source-commit", required=True, help="Upstream commit SHA, recorded for reproducibility")
    args = parser.parse_args()
    vendor(args.source_root, args.dest_root, args.source_commit)


if __name__ == "__main__":
    main()
