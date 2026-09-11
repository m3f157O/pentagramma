"""Build a curated Atomic Red Team sample set for sandbox recall audits.

Two phases:

  --scan    Parse out/atomic_redteam/atomics/*.yaml (fetched from the
            redcanaryco/atomic-red-team repo), filter to atomics that can
            run standalone in the isolated analysis VM, and print a review
            table (technique, name, executor, flags). Human reviews this.

  --build   Generate detonatable samples for the curated GUID list in
            samples/atomic_redteam/curated.txt into samples/atomic_redteam/
            plus a manifest.json (expected ATT&CK technique per sample).
            Detonate with: scripts/detonate_corpus.py samples/atomic_redteam
            then audit with scripts/verify_atomic_coverage.py.

Filters (the VM is isolated, admin, snapshot-restored):
  * executor must be command_prompt or powershell (no manual/gui/python)
  * no http(s) URLs in the command (dead-C2 starvation class -- tests that
    download would fail for infra reasons, not detection reasons)
  * no PathToAtomicsFolder references (payload files we did not fetch)
  * no dependency blocks (prereq files we would have to stage)
  * destructive-but-detectable atomics (log clearing, shadow deletion) are
    KEPT and flagged -- the VM is restored from SANDBOX_READY after every
    run, and these are exactly the behaviors we want detections for.

The samples are attack-shaped but benign: they belong in a RECALL audit
(manifest-driven), NOT in tests/corpus/labels.json (which would poison the
verdict ground truth -- these are not real malware).
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ATOMICS_DIR = PROJECT_ROOT / "out" / "atomic_redteam" / "atomics"
OUT_DIR = PROJECT_ROOT / "samples" / "atomic_redteam"
CURATED_FILE = OUT_DIR / "curated.txt"

EXECUTOR_SUFFIX = {"command_prompt": ".bat", "powershell": ".ps1"}
URL_RE = re.compile(r"https?://", re.IGNORECASE)
PATF_RE = re.compile(r"PathToAtomicsFolder", re.IGNORECASE)


def iter_atomic_tests():
    for path in sorted(ATOMICS_DIR.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except yaml.YAMLError as exc:
            print(f"warn: {path.name}: {exc}", file=sys.stderr)
            continue
        if not isinstance(doc, dict):
            continue
        technique = str(doc.get("attack_technique") or path.stem)
        for test in doc.get("atomic_tests") or []:
            yield technique, test


def substitute_args(command: str, test: dict) -> str:
    args = test.get("input_arguments") or {}
    for name, spec in args.items():
        default = str((spec or {}).get("default") or "")
        command = command.replace("#{" + name + "}", default)
    return command


def evaluate(technique: str, test: dict):
    """Return (command, suffix, flags) or (None, None, [reject reasons])."""
    flags = []
    if "windows" not in [str(p).lower() for p in (test.get("supported_platforms") or [])]:
        return None, None, ["not-windows"]
    executor = test.get("executor") or {}
    name = str(executor.get("name") or "").lower()
    if name not in EXECUTOR_SUFFIX:
        return None, None, [f"executor:{name or 'none'}"]
    command = executor.get("command")
    if not command:
        return None, None, ["no-command"]
    if test.get("dependencies"):
        return None, None, ["has-dependencies"]
    command = substitute_args(str(command), test)
    if URL_RE.search(command):
        return None, None, ["has-url"]
    if PATF_RE.search(command):
        return None, None, ["path-to-atomics"]
    if re.search(r"\bvssadmin\b|\bbcdedit\b|\bformat\s", command, re.IGNORECASE):
        flags.append("destructive")
    if re.search(r"wevtutil\s+(?:cl|clear-log)", command, re.IGNORECASE):
        flags.append("log-clear")
    if executor.get("elevation_required"):
        flags.append("elevated")
    return command, EXECUTOR_SUFFIX[name], flags


def cmd_scan() -> None:
    kept = rejected = 0
    for technique, test in iter_atomic_tests():
        command, suffix, flags = evaluate(technique, test)
        name = str(test.get("name") or "")[:58]
        guid = str(test.get("auto_generated_guid") or "")
        if command is None:
            rejected += 1
            continue
        kept += 1
        print(f"{technique:<11} {guid[:8]} {suffix:<5} {','.join(flags) or '-':<18} {name}")
    print(f"\n{kept} candidates / {rejected} rejected", file=sys.stderr)


def cmd_build() -> None:
    if not CURATED_FILE.exists():
        sys.exit(f"curated list missing: {CURATED_FILE} (add one GUID per line)")
    wanted = {ln.split("#")[0].strip() for ln in CURATED_FILE.read_text().splitlines()}
    wanted = {g for g in wanted if g}
    manifest = []
    seen = set()
    for technique, test in iter_atomic_tests():
        guid = str(test.get("auto_generated_guid") or "")
        prefix = next((w for w in wanted if guid.startswith(w)), None)
        if not prefix or guid in seen:
            continue
        command, suffix, flags = evaluate(technique, test)
        if command is None:
            print(f"warn: curated {guid} ({test.get('name')}) rejected by filters: {flags}",
                  file=sys.stderr)
            continue
        seen.add(guid)
        seen.add(prefix)
        slug = re.sub(r"[^a-z0-9]+", "_", str(test.get("name") or "atomic").lower()).strip("_")[:48]
        fname = f"art_{technique.replace('.', '_')}_{slug}{suffix}"
        header = (
            f"REM Atomic Red Team: {test.get('name')}\nREM {technique} | guid {guid}\n"
            if suffix == ".bat" else
            f"# Atomic Red Team: {test.get('name')}\n# {technique} | guid {guid}\n"
        )
        (OUT_DIR / fname).write_text(header + command + "\n", encoding="utf-8")
        manifest.append({
            "file": fname, "technique": technique, "name": test.get("name"),
            "guid": guid, "flags": flags,
            "expected_verdict_min": "suspicious",
        })
    missing = wanted - seen
    if missing:
        print(f"warn: {len(missing)} curated GUIDs not found: {sorted(missing)}", file=sys.stderr)
    (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"built {len(manifest)} samples in {OUT_DIR}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--build", action="store_true")
    args = ap.parse_args()
    if args.scan:
        cmd_scan()
    elif args.build:
        cmd_build()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
