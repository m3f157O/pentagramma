"""capa (flare-capa) capability analysis.

Host-side static capability detection: capa names what a PE *can do* (mapped to
MITRE ATT&CK and MBC) by matching ~1000 rules against its disassembly --
complementing the signature-based YARA/Sigma layers with capability-level
intent ("inject code", "encrypt data using RC4", "check for VM").

capa runs as a subprocess (its own vivisect-backed disassembly) under a
timeout, so a slow or hostile sample can't wedge the analysis. Rules + FLIRT
signatures are vendored (scripts/vendor_capa_rules.py) because capa's wheel
ships neither. This module imports nothing from the rest of the detection layer
so it stays a leaf dependency (detectors.py reads its output dict directly).
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# High-signal ATT&CK techniques (technique-level; subtechnique stripped) that,
# detected statically by capa, meaningfully raise suspicion. capa is otherwise
# informational -- a capability is not inherently malicious -- so only these
# feed the small verdict signal in orchestrator/detectors.py. Deliberately
# excludes ultra-common discovery techniques (system info, file enumeration)
# that fire on benign software too.
HIGH_SIGNAL_ATTACK = {
    "T1055",  # process injection
    "T1620",  # reflective code loading
    "T1027",  # obfuscated / compressed files
    "T1140",  # deobfuscate / decode
    "T1486",  # data encrypted for impact (ransomware)
    "T1497",  # virtualization / sandbox evasion
    "T1543",  # create or modify system process (service)
    "T1547",  # boot or logon autostart execution (persistence)
    "T1105",  # ingress tool transfer
    "T1056",  # input capture (keylogging)
    "T1003",  # OS credential dumping
    "T1562",  # impair defenses
    "T1071",  # application layer protocol (C2)
}

# capa capability names whose wording is itself high-signal, independent of any
# ATT&CK tag (many precise capa rules carry no attack mapping).
HIGH_SIGNAL_NAME_RE = re.compile(
    r"inject|hollow|doppel|herpaderp|process ghost|anti-?vm|anti-?debug|anti-?sandbox|"
    r"packer|packed|shellcode|reflective|ransom|keylog|credential|encrypt data|"
    r"disable (?:windows )?defender|bypass uac|amsi|etw",
    re.IGNORECASE,
)

_NAMESPACE_RE = re.compile(r"^\s*namespace:\s*(.+?)\s*$", re.MULTILINE)


def _namespace_from_source(source: Optional[str]) -> Optional[str]:
    """capa 9.x result docs drop the rule namespace from meta but keep the raw
    rule `source`; recover it from there for display/grouping."""
    if not source:
        return None
    m = _NAMESPACE_RE.search(source)
    return m.group(1).strip() if m else None


def _is_high_signal(name: str, attack_ids: List[str]) -> bool:
    if name and HIGH_SIGNAL_NAME_RE.search(name):
        return True
    return any((aid or "").split(".")[0] in HIGH_SIGNAL_ATTACK for aid in attack_ids)


def summarize_capa_json(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce a capa JSON result document to the report-facing summary. Pure
    function (no I/O) so it's unit-testable against a captured fixture."""
    meta = doc.get("meta", {}) or {}
    analysis = meta.get("analysis", {}) or {}
    rules = doc.get("rules", {}) or {}

    capabilities: List[Dict[str, Any]] = []
    attack_ids: set = set()
    tactics: set = set()
    mbc_ids: set = set()

    for name, rule in rules.items():
        rmeta = rule.get("meta", {}) or {}
        # Subscope rules are internal building blocks, not standalone findings.
        if rmeta.get("is_subscope_rule"):
            continue
        attack = rmeta.get("attack") or []
        mbc = rmeta.get("mbc") or []
        a_ids = [a.get("id") for a in attack if a.get("id")]
        for a in attack:
            if a.get("id"):
                attack_ids.add(a["id"])
            if a.get("tactic"):
                tactics.add(a["tactic"])
        for m in mbc:
            if m.get("id"):
                mbc_ids.add(m["id"])
        capabilities.append(
            {
                "name": name,
                "namespace": _namespace_from_source(rule.get("source")),
                "attack": a_ids,
                "mbc": [m.get("id") for m in mbc if m.get("id")],
                "lib": bool(rmeta.get("lib")),
                "description": rmeta.get("description"),
                "match_count": len(rule.get("matches") or []),
                "high_signal": _is_high_signal(name, a_ids),
            }
        )

    # High-signal first, then most-matched -- the analyst's reading order.
    capabilities.sort(key=lambda c: (not c["high_signal"], -c["match_count"], c["name"]))

    return {
        "available": True,
        "capa_version": meta.get("version"),
        "format": analysis.get("format"),
        "arch": analysis.get("arch"),
        "os": analysis.get("os"),
        "capability_count": len(capabilities),
        "high_signal_count": sum(1 for c in capabilities if c["high_signal"]),
        "attack": sorted(attack_ids),
        "tactics": sorted(tactics),
        "mbc": sorted(mbc_ids),
        "capabilities": capabilities,
    }


def _resolve_capa_command(config: Dict[str, Any]) -> List[str]:
    """capa invocation: an explicit config override, else the console script
    next to the running interpreter, else `python -m capa.main`."""
    override = config.get("command")
    if override:
        return list(override) if isinstance(override, (list, tuple)) else [str(override)]
    exe = Path(sys.executable).with_name("capa.exe" if os.name == "nt" else "capa")
    if exe.exists():
        return [str(exe)]
    return [sys.executable, "-m", "capa.main"]


def analyze_file(file_path: str | Path, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run capa on a sample. Always returns a dict (never raises); on any
    problem returns {available: False, reason, ...} so the caller can record
    the gap without special-casing. capa is PE-only here (its default flavor);
    scripts/URLs/etc. are skipped cleanly."""
    path = Path(file_path)
    try:
        with path.open("rb") as fh:
            head = fh.read(2)
    except OSError as exc:
        return {"available": False, "reason": "unreadable", "error": str(exc)}
    if head != b"MZ":
        return {"available": False, "reason": "not_pe", "detail": "capa runs on PE samples; skipped."}

    rules_dir = config.get("rules_dir")
    if not rules_dir or not Path(rules_dir).is_dir():
        return {"available": False, "reason": "no_rules", "detail": f"capa rules dir not found: {rules_dir}"}

    cmd = _resolve_capa_command(config) + ["-j", "-r", str(rules_dir)]
    sigs_dir = config.get("sigs_dir")
    if sigs_dir and Path(sigs_dir).is_dir():
        cmd += ["-s", str(sigs_dir)]
    cmd += [str(path)]

    timeout = int(config.get("timeout_seconds", 180))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "timeout", "detail": f"capa exceeded {timeout}s"}
    except Exception as exc:
        return {"available": False, "reason": "error", "error": str(exc)}

    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return {"available": False, "reason": "capa_failed", "error": (proc.stderr or "no output")[-1000:]}
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"available": False, "reason": "bad_json", "error": str(exc)}
    return summarize_capa_json(doc)


def high_signal_capabilities(capa_result: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The high-signal capabilities from a capa result (for scoring/UI). Safe
    on a missing/failed result."""
    if not capa_result or not capa_result.get("available"):
        return []
    return [c for c in capa_result.get("capabilities", []) if c.get("high_signal")]


def attack_ids(capa_result: Optional[Dict[str, Any]]) -> List[str]:
    """ATT&CK technique IDs capa attributed to the sample (for MITRE coverage
    enrichment). Safe on a missing/failed result."""
    if not capa_result or not capa_result.get("available"):
        return []
    return list(capa_result.get("attack", []))
