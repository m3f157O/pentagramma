"""Standalone assert-based test for orchestrator/capa_analysis.py's result
parsing + high-signal classification + verdict scoring.

Uses a hand-built minimal capa result document (the capa 9.x JSON schema) so it
runs without flare-capa or the vendored rules installed. Same plain-script
convention as tests/test_verdict.py. Run directly:

    .venv/Scripts/python.exe tests/test_capa_analysis.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import capa_analysis, detectors  # noqa: E402
from orchestrator.verdict import compute_verdict  # noqa: E402


def _rule(name, namespace=None, attack=None, mbc=None, lib=False, subscope=False, matches=1):
    src = f"rule:\r\n  meta:\r\n    name: {name}\r\n"
    if namespace:
        src += f"    namespace: {namespace}\r\n"
    return {
        "meta": {
            "name": name,
            "attack": [{"id": a, "tactic": "X", "technique": "Y"} for a in (attack or [])],
            "mbc": [{"id": m} for m in (mbc or [])],
            "lib": lib,
            "is_subscope_rule": subscope,
            "description": f"{name} desc",
        },
        "source": src,
        "matches": [None] * matches,
    }


CAPA_DOC = {
    "meta": {"version": "9.4.0", "analysis": {"format": "pe", "arch": "amd64", "os": "windows"}},
    "rules": {
        # high-signal by ATT&CK (T1055 = injection)
        "inject APC": _rule("inject APC", "host-interaction/process/inject", attack=["T1055.004"], matches=3),
        # high-signal by name regex (no attack tag)
        "reference anti-VM strings": _rule("reference anti-VM strings", "anti-analysis/anti-vm"),
        # informational (common discovery technique, not in HIGH_SIGNAL_ATTACK)
        "get hostname": _rule("get hostname", "host-interaction/os/hostname", attack=["T1082"]),
        # library code -- should still be listed but flagged lib
        "contain loop": _rule("contain loop", lib=True),
        # subscope -- must be excluded entirely
        "internal building block": _rule("internal building block", subscope=True),
    },
}


def test_summary_and_high_signal() -> None:
    s = capa_analysis.summarize_capa_json(CAPA_DOC)
    assert s["available"] and s["capa_version"] == "9.4.0" and s["format"] == "pe", s
    # 5 rules minus the 1 subscope rule
    assert s["capability_count"] == 4, s["capability_count"]
    assert s["high_signal_count"] == 2, s["high_signal_count"]
    names_hs = {c["name"] for c in s["capabilities"] if c["high_signal"]}
    assert names_hs == {"inject APC", "reference anti-VM strings"}, names_hs
    # subscope excluded; lib rule present but flagged
    all_names = {c["name"] for c in s["capabilities"]}
    assert "internal building block" not in all_names, all_names
    assert any(c["name"] == "contain loop" and c["lib"] for c in s["capabilities"])
    # attack aggregation + namespace recovery from source
    assert "T1055.004" in s["attack"] and "T1082" in s["attack"], s["attack"]
    inject = next(c for c in s["capabilities"] if c["name"] == "inject APC")
    assert inject["namespace"] == "host-interaction/process/inject", inject
    # high-signal sorts to the front
    assert s["capabilities"][0]["high_signal"], s["capabilities"][0]
    print("PASS: capa summary parses; high-signal via ATT&CK + name; subscope excluded; namespace recovered")


def test_scoring() -> None:
    s = capa_analysis.summarize_capa_json(CAPA_DOC)
    reasons = detectors.classify_static({"capa": s})
    capa_reasons = [r for r in reasons if "capa" in r["label"]]
    assert len(capa_reasons) == 1, capa_reasons  # once-only, not per-capability
    assert capa_reasons[0]["weight"] == detectors.STATIC_CAPA_SIGNAL_WEIGHT, capa_reasons
    v = compute_verdict([], {"capa": s})
    assert v["score"] == detectors.STATIC_CAPA_SIGNAL_WEIGHT, v
    print("PASS: high-signal capa contributes a single verdict signal")


def test_unavailable_is_safe() -> None:
    for bad in ({"available": False, "reason": "not_pe"}, {}, None):
        assert capa_analysis.high_signal_capabilities(bad) == []
        assert capa_analysis.attack_ids(bad) == []
        assert detectors.classify_static({"capa": bad or {}}) == []
    print("PASS: missing/failed capa result contributes nothing and never raises")


def main() -> None:
    test_summary_and_high_signal()
    test_scoring()
    test_unavailable_is_safe()
    print("\nAll capa-analysis tests passed.")


if __name__ == "__main__":
    main()
