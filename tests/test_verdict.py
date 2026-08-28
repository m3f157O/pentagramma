"""Standalone assert-based test for orchestrator/verdict.py.

Same plain-script convention as tests/test_sigma_engine.py and
tests/test_pid_lineage.py. Run directly:

    .venv/Scripts/python.exe tests/test_verdict.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.verdict import compute_verdict  # noqa: E402


def main() -> None:
    v = compute_verdict([], None)
    assert v == {"score": 0, "level": "clean", "top_reasons": []}, v
    print("PASS: empty alerts -> clean, score 0")

    v = compute_verdict([{"event_id": 25, "in_sample_scope": False}], None)
    assert v["score"] == 0
    print("PASS: environment-scoped event_id=25 contributes nothing")

    v = compute_verdict([{"event_id": 25, "in_sample_scope": True}], None)
    assert v["score"] == 40 and v["level"] == "malicious", v
    print("PASS: single in-scope ProcessTampering -> malicious, score 40")

    v = compute_verdict(
        [{"event_type": "ProcessCreate", "in_sample_scope": True, "sigma": {"level": "critical", "id": "x", "title": "Test Critical"}}],
        None,
    )
    assert v["score"] == 25 and v["level"] == "suspicious", v
    print("PASS: single sigma critical -> suspicious, score 25")

    v = compute_verdict(
        [{"event_type": "DmpYaraMatch", "in_sample_scope": True, "data": {"Rule": "evil_rule"}}],
        None,
    )
    assert v["score"] == 20
    assert v["top_reasons"][0]["reason"] == "YARA match: evil_rule"
    print("PASS: dump YARA match -> suspicious, score 20, reason names the rule")

    # Microsoft Defender's own threat detection (EID 1116), surfaced by
    # heuristics.detect_defender_threats and scored via Defender's severity.
    v = compute_verdict(
        [{"event_type": "DefenderThreatDetected", "in_sample_scope": True,
          "data": {"Threat Name": "Trojan:Win32/Ceprolad.A", "Severity Name": "Severe"}}],
        None,
    )
    assert v["score"] == 25, v  # Severe -> critical -> 25
    assert v["top_reasons"][0]["reason"] == "Microsoft Defender detected Trojan:Win32/Ceprolad.A", v
    print("PASS: Defender 'Severe' threat detection -> critical weight 25, names the threat")

    # Missing/unknown severity floors at 'high' -- an AV catch is never a throwaway signal.
    v = compute_verdict(
        [{"event_type": "DefenderThreatDetected", "in_sample_scope": True,
          "data": {"Threat Name": "Unknown/Thing"}}],
        None,
    )
    assert v["score"] == 15, v  # floored to high
    print("PASS: Defender detection with no severity floors at high weight 15")

    v = compute_verdict([{"event_type": "ImageLoad", "in_sample_scope": True}], None)
    assert v["score"] == 4 and v["level"] == "clean", v
    print("PASS: plain heuristic alert -> clean, score 4")

    v = compute_verdict(
        [{"event_type": "RegistryValueSet", "in_sample_scope": True, "priority": "high", "priority_reason": "Run key persistence"}],
        None,
    )
    assert v["score"] == 12
    assert v["top_reasons"][0]["reason"] == "Run key persistence"
    print("PASS: heuristic high-priority alert uses priority_reason as the label")

    # Repeated identical finding (same rule id, 10x) must not sum -- only
    # the single highest-weighted instance of a distinct finding counts.
    dup_alerts = [
        {"event_type": "ProcessCreate", "in_sample_scope": True, "sigma": {"level": "high", "id": "dup-rule", "title": "Dup"}}
        for _ in range(10)
    ]
    v = compute_verdict(dup_alerts, None)
    assert v["score"] == 15, v["score"]
    print("PASS: repeated identical finding (same rule id) does not inflate score by volume")

    # Diverse findings DO add up, capped at the alert-contribution ceiling.
    diverse_alerts = [
        {"event_id": 25, "in_sample_scope": True},  # 40
        {"event_type": "ProcessCreate", "in_sample_scope": True, "sigma": {"level": "critical", "id": "a", "title": "A"}},  # 25
        {"event_type": "DmpYaraMatch", "in_sample_scope": True, "data": {"Rule": "r1"}},  # 20
    ]
    v = compute_verdict(diverse_alerts, None)
    assert v["score"] == 70 and v["level"] == "malicious", v  # 40+25+20=85, capped at 70
    assert len(v["top_reasons"]) == 3
    print("PASS: diverse findings sum and cap at the alert-contribution ceiling (70)")

    # Static analysis contributes independently and can push past the cap.
    # status="NotSigned" (a real Get-AuthenticodeSignature result for a
    # checkable format, e.g. an EXE) matters here: classify_static only
    # scores the unsigned signal when the check actually ran and came back
    # negative, not just because signed=False (see its docstring -- a
    # status of "UnknownError"/missing means the format isn't Authenticode-
    # checkable at all, e.g. .bat/.vbs, and must NOT be scored as evidence).
    static = {"packed_suspected": True, "signature": {"status": "NotSigned", "signed": False}, "yara": [{"rule": "static_hit"}]}
    v = compute_verdict(diverse_alerts, static)
    assert v["score"] == 100, v["score"]  # 70 (capped) + 10 + 5 + 15 = 100, clipped at MAX_SCORE
    print("PASS: static analysis adds on top of the alert cap, clipped at 100")

    # A signature check that couldn't even run (e.g. a script format with no
    # Authenticode container) must not be scored as "unsigned" -- only a
    # completed check that came back negative is real evidence.
    unsigned_but_unchecked = {"signature": {"status": "UnknownError", "signed": False}}
    v = compute_verdict([], unsigned_but_unchecked)
    assert v["score"] == 0 and v["level"] == "clean", v
    print("PASS: signature status 'UnknownError' (not checkable, e.g. a script) is not scored as unsigned")

    v = compute_verdict([], {"packed_suspected": True})
    assert v["score"] == 10 and v["level"] == "suspicious", v
    print("PASS: static-only packed sample -> small score bump into suspicious")

    print("\nALL VERDICT TESTS PASSED")


if __name__ == "__main__":
    main()
