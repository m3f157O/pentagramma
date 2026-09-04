"""Unit tests for the Sigma literal-anchor prefilter: every soundness clause
of _harvest_anchors, plus equivalence of filtered vs unfiltered evaluation
on a mixed event set. Run directly:

    .venv/Scripts/python.exe tests/test_sigma_prefilter.py
"""

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.sigma_engine import CompiledRule, SigmaEngine, _harvest_anchors  # noqa: E402
from sigma.rule import SigmaRule  # noqa: E402

BASE = """title: T
id: 00000000-0000-0000-0000-000000000001
logsource:
  product: windows
  category: process_creation
detection:
{detection}
"""


def _rule(detection_yaml: str) -> SigmaRule:
    return SigmaRule.from_yaml(BASE.format(detection=detection_yaml))


def _anchors(detection_yaml: str):
    return _harvest_anchors(CompiledRule(_rule(detection_yaml), []).conditions)


def main() -> None:
    # 1. Single condition, pure AND of plain literals -> anchors.
    a = _anchors("""  sel:
      Image: 'C:\\\\Tools\\\\evil.exe'
      CommandLine: '--silent'
  condition: sel
""")
    assert sorted(a) == [("CommandLine", "--silent"), ("Image", "c:\\tools\\evil.exe")], a
    print("PASS pure-AND literals anchor")

    # 2. Multi-condition list (OR alternatives): intersection of per-condition
    #    anchors -- different literals -> empty (but NOT disqualified; the
    #    rule is simply unanchored).
    a = _anchors("""  sel1:
      Image: 'a.exe'
  sel2:
      Image: 'b.exe'
  condition: [sel1, sel2]
""")
    assert a == [], a
    print("PASS multi-condition intersection empty")

    # 3. OR of different selections -> intersection empty (unanchored).
    a = _anchors("""  sel1:
      Image: 'a.exe'
  sel2:
      CommandLine: 'x'
  condition: sel1 or sel2
""")
    assert a == [], a
    # 3b. OR where ALL branches share an anchor -> kept.
    a = _anchors("""  sel1:
      Image: 'C:\\Tools\\evil.exe'
      CommandLine: '--a'
  sel2:
      Image: 'C:\\Tools\\evil.exe'
      CommandLine: '--b'
  condition: sel1 or sel2
""")
    assert a == [("Image", "c:\\tools\\evil.exe")], a
    print("PASS OR: intersection semantics")

    # 4. NOT branch contributes nothing; the AND chain's other literals
    #    still anchor (the classic "selection and not filter" Sigma shape).
    a = _anchors("""  sel:
      Image: 'C:\\Tools\\evil.exe'
  filt:
      User: 'SYSTEM'
  condition: sel and not filt
""")
    assert a == [("Image", "c:\\tools\\evil.exe")], a
    print("PASS NOT excluded, AND-kept anchors survive")

    # 5. Wildcards anchor on their longest literal part; multi-value lists
    #    contribute nothing but don't disqualify the AND chain.
    a = _anchors("""  sel:
      Image: 'a.exe'
      CommandLine: '*--silent*'
      Hashes:
        - 'MD5=aaa'
        - 'MD5=bbb'
  condition: sel
""")
    assert a is not None and ("Image", "a.exe") in a  # 5 chars >= 4, plain literal
    assert ("CommandLine", "--silent") in a, a  # longest wildcard part
    print("PASS wildcard longest-part anchor + multi-value skipped")

    # 6. Keyword (fieldless) -> no anchors but harmless.
    a = _anchors("""  sel:
      - 'justakeyword'
  condition: sel
""")
    assert a == [], a
    print("PASS keyword-only yields no anchors")

    # 7. End-to-end equivalence: filtered vs unfiltered on a mixed event set.
    rules_yaml = {
        "plain.yml": BASE.format(detection="""  sel:
      Image|endswith: '\\\\evil.exe'
  condition: sel
"""),
        "anchored.yml": BASE.format(detection="""  sel:
      Image: 'C:\\\\Tools\\\\evil.exe'
      CommandLine: '--silent'
  condition: sel
"""),
        "ornode.yml": BASE.format(detection="""  sel1:
      Image: 'a.exe'
  sel2:
      Image: 'b.exe'
  condition: sel1 or sel2
"""),
    }
    with tempfile.TemporaryDirectory() as td:
        for name, text in rules_yaml.items():
            Path(td, name).write_text(text, encoding="utf-8")
        engine_on = SigmaEngine(Path(td), min_level="informational")
        engine_off = SigmaEngine(Path(td), min_level="informational")
        engine_off._prefilter_enabled = False

    events = [
        {"event_type": "ProcessCreate", "source": "sysmon", "event_id": 1,
         "data": {"Image": "C:\\Tools\\evil.exe", "CommandLine": "--silent"}},
        {"event_type": "ProcessCreate", "source": "sysmon", "event_id": 1,
         "data": {"Image": "C:\\Tools\\evil.exe", "CommandLine": "--loud"}},  # anchor miss on CommandLine
        {"event_type": "ProcessCreate", "source": "sysmon", "event_id": 1,
         "data": {"Image": "C:\\tools\\EVIL.exe", "CommandLine": "--silent"}},  # case-insensitive
        {"event_type": "ProcessCreate", "source": "sysmon", "event_id": 1,
         "data": {"Image": "b.exe"}},
        {"event_type": "ProcessCreate", "source": "sysmon", "event_id": 1,
         "data": {"Image": "C:\\legit.exe"}},
        {"event_type": "FileCreate", "source": "sysmon", "event_id": 11,
         "data": {"TargetFilename": "C:\\x"}},
    ]
    a_on = engine_on.evaluate(events)
    a_off = engine_off.evaluate(events)
    key = lambda a: (a.get("sigma", {}).get("id"), (a.get("data") or {}).get("Image"), (a.get("data") or {}).get("CommandLine"))
    assert sorted(map(key, a_on)) == sorted(map(key, a_off)), "prefilter changed results!"
    assert len(a_on) > 0, "expected at least some matches"
    # the anchored rule must have matched exactly the two exact-Image events
    anchored = [a for a in a_on if a.get("sigma", {}).get("title") == "T"
                and (a.get("data") or {}).get("CommandLine") == "--silent"]
    assert len(anchored) >= 2, anchored
    print(f"PASS filtered == unfiltered ({len(a_on)} alerts on mixed events)")

    # 8. Case-insensitive containment never skips a cased true match.
    a = _anchors("""  sel:
      Image: 'Evil.EXE'
  condition: sel
""")
    assert a == [("Image", "evil.exe")], a
    print("PASS anchors stored lowercased")

    print("ALL SIGMA PREFILTER TESTS PASSED")


if __name__ == "__main__":
    main()
