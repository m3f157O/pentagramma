"""Bulk-verify samples/detection_tests/ against real sandbox execution.

Submits every sample in samples/detection_tests/ through the live
orchestrator's job queue (POST /api/jobs -- see orchestrator/jobs.py), waits
for the whole queue to drain, then checks each job's REAL report against the
same expectations tests/test_detection_quality.py asserts offline against
hand-built telemetry -- reusing its SCENARIOS list as the single source of
truth so the two never drift apart. This is the "bulk verify, later" step
that harness was always meant to be paired with: confirms the synthetic
predictions actually hold against genuine VM execution, not just crafted
fixtures.

    .venv/Scripts/python.exe scripts/bulk_verify_detection_tests.py

Requires a running orchestrator (default http://127.0.0.1:18000) with an
idle queue -- refuses to start if a job is already active/queued, so this
batch's results can't get mixed up with someone else's in-flight job.
"""

import argparse
import sys
import time
from pathlib import Path
from typing import Optional

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.test_detection_quality import SCENARIOS  # noqa: E402

SAMPLES_DIR = PROJECT_ROOT / "samples" / "detection_tests"

# scenario name (tests/test_detection_quality.py) -> real script filename
SAMPLE_FILES = {
    "benign_control": "benign_control.bat",
    "lolbin_cradle": "lolbin_cradle.bat",
    "amsi_detection": "amsi_detection.ps1",
    "persistence_runkey": "persistence_runkey.ps1",
    "process_injection": "process_injection.exe",
    "mass_file_modification": "mass_file_modification.ps1",
    "credential_access_lsass": "credential_access_lsass.ps1",
    "defender_tampering": "defender_tampering.ps1",
    "lolbin_certutil_download": "lolbin_certutil_download.bat",
    "c2_named_pipe": "c2_named_pipe.ps1",
    "wmi_persistence": "wmi_persistence.ps1",
}


# process_injection.exe is a ~67MB self-contained single-file publish --
# 30s (fine for every other, KB-sized script/batch file in this corpus) was
# repeatedly too short for its upload to complete, crashing the whole run.
SUBMIT_TIMEOUT_SECONDS = 180
# Individual poll requests are trivial (a small JSON job record) but the
# orchestrator can be briefly slow to respond under load; a short per-request
# timeout plus a couple of silent retries survives that without needing a
# longer timeout on every single poll.
POLL_REQUEST_TIMEOUT_SECONDS = 30
POLL_REQUEST_RETRIES = 5


def submit(base_url: str, scenario_name: str, timeout_seconds: int) -> dict:
    filename = SAMPLE_FILES[scenario_name]
    path = SAMPLES_DIR / filename
    with open(path, "rb") as f:
        resp = requests.post(
            f"{base_url}/api/jobs",
            files={"file": (filename, f)},
            data={"timeout": str(timeout_seconds)},
            timeout=SUBMIT_TIMEOUT_SECONDS,
        )
    resp.raise_for_status()
    return resp.json()


def _get_with_retries(url: str) -> dict:
    last_exc: Optional[Exception] = None
    for attempt in range(POLL_REQUEST_RETRIES):
        try:
            resp = requests.get(url, timeout=POLL_REQUEST_TIMEOUT_SECONDS)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            time.sleep(min(2 ** attempt, 10))
    raise last_exc  # type: ignore[misc]


def poll_job(base_url: str, job_id: str, poll_interval: int = 5, max_wait: int = 900) -> dict:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        job = _get_with_retries(f"{base_url}/api/jobs/{job_id}")
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(poll_interval)
    raise TimeoutError(f"job {job_id} did not finish within {max_wait}s")


def get_report(base_url: str, analysis_id: str) -> dict:
    # Full reports run tens of MB (raw event telemetry included) -- same
    # retry treatment as poll_job, just with a longer per-attempt timeout.
    last_exc: Optional[Exception] = None
    for attempt in range(POLL_REQUEST_RETRIES):
        try:
            resp = requests.get(f"{base_url}/api/reports/{analysis_id}", timeout=SUBMIT_TIMEOUT_SECONDS)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            time.sleep(min(2 ** attempt, 10))
    raise last_exc  # type: ignore[misc]


# --- assertion helpers, mirroring tests/test_detection_quality.py but
# scoped to in_sample_scope alerts (real reports also carry environment
# noise the offline synthetic fixtures never had to filter) ---
def fired_sigma_ids(alerts):
    return {a["sigma"]["id"] for a in alerts if a.get("in_sample_scope") and a.get("sigma")}


def fired_event_types(alerts):
    return {a.get("event_type") for a in alerts if a.get("in_sample_scope") and not a.get("sigma")}


def has_priority_high(alerts):
    return any(a.get("in_sample_scope") and a.get("priority") == "high" for a in alerts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18000")
    parser.add_argument("--timeout", type=int, default=90, help="per-sample execution timeout (seconds)")
    parser.add_argument("--max-wait", type=int, default=900, help="max seconds to wait for a single job to finish")
    args = parser.parse_args()

    missing = [sc["name"] for sc in SCENARIOS if sc["name"] not in SAMPLE_FILES]
    assert not missing, f"no real sample mapped for scenario(s): {missing}"
    for name, filename in SAMPLE_FILES.items():
        assert (SAMPLES_DIR / filename).exists(), f"missing sample file: {SAMPLES_DIR / filename}"

    snap = requests.get(f"{args.base_url}/api/jobs", timeout=15).json()
    if snap["active_job_id"] or snap["queue_length"]:
        print(f"Refusing to start: VM is busy (active={snap['active_job_id']}, queue_length={snap['queue_length']})")
        sys.exit(1)

    print(f"Submitting {len(SCENARIOS)} samples to the queue...")
    submissions = []
    for sc in SCENARIOS:
        job = submit(args.base_url, sc["name"], args.timeout)
        pos = f" position={job['queue_position']}" if job.get("queue_position") else ""
        print(f"  {sc['name']:<26} -> job {job['job_id']}  status={job['status']}{pos}")
        submissions.append((sc, job))

    print("\nWaiting for the queue to drain (this runs real VM analyses, one at a time)...\n")
    results = []
    for sc, job in submissions:
        started = time.time()
        finished = poll_job(args.base_url, job["job_id"], max_wait=args.max_wait)
        print(f"  {sc['name']:<26} -> {finished['status']} ({time.time() - started:.0f}s)")
        results.append((sc, finished))

    print(f"\n{'scenario':<26} {'verdict':<12} {'score':>5}  {'in-scope':>8}  result")
    print("-" * 78)
    failures = []
    for sc, job in results:
        problems = []
        if job["status"] != "completed":
            problems.append(f"job status={job['status']}, error={job.get('error')}")
            level, score, in_scope_count = "N/A", "N/A", "N/A"
        else:
            report = get_report(args.base_url, job["analysis_id"])
            verdict = report["verdict"]
            alerts = report.get("alerts", [])
            scoped = [a for a in alerts if a.get("in_sample_scope")]
            level, score, in_scope_count = verdict["level"], verdict["score"], len(scoped)
            sids = fired_sigma_ids(alerts)
            ets = fired_event_types(alerts)

            if level not in sc["expect_level"]:
                problems.append(f"verdict {level} not in {sorted(sc['expect_level'])}")
            for rid in sc.get("expect_sigma", []):
                if rid not in sids:
                    problems.append(f"expected sigma rule {rid} did not fire")
            for et in sc.get("expect_event_types", set()):
                if et not in ets:
                    problems.append(f"expected event type {et} not alerted")
            if sc.get("expect_priority_high") and not has_priority_high(alerts):
                problems.append("expected a priority=high annotation")

        result = "PASS" if not problems else "FAIL"
        print(f"{sc['name']:<26} {str(level):<12} {str(score):>5}  {str(in_scope_count):>8}  {result}")
        for p in problems:
            print(f"    - {p}")
        if problems:
            failures.append(sc["name"])

    print("-" * 78)
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        sys.exit(1)
    print("ALL SCENARIOS VERIFIED AGAINST REAL VM EXECUTION")


if __name__ == "__main__":
    main()
