"""Guardian A4 stability gate: N alternating real VM runs with the driver active.

Cycles benign_control.bat / InjectionHarness.exe / test-tamper.ps1 through the
live orchestrator queue and checks, per run:
  - job completes cleanly (no executor error -- e.g. the historical flaky
    "Access is denied" at execute_sample would surface here)
  - benign: verdict stays in the golden-image baseline (clean..suspicious, <= 40)
  - harness: verdict malicious (>= 80)  [9/9 technique assertions are covered
    separately by scripts/run_injection_harness.ps1 / /api/harness/run]
  - tamper: taskkill denied, sysmon key write denied, Sysmon Running at end

Usage:
    .venv/Scripts/python.exe scripts/guardian_stability_gate.py [--runs 20]
"""

import argparse
import sys
import time
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLES = [
    ("benign", PROJECT_ROOT / "samples" / "detection_tests" / "benign_control.bat"),
    ("harness", PROJECT_ROOT / "samples" / "InjectionHarness" / "InjectionHarness" / "bin" / "Release" / "net8.0" / "win-x64" / "publish" / "InjectionHarness.exe"),
    ("tamper", PROJECT_ROOT / "tests" / "local" / "test-tamper.ps1"),
]

SUBMIT_TIMEOUT = 180
POLL_TIMEOUT = 30
POLL_RETRIES = 5


def _get(url: str) -> dict:
    last = None
    for attempt in range(POLL_RETRIES):
        try:
            r = requests.get(url, timeout=POLL_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as exc:
            last = exc
            time.sleep(min(2 ** attempt, 10))
    raise last  # type: ignore[misc]


def submit(base_url: str, path: Path) -> dict:
    with open(path, "rb") as f:
        r = requests.post(f"{base_url}/api/jobs", files={"file": (path.name, f)},
                          timeout=SUBMIT_TIMEOUT)
    r.raise_for_status()
    return r.json()


def poll_job(base_url: str, job_id: str, max_wait: int) -> dict:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        job = _get(f"{base_url}/api/jobs/{job_id}")
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(10)
    raise TimeoutError(f"job {job_id} did not finish in {max_wait}s")


def check(kind: str, report: dict) -> list:
    problems = []
    verdict = report.get("verdict", {})
    level, score = verdict.get("level", "?"), verdict.get("score", -1)
    if kind == "benign":
        if level not in ("clean", "suspicious") or score > 40:
            problems.append(f"benign drifted from baseline: {level}/{score}")
    elif kind == "harness":
        if level != "malicious" or score < 80:
            problems.append(f"harness below baseline: {level}/{score}")
    elif kind == "tamper":
        import json as _json
        stdout = (report.get("execution_info") or {}).get("Stdout", "")
        try:
            res = _json.loads(stdout.strip().splitlines()[-1])
        except Exception:
            problems.append("tamper canary stdout JSON missing/unparseable")
        else:
            if res.get("taskkill_sysmon_exitcode") != 1:
                problems.append(f"taskkill not denied: {res.get('taskkill_sysmon_exitcode')}")
            if res.get("sysmon_key_write") != "denied":
                problems.append(f"sysmon key write not denied: {res.get('sysmon_key_write')}")
            if res.get("sysmon_status_end") != "Running":
                problems.append(f"sysmon not running at end: {res.get('sysmon_status_end')}")
    return problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://127.0.0.1:18000")
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--max-wait", type=int, default=900)
    args = ap.parse_args()

    for kind, path in SAMPLES:
        if not path.exists():
            print(f"missing sample for '{kind}': {path}")
            sys.exit(1)

    snap = _get(f"{args.base_url}/api/jobs")
    if snap["active_job_id"] or snap["queue_length"]:
        print(f"Refusing to start: VM busy (active={snap['active_job_id']}, queue={snap['queue_length']})")
        sys.exit(1)

    submissions = []
    for i in range(args.runs):
        kind, path = SAMPLES[i % len(SAMPLES)]
        job = submit(args.base_url, path)
        submissions.append((i + 1, kind, job["job_id"]))
        print(f"[{i + 1:>2}/{args.runs}] queued {kind:<8} job={job['job_id']}")

    failures = 0
    print(f"\n{'run':>4} {'kind':<8} {'verdict':<12} {'score':>5}  result")
    print("-" * 60)
    for run_no, kind, job_id in submissions:
        job = poll_job(args.base_url, job_id, args.max_wait)
        problems = []
        level, score = "N/A", "N/A"
        if job["status"] != "completed":
            problems.append(f"job {job['status']}: {job.get('error', '')[:120]}")
        else:
            report = _get(f"{args.base_url}/api/reports/{job['analysis_id']}")
            v = report.get("verdict", {})
            level, score = v.get("level", "?"), v.get("score", "?")
            problems = check(kind, report)
        ok = not problems
        failures += 0 if ok else 1
        print(f"{run_no:>4} {kind:<8} {level:<12} {str(score):>5}  {'PASS' if ok else 'FAIL'}")
        for p in problems:
            print(f"      - {p}")

    print("-" * 60)
    if failures:
        print(f"STABILITY GATE FAILED: {failures}/{args.runs} runs had problems")
        sys.exit(1)
    print(f"STABILITY GATE PASSED: {args.runs}/{args.runs} clean runs")


if __name__ == "__main__":
    main()
