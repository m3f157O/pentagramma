"""Detonate a directory (or list) of samples through the live orchestrator.

A generic companion to scripts/bulk_verify_detection_tests.py: that one is
hard-wired to the detection_tests scenarios and asserts expected detections;
THIS one just submits arbitrary samples, waits for the queue to drain, and
prints the resulting verdict for each -- for growing the labeled corpus
(tests/corpus/labels.json) with new goodware / malware families whose reports
then live in reports/ forever.

Typical use -- grow the benign side of the corpus, then re-measure FPR:

    .venv/Scripts/python.exe scripts/detonate_corpus.py samples/goodware
    .venv/Scripts/python.exe scripts/detection_metrics.py
    .venv/Scripts/python.exe scripts/calibrate_verdict.py

Requires a running orchestrator (default http://127.0.0.1:18000) with an idle
queue -- it refuses to start if a job is already active/queued so this batch's
reports can't get mixed up with an in-flight analysis. The orchestrator saves
each completed report to reports/<analysis_id>.json itself; this script only
drives submission and prints a summary.

The samples here are NOT labeled by this script -- label them in
tests/corpus/labels.json (by filename, which matches every run of that sample).
"""

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# process_injection.exe is ~67MB; a KB-sized script uploads instantly but a
# large binary needs headroom -- mirror bulk_verify's generous submit timeout.
SUBMIT_TIMEOUT_SECONDS = 180
POLL_REQUEST_TIMEOUT_SECONDS = 30
POLL_REQUEST_RETRIES = 5

# File types the sandbox knows how to launch (orchestrator/sample_types.py).
SAMPLE_SUFFIXES = {".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".zip"}
# Never submit these even if present in the dir.
SKIP_NAMES = {"readme.md", "readme.txt"}


def collect_samples(paths: List[Path]) -> List[Path]:
    """Expand dirs to their runnable sample files; keep explicit files as-is."""
    out: List[Path] = []
    for p in paths:
        if p.is_dir():
            for f in sorted(p.iterdir()):
                if (
                    f.is_file()
                    and f.suffix.lower() in SAMPLE_SUFFIXES
                    and f.name.lower() not in SKIP_NAMES
                ):
                    out.append(f)
        elif p.is_file():
            out.append(p)
        else:
            print(f"warning: not found, skipping: {p}", file=sys.stderr)
    return out


def submit(base_url: str, path: Path, timeout_seconds: int) -> dict:
    with open(path, "rb") as f:
        resp = requests.post(
            f"{base_url}/api/jobs",
            files={"file": (path.name, f)},
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
    return _get_with_retries(f"{base_url}/api/reports/{analysis_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", type=Path, help="Sample files and/or directories of samples")
    parser.add_argument("--worklist", type=Path, default=None,
                        help="text file with one sample path per line (e.g. from verify_groundtruth.py)")
    parser.add_argument("--base-url", default="http://127.0.0.1:18000")
    parser.add_argument("--timeout", type=int, default=90, help="per-sample in-VM execution timeout (seconds)")
    parser.add_argument("--max-wait", type=int, default=900, help="max seconds to wait for a single job to finish")
    args = parser.parse_args()

    raw_paths = [p if p.is_absolute() else (PROJECT_ROOT / p) for p in args.paths]
    if args.worklist:
        wl = args.worklist if args.worklist.is_absolute() else PROJECT_ROOT / args.worklist
        for line in wl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw_paths.append(Path(line))
    samples = collect_samples(raw_paths)
    if not samples:
        print("No runnable samples found.", file=sys.stderr)
        sys.exit(1)

    try:
        snap = requests.get(f"{args.base_url}/api/jobs", timeout=15).json()
    except requests.exceptions.RequestException as exc:
        print(f"Cannot reach orchestrator at {args.base_url}: {exc}\n"
              "Start it first (./start.ps1) with Hyper-V access, then re-run.", file=sys.stderr)
        sys.exit(2)
    if snap.get("active_job_id") or snap.get("queue_length"):
        print(f"Refusing to start: VM is busy (active={snap.get('active_job_id')}, "
              f"queue_length={snap.get('queue_length')})")
        sys.exit(1)

    print(f"Submitting {len(samples)} sample(s) to the queue...")
    submissions = []
    for path in samples:
        job = submit(args.base_url, path, args.timeout)
        pos = f" position={job['queue_position']}" if job.get("queue_position") else ""
        print(f"  {path.name:<32} -> job {job['job_id']}  status={job['status']}{pos}")
        submissions.append((path, job))

    print("\nWaiting for the queue to drain (real VM analyses, one at a time)...\n")
    rows = []
    for path, job in submissions:
        started = time.time()
        try:
            finished = poll_job(args.base_url, job["job_id"], max_wait=args.max_wait)
        except TimeoutError as exc:
            print(f"  {path.name:<32} -> TIMEOUT ({exc})")
            rows.append((path.name, "timeout", None, None))
            continue
        elapsed = time.time() - started
        if finished["status"] != "completed":
            print(f"  {path.name:<32} -> {finished['status']} ({elapsed:.0f}s) error={finished.get('error')}")
            rows.append((path.name, finished["status"], None, finished.get("analysis_id")))
            continue
        report = get_report(args.base_url, finished["analysis_id"])
        v = report.get("verdict", {}) or {}
        print(f"  {path.name:<32} -> completed ({elapsed:.0f}s)  "
              f"verdict={v.get('level')}/{v.get('score')}  id={finished['analysis_id']}")
        rows.append((path.name, v.get("level"), v.get("score"), finished.get("analysis_id")))

    print(f"\n{'sample':<32} {'verdict':<12} {'score':>6}")
    print("-" * 54)
    for name, level, score, _ in rows:
        print(f"{name:<32} {str(level):<12} {str(score):>6}")
    print("-" * 54)
    print(f"{len(rows)} detonated. Reports saved to reports/ by the orchestrator; "
          "label them in tests/corpus/labels.json, then run detection_metrics.py.")


if __name__ == "__main__":
    main()
