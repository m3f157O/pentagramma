"""Standalone assert-based test for orchestrator/jobs.py's FIFO analysis
queue (submit_analysis_job / release() hand-off / eviction).

Same plain-script convention as tests/test_verdict.py. Run directly:

    .venv/Scripts/python.exe tests/test_jobs.py

orchestrator.jobs.SandboxExecutor is monkeypatched with a fake whose
run_analysis() blocks on a per-sample threading.Event the test controls --
SandboxExecutor's real __init__ does live Hyper-V/YARA/Sigma setup, far too
heavy for a unit test, and would need an actual VM to run at all.
"""

import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import jobs  # noqa: E402

order = []
order_lock = threading.Lock()
gates = {}


class FakeExecutor:
    def __init__(self, config):
        self.config = config

    def run_analysis(self, sample_filename=None, **kwargs):
        with order_lock:
            order.append(sample_filename)
        gate = gates.get(sample_filename)
        if gate is not None:
            gate.wait(timeout=5)
        return {"analysis_id": f"fake-{sample_filename}", "status": "completed"}


jobs.SandboxExecutor = FakeExecutor


def _wait_until(predicate, timeout=5.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _wait_job_finished(job_id, timeout=5.0):
    return _wait_until(lambda: jobs.get_job(job_id)["status"] in ("completed", "failed"), timeout=timeout)


def test_fifo_order_and_queue_position():
    assert jobs.get_active_job_id() is None, "must start idle"
    order.clear()
    names = ["a.exe", "b.exe", "c.exe"]
    for n in names:
        gates[n] = threading.Event()

    submitted = [jobs.submit_analysis_job(config=None, sample_path=None, sample_filename=n) for n in names]

    assert submitted[0]["status"] == "running", submitted[0]
    assert submitted[1]["status"] == "queued" and submitted[1]["queue_position"] == 1, submitted[1]
    assert submitted[2]["status"] == "queued" and submitted[2]["queue_position"] == 2, submitted[2]
    print("PASS: first submission starts immediately, rest queue with correct positions")

    # Release a, confirm b starts and c's position shifts from 2 -> 1.
    assert _wait_until(lambda: "a.exe" in order), "a.exe never started"
    gates["a.exe"].set()
    assert _wait_job_finished(submitted[0]["job_id"]), "a.exe never finished"
    assert _wait_until(lambda: "b.exe" in order), "b.exe never started after a.exe finished"
    assert jobs.get_job(submitted[2]["job_id"])["queue_position"] == 1, jobs.get_job(submitted[2]["job_id"])
    print("PASS: release() hands off to the next queued job and shifts queue_position down")

    gates["b.exe"].set()
    assert _wait_job_finished(submitted[1]["job_id"]), "b.exe never finished"
    assert _wait_until(lambda: "c.exe" in order), "c.exe never started after b.exe finished"
    gates["c.exe"].set()
    assert _wait_job_finished(submitted[2]["job_id"]), "c.exe never finished"

    assert order == names, order
    assert jobs.get_active_job_id() is None
    with jobs._lock:
        assert jobs._queue == [], jobs._queue
    print("PASS: FIFO order preserved end-to-end, slot and queue empty after drain")


def test_eviction_skips_pending():
    with jobs._lock:
        saved_jobs = jobs._jobs
        original_cap = jobs.MAX_RETAINED_JOBS
        jobs._jobs = OrderedDict()
        try:
            for i in range(10):
                jid = f"done-{i}"
                jobs._jobs[jid] = {"job_id": jid, "status": "completed", "created_at": f"2020-01-01T00:00:{i:02d}Z"}
            for i in range(5):
                jid = f"pending-{i}"
                jobs._jobs[jid] = {"job_id": jid, "status": "queued", "created_at": f"2020-01-01T00:01:{i:02d}Z"}

            jobs.MAX_RETAINED_JOBS = 8
            jobs._evict_finished_locked()

            remaining = set(jobs._jobs.keys())
            assert all(f"pending-{i}" in remaining for i in range(5)), remaining
            assert len(remaining) == 8, remaining
            assert sum(1 for k in remaining if k.startswith("done-")) == 3, remaining
        finally:
            jobs.MAX_RETAINED_JOBS = original_cap
            jobs._jobs = saved_jobs
    print("PASS: eviction only trims completed/failed jobs, never queued/running ones")


def test_concurrent_submit_all_complete():
    assert jobs.get_active_job_id() is None, "must start idle"
    order.clear()
    n = 12
    names = [f"stress-{i}.exe" for i in range(n)]
    for name in names:
        gates[name] = threading.Event()
        gates[name].set()  # let every job finish immediately once it starts -- no artificial blocking

    submitted = []
    submitted_lock = threading.Lock()

    def submit(name):
        job = jobs.submit_analysis_job(config=None, sample_path=None, sample_filename=name)
        with submitted_lock:
            submitted.append(job)

    threads = [threading.Thread(target=submit, args=(name,)) for name in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(submitted) == n, submitted

    def all_done():
        return all(jobs.get_job(j["job_id"])["status"] in ("completed", "failed") for j in submitted)

    assert _wait_until(all_done, timeout=10), [
        (j["job_id"], jobs.get_job(j["job_id"])["status"]) for j in submitted if not all_done()
    ]
    assert jobs.get_active_job_id() is None
    with jobs._lock:
        assert jobs._queue == [], jobs._queue
        assert jobs._queue_specs == {}, jobs._queue_specs
    print(f"PASS: {n} concurrently-submitted jobs all completed, no job left stuck in the queue")


def main() -> None:
    test_fifo_order_and_queue_position()
    test_eviction_skips_pending()
    test_concurrent_submit_all_complete()
    print("ALL JOB-QUEUE TESTS PASSED")


if __name__ == "__main__":
    main()
