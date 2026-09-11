"""In-memory job tracker for asynchronous sandbox analysis runs.

Job records are NOT persisted — they exist purely to give a live-progress
view of a run in flight. Report .json files on disk (orchestrator/reporting.py)
remain the durable record; job records (and the pending queue below) are
lost on orchestrator restart.

There is exactly one Hyper-V VM behind this orchestrator
(config.hyperv.analysis_vm). HyperVManager/SandboxExecutor hold no locks of
their own, so this module also enforces single-flight: only one job (of any
type — analysis or an injection-harness run) may be active at a time.
/api/analyze (the original synchronous endpoint) claims the same slot so it
can't race against a dashboard-submitted job.

Analysis jobs (submit_analysis_job) additionally get a real, in-memory,
strict-FIFO queue: submitting while a job is active no longer fails —
the job is queued and release() automatically starts the next queued job
as soon as the slot frees up (see _queue/_queue_specs below). Harness runs
and the synchronous /api/analyze endpoint are NOT queued — they still
reject-fast ("busy") via try_acquire(), same as before.
"""

import logging
import re
import subprocess
import threading
import traceback
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from orchestrator.config import SandboxConfig
from orchestrator.executor import SandboxExecutor

logger = logging.getLogger(__name__)

MAX_RETAINED_JOBS = 200

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HARNESS_SCRIPT = PROJECT_ROOT / "scripts" / "run_injection_harness.ps1"
HARNESS_TIMEOUT_SECONDS = 900
GUARDIAN_DIR = PROJECT_ROOT / "guardian"
GUARDIAN_BUILD_SCRIPT = GUARDIAN_DIR / "build_guardian.ps1"
GUARDIAN_SIGN_SCRIPT = GUARDIAN_DIR / "make_test_cert.ps1"
GUARDIAN_SPIKE_SCRIPT = GUARDIAN_DIR / "guardian_spike.ps1"
GUARDIAN_A1_SCRIPT = GUARDIAN_DIR / "guardian_a1_test.ps1"
GUARDIAN_PROVISION_SCRIPT = GUARDIAN_DIR / "install_guardian.ps1"
GUARDIAN_SOAK_SCRIPT = GUARDIAN_DIR / "guardian_verifier_soak.ps1"

# POST /api/guardian/run actions -> (script, args, timeout_s). "build" is
# special-cased (build + sign, two scripts). Spike stages are the one-time
# A0 feasibility flow; load/test/cleanup are the repeatable A1a functional
# flow. All claim the single-flight slot: they drive the same one VM.
GUARDIAN_ACTIONS = {
    "build": None,  # special-cased
    "spike-inspect": (GUARDIAN_SPIKE_SCRIPT, ["-Stage", "inspect"], 300),
    "spike-enable": (GUARDIAN_SPIKE_SCRIPT, ["-Stage", "enable"], 600),
    "spike-load": (GUARDIAN_SPIKE_SCRIPT, ["-Stage", "load"], 300),
    "spike-diag": (GUARDIAN_SPIKE_SCRIPT, ["-Stage", "diag"], 300),
    "spike-cleanup": (GUARDIAN_SPIKE_SCRIPT, ["-Stage", "cleanup"], 300),
    "load": (GUARDIAN_A1_SCRIPT, ["-Stage", "load"], 300),
    "test": (GUARDIAN_A1_SCRIPT, ["-Stage", "test"], 600),
    "cleanup": (GUARDIAN_A1_SCRIPT, ["-Stage", "cleanup"], 300),
    "provision": (GUARDIAN_PROVISION_SCRIPT, [], 1800),
    "verifier-soak": (GUARDIAN_SOAK_SCRIPT, [], 1800),
}

_lock = threading.Lock()
_jobs: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
_active_job_id: Optional[str] = None

# FIFO queue for analysis jobs only (see module docstring). _queue holds
# pending job_ids in submission order; _queue_specs holds the kwargs
# _run_analysis_job needs to actually start each one. Both live only under
# _lock, alongside _active_job_id/_jobs. Intentionally unbounded — batch
# submissions are already gated by per-request disk I/O in
# SampleManager.store_sample, not by the queue itself.
_queue: List[str] = []
_queue_specs: Dict[str, Dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Single-flight slot
# ---------------------------------------------------------------------------

def try_acquire(job_id: str) -> bool:
    """Atomically claim the single-flight slot for job_id. False if busy.

    Used by submit_harness_job and /api/analyze, which reject-fast rather
    than queue. submit_analysis_job does NOT use this — it needs a single
    atomic check-and-enqueue (see its docstring for why splitting that
    across two lock acquisitions would race against release()).
    """
    global _active_job_id
    with _lock:
        if _active_job_id is not None:
            return False
        _active_job_id = job_id
        return True


def release() -> None:
    """Free the single-flight slot and, if any analysis jobs are queued,
    atomically hand it straight to the next one — the slot is never
    observably free to a racing caller in between, so try_acquire()'s
    "_active_job_id is None" check elsewhere stays correct unchanged."""
    global _active_job_id
    next_job_id: Optional[str] = None
    next_spec: Optional[Dict[str, Any]] = None
    with _lock:
        _active_job_id = None
        if _queue:
            next_job_id = _queue.pop(0)
            next_spec = _queue_specs.pop(next_job_id)
            _active_job_id = next_job_id

    if next_job_id is not None and next_spec is not None:
        try:
            thread = threading.Thread(
                target=_run_analysis_job,
                kwargs=dict(job_id=next_job_id, **next_spec),
                daemon=True,
            )
            thread.start()
        except Exception as exc:
            # A failed hand-off must not wedge the queue forever: drop the
            # slot and mark the job itself failed so the rest can proceed.
            update_job(next_job_id, status="failed", finished_at=_now_iso(), error=f"queue hand-off failed: {exc}")
            release()


def get_active_job_id() -> Optional[str]:
    with _lock:
        return _active_job_id


def get_queue_snapshot() -> "tuple[Optional[str], int]":
    """(active_job_id, queue_length) read atomically under one lock."""
    with _lock:
        return _active_job_id, len(_queue)


# ---------------------------------------------------------------------------
# Job record store
# ---------------------------------------------------------------------------

def _create_job_record(
    job_id: str,
    job_type: str,
    sample_filename: str,
    arguments: str,
    timeout_seconds: Optional[int],
    sample_type: str = "unknown",
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "job_id": job_id,
        "job_type": job_type,  # "analysis" | "harness"
        "status": "queued",  # queued | running | completed | failed
        "sample_filename": sample_filename,
        "sample_type": sample_type,
        "arguments": arguments,
        "timeout_seconds": timeout_seconds,
        "created_at": _now_iso(),
        "started_at": None,
        "finished_at": None,
        "current_step": None,
        "step_history": [],
        "analysis_id": None,
        # completed/failed/None — distinct from job status: a job can
        # status="completed" (run_analysis returned) while report_status
        # is "failed" (e.g. VM-stop error after an otherwise good run).
        "report_status": None,
        "error": None,
    }
    with _lock:
        _jobs[job_id] = record
        _evict_finished_locked()
    return dict(record)


def _evict_finished_locked() -> None:
    """Drop oldest completed/failed jobs to cap memory at MAX_RETAINED_JOBS.
    Must be called while holding _lock. Never evicts a queued/running job —
    plain FIFO-oldest eviction (the old behavior) could otherwise drop a job
    a large batch submission still has queued, orphaning its _queue entry.
    """
    if len(_jobs) <= MAX_RETAINED_JOBS:
        return
    for jid in list(_jobs.keys()):
        if len(_jobs) <= MAX_RETAINED_JOBS:
            break
        if _jobs[jid]["status"] in ("completed", "failed"):
            del _jobs[jid]


def update_job(job_id: str, **fields: Any) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.update(fields)


def append_step(job_id: str, name: str, **ctx: Any) -> None:
    entry = {"step": name, "at": _now_iso(), **ctx}
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job["step_history"].append(entry)
            job["current_step"] = name


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return None
        result = dict(job)
        result["queue_position"] = (_queue.index(job_id) + 1) if job_id in _queue else None
        return result


def list_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    with _lock:
        records = []
        for j in _jobs.values():
            d = dict(j)
            d["queue_position"] = (_queue.index(j["job_id"]) + 1) if j["job_id"] in _queue else None
            records.append(d)
    records.sort(key=lambda j: j["created_at"], reverse=True)
    return records[:limit]


# ---------------------------------------------------------------------------
# Analysis job (wraps SandboxExecutor.run_analysis)
# ---------------------------------------------------------------------------

def submit_analysis_job(
    config: SandboxConfig,
    sample_path: Optional[str],
    sample_filename: str,
    arguments: str = "",
    timeout_seconds: Optional[int] = None,
    sample_type: str = "unknown",
    launcher_path: Optional[str] = None,
    launcher_arguments: Optional[str] = None,
    destination_filename: Optional[str] = None,
    working_directory_in_vm: Optional[str] = None,
    url: Optional[str] = None,
    url_mode: Optional[str] = None,
    execution_error: Optional[str] = None,
    execution_error_detail: Optional[Any] = None,
    interactive: bool = False,
) -> Dict[str, Any]:
    """Run SandboxExecutor.run_analysis in a background thread -- immediately
    if the VM is idle, or queued (FIFO) behind whatever is already active.
    Always returns the initial job record; unlike a plain single-flight
    claim, this never fails with "busy" -- submission always succeeds, it
    just may not start right away. Check the returned record's "status"
    ("queued" vs "running") and "queue_position" to see where it landed.

    The claim-slot-or-enqueue decision is one atomic critical section (a
    single `with _lock:` block) rather than calling try_acquire() and then
    separately locking to append to the queue -- splitting it in two would
    race against release(): if the active job finishes and calls release()
    in the gap between those two lock acquisitions, release() would see an
    empty queue, clear _active_job_id, and this job would be enqueued right
    after with nothing left to ever hand off to it.

    The sample_type/launcher_*/url* kwargs are produced by
    orchestrator/sample_types.py (see main.py) and passed straight through
    to run_analysis -- see that method's docstring for what each does and
    why they're all safe to omit for a plain EXE submission.
    """
    global _active_job_id
    job_id = str(uuid.uuid4())
    job = _create_job_record(job_id, "analysis", sample_filename, arguments, timeout_seconds, sample_type=sample_type)

    run_kwargs: Dict[str, Any] = dict(
        config=config,
        sample_path=sample_path,
        sample_filename=sample_filename,
        arguments=arguments,
        timeout_seconds=timeout_seconds,
        sample_type=sample_type,
        launcher_path=launcher_path,
        launcher_arguments=launcher_arguments,
        destination_filename=destination_filename,
        working_directory_in_vm=working_directory_in_vm,
        url=url,
        url_mode=url_mode,
        execution_error=execution_error,
        execution_error_detail=execution_error_detail,
        interactive=interactive,
    )

    start_now = False
    with _lock:
        if _active_job_id is None:
            _active_job_id = job_id
            start_now = True
        else:
            _queue.append(job_id)
            _queue_specs[job_id] = run_kwargs

    if start_now:
        thread = threading.Thread(target=_run_analysis_job, kwargs=dict(job_id=job_id, **run_kwargs), daemon=True)
        thread.start()

    return get_job(job_id) or job


def _run_analysis_job(
    job_id: str,
    config: SandboxConfig,
    sample_path: Optional[str],
    arguments: str,
    timeout_seconds: Optional[int],
    sample_type: str = "unknown",
    sample_filename: Optional[str] = None,
    launcher_path: Optional[str] = None,
    launcher_arguments: Optional[str] = None,
    destination_filename: Optional[str] = None,
    working_directory_in_vm: Optional[str] = None,
    url: Optional[str] = None,
    url_mode: Optional[str] = None,
    execution_error: Optional[str] = None,
    execution_error_detail: Optional[Any] = None,
    interactive: bool = False,
) -> None:
    update_job(job_id, status="running", started_at=_now_iso())
    executor = SandboxExecutor(config)

    def on_step(name: str, **ctx: Any) -> None:
        append_step(job_id, name, **ctx)

    try:
        report = executor.run_analysis(
            sample_path=sample_path,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
            on_step=on_step,
            sample_type=sample_type,
            sample_filename=sample_filename,
            launcher_path=launcher_path,
            launcher_arguments=launcher_arguments,
            destination_filename=destination_filename,
            working_directory_in_vm=working_directory_in_vm,
            url=url,
            url_mode=url_mode,
            execution_error=execution_error,
            execution_error_detail=execution_error_detail,
            interactive=interactive,
        )
        update_job(
            job_id,
            status="completed",
            finished_at=_now_iso(),
            analysis_id=report.get("analysis_id"),
            report_status=report.get("status"),
        )
    except Exception as exc:
        # Keep `error` as the short message (API consumers expect it), but
        # also retain the full traceback -- str(exc) alone is not enough to
        # root-cause launch-path crashes (cf. emotet fc7a60ad NoneType bug).
        tb = traceback.format_exc()
        logger.error("analysis job %s failed:\n%s", job_id, tb)
        update_job(
            job_id,
            status="failed",
            finished_at=_now_iso(),
            error=str(exc),
            error_traceback=tb,
        )
    finally:
        release()


# ---------------------------------------------------------------------------
# Injection-harness job (wraps scripts/run_injection_harness.ps1)
# ---------------------------------------------------------------------------

def submit_harness_job(
    vm_name: Optional[str] = None,
    snapshot_name: Optional[str] = None,
    timeout_seconds: int = 120,
) -> Optional[Dict[str, Any]]:
    """Claim the single-flight slot and run
    scripts/run_injection_harness.ps1 (rebuild + execute InjectionHarness.exe)
    in a background thread.

    Progress is necessarily coarse (queued/running/completed/failed only):
    the script runs SandboxExecutor in a separate `python -c` subprocess, not
    in-process, so step-level on_step tracking from _run_analysis_job can't
    reach it.
    """
    job_id = str(uuid.uuid4())
    if not try_acquire(job_id):
        return None

    job = _create_job_record(job_id, "harness", "InjectionHarness.exe", "", timeout_seconds)

    thread = threading.Thread(
        target=_run_harness_job,
        args=(job_id, vm_name, snapshot_name, timeout_seconds),
        daemon=True,
    )
    thread.start()
    return job


def _run_harness_job(
    job_id: str,
    vm_name: Optional[str],
    snapshot_name: Optional[str],
    timeout_seconds: int,
) -> None:
    update_job(job_id, status="running", started_at=_now_iso())
    append_step(job_id, "run_injection_harness_ps1")

    args = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(HARNESS_SCRIPT)]
    if vm_name:
        args += ["-VMName", vm_name]
    if snapshot_name:
        args += ["-SnapshotName", snapshot_name]
    args += ["-TimeoutSeconds", str(timeout_seconds)]

    try:
        proc = subprocess.run(
            args,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=HARNESS_TIMEOUT_SECONDS,
        )
        stdout = proc.stdout or ""
        match = re.search(r"Analysis complete:\s*([0-9a-fA-F-]{36})", stdout)
        analysis_id = match.group(1) if match else None

        if proc.returncode != 0 or analysis_id is None:
            update_job(
                job_id,
                status="failed",
                finished_at=_now_iso(),
                error=((proc.stderr or stdout) or "run_injection_harness.ps1 failed")[-2000:],
            )
        else:
            update_job(
                job_id,
                status="completed",
                finished_at=_now_iso(),
                analysis_id=analysis_id,
                report_status="completed",
            )
    except subprocess.TimeoutExpired:
        update_job(
            job_id,
            status="failed",
            finished_at=_now_iso(),
            error=f"Timed out after {HARNESS_TIMEOUT_SECONDS}s",
        )
    except Exception as exc:
        update_job(job_id, status="failed", finished_at=_now_iso(), error=str(exc))
    finally:
        release()


# ---------------------------------------------------------------------------
# Guardian driver job (wraps guardian\*.ps1 stages)
# ---------------------------------------------------------------------------

def submit_guardian_job(action: str) -> Optional[Dict[str, Any]]:
    """Claim the single-flight slot and run a guardian driver stage
    (see GUARDIAN_ACTIONS) in a background thread.

    The scripts drive the analysis VM via PowerShell Direct, so this shares
    the single-flight slot with analysis/harness jobs. Progress is coarse
    (queued/running/completed/failed); the script's stdout tail is stored on
    the job record as "output". For action="test" the report_status field
    carries the check verdict: "all_pass" | "checks_failed".
    """
    if action not in GUARDIAN_ACTIONS:
        raise ValueError(f"unknown guardian action: {action}")
    job_id = str(uuid.uuid4())
    if not try_acquire(job_id):
        return None

    job = _create_job_record(job_id, "guardian", f"guardian:{action}", "", None)

    thread = threading.Thread(target=_run_guardian_job, args=(job_id, action), daemon=True)
    thread.start()
    return job


def _run_ps_stage(job_id: str, args: List[str], timeout: int) -> "tuple[int, str]":
    """Run one PowerShell stage; return (returncode, combined output tail)."""
    proc = subprocess.run(
        ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File"] + args,
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or ""))[-4000:]


def _run_guardian_job(job_id: str, action: str) -> None:
    update_job(job_id, status="running", started_at=_now_iso())
    try:
        if action == "build":
            append_step(job_id, "build_guardian_ps1")
            rc, out = _run_ps_stage(job_id, [str(GUARDIAN_BUILD_SCRIPT)], 300)
            if rc == 0:
                append_step(job_id, "make_test_cert_ps1")
                rc2, out2 = _run_ps_stage(job_id, [str(GUARDIAN_SIGN_SCRIPT), "-SignOnly"], 300)
                out = out + "\n" + out2
                rc = rc2
        else:
            script, extra_args, timeout = GUARDIAN_ACTIONS[action]
            append_step(job_id, f"{script.stem} {' '.join(extra_args)}")
            rc, out = _run_ps_stage(job_id, [str(script)] + extra_args, timeout)

        fields: Dict[str, Any] = {"finished_at": _now_iso(), "output": out}
        if rc != 0:
            fields["status"] = "failed"
            fields["error"] = out[-2000:] or f"guardian action '{action}' failed"
        else:
            fields["status"] = "completed"
            if action in ("test", "verifier-soak"):
                fields["report_status"] = "checks_failed" if "[FAIL]" in out else "all_pass"
        update_job(job_id, **fields)
    except subprocess.TimeoutExpired:
        update_job(job_id, status="failed", finished_at=_now_iso(), error=f"guardian action '{action}' timed out")
    except Exception as exc:
        update_job(job_id, status="failed", finished_at=_now_iso(), error=str(exc))
    finally:
        release()
