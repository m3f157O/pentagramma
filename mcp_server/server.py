"""MCP server for the Hyper-V malware sandbox.

Thin wrapper around the orchestrator's REST API (orchestrator/main.py, see
start.ps1). The orchestrator must already be running and reachable at
SANDBOX_ORCHESTRATOR_URL (default http://127.0.0.1:18000) for most tools to
work; run_injection_harness is the one exception, since it shells out to
scripts/run_injection_harness.ps1 directly.

Register with Claude Code, e.g.:
    claude mcp add hyperv-sandbox -- \
        "<repo>\\.venv\\Scripts\\python.exe" "<repo>\\mcp_server\\server.py"
"""

import asyncio
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestrator.harness_validation import validate_harness_alerts  # noqa: E402
from orchestrator.report_view import trim_report  # noqa: E402

ORCHESTRATOR_URL = os.environ.get("SANDBOX_ORCHESTRATOR_URL", "http://127.0.0.1:18000")
PROJECT_ROOT = Path(__file__).resolve().parent.parent

SHORT_TIMEOUT = 30.0
VM_OP_TIMEOUT = 180.0
# A full analysis run reverts+boots the VM, executes the sample, and collects
# telemetry — this can legitimately take several minutes.
ANALYZE_TIMEOUT = 900.0
HARNESS_TIMEOUT = 900.0

mcp = FastMCP("hyperv-sandbox")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

async def _request(method: str, path: str, timeout: float, **kwargs) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.request(method, f"{ORCHESTRATOR_URL}{path}", **kwargs)
        if resp.is_error:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise RuntimeError(f"{method} {path} failed ({resp.status_code}): {detail}")
        return resp.json()


async def _get(path: str, timeout: float = SHORT_TIMEOUT) -> Dict[str, Any]:
    return await _request("GET", path, timeout)


async def _post(path: str, timeout: float = SHORT_TIMEOUT, **kwargs) -> Dict[str, Any]:
    return await _request("POST", path, timeout, **kwargs)


# ---------------------------------------------------------------------------
# VM / health tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def sandbox_health() -> Dict[str, Any]:
    """Check whether the sandbox orchestrator API is up and reachable."""
    return await _get("/api/health")


@mcp.tool()
async def get_vm_status() -> Dict[str, Any]:
    """Get the analysis VM's current power state and IP address."""
    return await _get("/api/vm/status")


@mcp.tool()
async def ensure_clean_snapshot() -> Dict[str, Any]:
    """Create the clean VM snapshot if it does not exist yet (one-time setup)."""
    return await _post("/api/vm/snapshot", timeout=VM_OP_TIMEOUT)


@mcp.tool()
async def restore_clean_snapshot() -> Dict[str, Any]:
    """Revert the analysis VM to its clean snapshot without running a sample."""
    return await _post("/api/vm/restore", timeout=VM_OP_TIMEOUT)


# ---------------------------------------------------------------------------
# Analysis tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def submit_sample(
    sample_path: str,
    arguments: str = "",
    timeout_seconds: Optional[int] = None,
    include_raw_events: bool = False,
    max_events: int = 200,
    sample_type: Optional[str] = None,
    dll_entry_point: Optional[str] = None,
    archive_entry: Optional[str] = None,
    archive_password: Optional[str] = None,
) -> Dict[str, Any]:
    """Upload a local file and run it inside the sandbox VM.

    Reverts the VM to the clean snapshot, boots it, copies the sample in,
    executes it, collects Sysmon/network telemetry, stops the VM, and
    returns the analysis report. This can take several minutes. The sample
    is never executed on the host.

    Supports EXE, DLL, JS/VBS/PS1/BAT scripts, and ZIP archives -- see
    orchestrator/sample_types.py for how each is launched. For URLs, use
    submit_url instead.

    Args:
        sample_path: Absolute path to the sample file on the host filesystem.
        arguments: Command-line arguments to pass to the sample.
        timeout_seconds: In-VM execution timeout (default from config.yaml, max 600).
        include_raw_events: Include the raw telemetry event stream in the response.
        max_events: Cap on raw events returned when include_raw_events is true.
        sample_type: Override auto-detected type (exe/dll/js/vbs/ps1/bat/zip).
        dll_entry_point: DLL export to invoke via rundll32 when auto-detection
            is ambiguous (multiple exports, no DllRegisterServer).
        archive_entry: Which file to run from a multi-file ZIP.
        archive_password: ZIP password, if encrypted.
    """
    path = Path(sample_path)
    if not path.is_file():
        raise FileNotFoundError(f"Sample not found on host: {sample_path}")

    data: Dict[str, str] = {"arguments": arguments}
    if timeout_seconds is not None:
        data["timeout"] = str(timeout_seconds)
    for key, value in (
        ("sample_type", sample_type),
        ("dll_entry_point", dll_entry_point),
        ("archive_entry", archive_entry),
        ("archive_password", archive_password),
    ):
        if value is not None:
            data[key] = value

    async with httpx.AsyncClient(timeout=ANALYZE_TIMEOUT) as client:
        with path.open("rb") as fh:
            files = {"file": (path.name, fh, "application/octet-stream")}
            resp = await client.post(f"{ORCHESTRATOR_URL}/api/analyze", data=data, files=files)
        if resp.is_error:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise RuntimeError(f"POST /api/analyze failed ({resp.status_code}): {detail}")
        report = resp.json()

    return trim_report(report, include_raw_events, max_events)


@mcp.tool()
async def submit_url(
    url: str,
    url_mode: str = "browse",
    timeout_seconds: Optional[int] = None,
    include_raw_events: bool = False,
    max_events: int = 200,
) -> Dict[str, Any]:
    """Submit a URL (not a local file) and run it inside the sandbox VM.

    Reverts the VM to the clean snapshot, boots it, then either opens the
    URL in the guest's default browser ("browse" mode -- catches
    drive-by/exploit-kit/social-engineering page behavior) or downloads it
    via curl.exe ("fetch" mode -- the downloaded payload then shows up
    under the report's dropped_files, hashed and YARA-rescanned, since
    curl.exe is the launched process). Can take several minutes.

    Args:
        url: The URL to analyze. http/https only.
        url_mode: "browse" (default) or "fetch".
        timeout_seconds: In-VM execution timeout (default from config.yaml, max 600).
        include_raw_events: Include the raw telemetry event stream in the response.
        max_events: Cap on raw events returned when include_raw_events is true.
    """
    data: Dict[str, str] = {"url": url, "url_mode": url_mode}
    if timeout_seconds is not None:
        data["timeout"] = str(timeout_seconds)

    async with httpx.AsyncClient(timeout=ANALYZE_TIMEOUT) as client:
        resp = await client.post(f"{ORCHESTRATOR_URL}/api/analyze", data=data)
        if resp.is_error:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise RuntimeError(f"POST /api/analyze failed ({resp.status_code}): {detail}")
        report = resp.json()

    return trim_report(report, include_raw_events, max_events)


@mcp.tool()
async def get_report(
    analysis_id: str,
    include_raw_events: bool = False,
    max_events: int = 200,
) -> Dict[str, Any]:
    """Fetch a previously generated analysis report by ID.

    By default the raw event stream is omitted (only counts, alerts, MITRE
    coverage, and the process tree are returned) since reports can contain
    tens of thousands of raw events. Set include_raw_events=true for up to
    max_events raw events.
    """
    report = await _get(f"/api/reports/{analysis_id}")
    return trim_report(report, include_raw_events, max_events)


@mcp.tool()
async def list_reports() -> Dict[str, Any]:
    """List all analysis IDs that have a saved report."""
    return await _get("/api/reports")


# ---------------------------------------------------------------------------
# Injection-harness workflow (mirrors scripts/run_injection_harness.ps1 and
# scripts/harness_assertions.py) — the iterative detection-tuning loop
# described in PLAN.md.
# ---------------------------------------------------------------------------

@mcp.tool()
async def validate_injection_harness(analysis_id: str) -> Dict[str, Any]:
    """Check whether an InjectionHarness.exe run produced the expected Sysmon
    signals for each technique (hollowing, PE replacement, herpaderping,
    ghosting). Mirrors scripts/harness_assertions.py.
    """
    report = await _get(f"/api/reports/{analysis_id}")
    stdout = (report.get("execution_info") or {}).get("Stdout", "")
    alerts = report.get("alerts", [])
    result = validate_harness_alerts(stdout, alerts)
    result["analysis_id"] = analysis_id
    return result


@mcp.tool()
async def run_injection_harness(
    vm_name: Optional[str] = None,
    snapshot_name: Optional[str] = None,
    timeout_seconds: int = 120,
    previous_report_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Rebuild samples/InjectionHarness from source and run it in the sandbox.

    Wraps scripts/run_injection_harness.ps1 directly (bypasses the REST API,
    invokes SandboxExecutor in-process) — requires the .NET 8 SDK on the
    host and must run with the same elevation the orchestrator normally
    needs for Hyper-V access. Prefer submit_sample + validate_injection_harness
    if you already have a built InjectionHarness.exe and just want to rerun it.
    """
    script = PROJECT_ROOT / "scripts" / "run_injection_harness.ps1"
    args = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(script)]
    if vm_name:
        args += ["-VMName", vm_name]
    if snapshot_name:
        args += ["-SnapshotName", snapshot_name]
    args += ["-TimeoutSeconds", str(timeout_seconds)]
    if previous_report_id:
        prev_path = PROJECT_ROOT / "reports" / f"{previous_report_id}.json"
        args += ["-PreviousReport", str(prev_path)]

    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(PROJECT_ROOT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=HARNESS_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"run_injection_harness.ps1 timed out after {HARNESS_TIMEOUT:.0f}s")

    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")

    match = re.search(r"Analysis complete:\s*([0-9a-fA-F-]{36})", stdout)
    analysis_id = match.group(1) if match else None

    return {
        "exit_code": proc.returncode,
        "analysis_id": analysis_id,
        "stdout": stdout[-8000:],
        "stderr": stderr[-4000:] if proc.returncode != 0 else "",
    }


if __name__ == "__main__":
    mcp.run()
