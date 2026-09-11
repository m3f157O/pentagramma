"""FastAPI REST API for the Hyper-V malware sandbox orchestrator."""

import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.types import Scope

from orchestrator import behavioral_signatures, cape_engine as cape_engine_mod, console, harness_validation, heuristics, jobs, local_trace, pcap_view, report_view, sample_types, static_analysis
from orchestrator.config import get_config
from orchestrator.executor import SandboxExecutor
from orchestrator.hyperv import HyperVManager
from orchestrator.reporting import ReportGenerator
from orchestrator.samples import SampleManager
from orchestrator.sigma_engine import SigmaEngine


app = FastAPI(
    title="Hyper-V Malware Sandbox Orchestrator",
    description="Phase 1: snapshot-based analysis using an existing Hyper-V VM.",
    version="0.1.0",
)

# Local live-trace manager (lazily built with the shared config)
_local_trace_mgr = None


def _local_trace() -> local_trace.LocalTraceManager:
    global _local_trace_mgr
    if _local_trace_mgr is None:
        _local_trace_mgr = local_trace.LocalTraceManager(_cfg())
    return _local_trace_mgr


def _console() -> console.ConsoleManager:
    """The singleton interactive-console manager (see orchestrator/console.py)."""
    mgr = console.get_console_manager(_cfg())
    assert mgr is not None
    return mgr


# Shared config and helpers (created per request to keep it simple)
def _cfg():
    return get_config()


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/vm/status")
def vm_status() -> Dict[str, Any]:
    try:
        hv = HyperVManager(_cfg())
        return hv.get_status()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# A full Sigma rule-parse is ~5s, so cache the engine across requests rather
# than rebuild it per /api/sigma/stats or /api/rules hit. The vendored ruleset
# is static per deployment; a config change needs a server restart to reflect,
# which matches how every other config value here is loaded.
_SIGMA_ENGINE_CACHE: Dict[str, SigmaEngine] = {}


def _get_sigma_engine() -> SigmaEngine:
    engine = _SIGMA_ENGINE_CACHE.get("engine")
    if engine is None:
        cfg = _cfg()
        sigma_cfg = cfg.sigma
        custom_dir = cfg.paths.get("sigma_custom_rules_dir")
        engine = SigmaEngine(
            rules_dir=Path(cfg.paths.get("sigma_rules_dir", "sigma_rules")),
            min_level=sigma_cfg.get("min_level", "medium"),
            excluded_categories=sigma_cfg.get("excluded_categories", []),
            disabled_rule_ids=sigma_cfg.get("disabled_rule_ids", []),
            custom_rules_dirs=[Path(custom_dir)] if custom_dir else None,
        )
        _SIGMA_ENGINE_CACHE["engine"] = engine
    return engine


@app.get("/api/sigma/stats")
def sigma_stats() -> Dict[str, Any]:
    """Diagnostic-only (rule_count/load_errors/coverage-gap visibility)."""
    try:
        engine = _get_sigma_engine()
        return {
            "rule_count": engine.rule_count,
            "load_errors": engine.load_errors,
            "correlation_rules_skipped": engine.correlation_rules_skipped,
            "unsupported_modifier_rule_ids": engine.unsupported_modifier_rule_ids,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _yara_rule_dirs(cfg) -> list:
    """Vendored + custom YARA dirs (matching executor.py's StaticAnalyzer
    construction) -- the single place main.py resolves them for the catalog
    and the lazy raw-source route."""
    dirs = []
    for key in ("yara_rules_dir", "yara_custom_rules_dir"):
        d = cfg.paths.get(key)
        if d:
            dirs.append(Path(d))
    return dirs


# A large vendored YARA set costs a few seconds to compile; cache the analyzer
# across /api/rules requests so the catalog's compiled rule_count + load_errors
# aren't recomputed per hit. Same rationale as _SIGMA_ENGINE_CACHE above.
_STATIC_ANALYZER_CACHE: Dict[str, Any] = {}


def _get_static_analyzer(cfg) -> static_analysis.StaticAnalyzer:
    analyzer = _STATIC_ANALYZER_CACHE.get("analyzer")
    if analyzer is None:
        yara_dir = cfg.paths.get("yara_rules_dir")
        yara_custom_dir = cfg.paths.get("yara_custom_rules_dir")
        analyzer = static_analysis.StaticAnalyzer(
            yara_rules_dir=Path(yara_dir) if yara_dir else None,
            custom_rules_dirs=[Path(yara_custom_dir)] if yara_custom_dir else None,
        )
        _STATIC_ANALYZER_CACHE["analyzer"] = analyzer
    return analyzer


def _rules_catalog(cfg, include_sigma_rules: bool) -> Dict[str, Any]:
    """Assemble the full detection-rule catalog: Sigma + YARA + hardcoded
    heuristics + static-analysis signals. include_sigma_rules=False returns
    just the counts/metadata (for the lightweight per-report summary), since
    the full Sigma rule list is ~2000 entries.
    """
    engine = _get_sigma_engine()
    yara_dirs = _yara_rule_dirs(cfg)
    yara_rules = static_analysis.describe_yara_rules(yara_dirs)
    # Compiled view (active rule count + any compile failures) from the cached
    # analyzer -- distinct from len(yara_rules), which is the on-disk count and
    # may be higher if some rules failed to compile.
    analyzer = _get_static_analyzer(cfg)
    yara_active = analyzer.yara_rule_count
    detectors = heuristics.describe_detectors()
    signals = static_analysis.describe_static_signals()
    behavioral = behavioral_signatures.describe_signatures()
    cape_engine = cape_engine_mod.get_engine(_cfg())
    cape = cape_engine.describe_signatures() if cape_engine else []

    sigma_block: Dict[str, Any] = {
        "count": engine.rule_count,
        "min_level": cfg.sigma.get("min_level", "medium"),
        "load_errors": engine.load_errors,
        "correlation_rules_skipped": engine.correlation_rules_skipped,
        "unsupported_modifier_rule_ids": engine.unsupported_modifier_rule_ids,
    }
    if include_sigma_rules:
        sigma_block["rules"] = engine.list_rules()

    return {
        "counts": {
            "sigma": engine.rule_count,
            "yara": yara_active,
            "heuristics": len(detectors),
            "static": len(signals),
            "behavioral": len(behavioral),
            "cape": len(cape),
        },
        "sigma": sigma_block,
        "yara": {
            "count": yara_active,
            "catalogued": len(yara_rules),
            "load_errors": analyzer.yara_load_errors,
            "targets": static_analysis._YARA_TARGETS,
            "rules": yara_rules,
        },
        "heuristics": {"count": len(detectors), "detectors": detectors},
        "behavioral": {"count": len(behavioral), "detectors": behavioral},
        "cape": {
            "count": len(cape),
            "detectors": cape,
            "load_errors": cape_engine.load_errors if cape_engine else [],
            "score_enabled": bool((getattr(_cfg(), "cape_signatures", None) or {}).get("score", False)),
        },
        "static": {"count": len(signals), "signals": signals},
    }


@app.get("/api/rules")
def rules_catalog() -> Dict[str, Any]:
    """Full detection-rule catalog for the top-level Rules browser -- every
    active Sigma rule plus the YARA rules, hardcoded heuristics and
    static-analysis signals."""
    try:
        return _rules_catalog(_cfg(), include_sigma_rules=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/rules/sigma/{rule_id}/raw")
def sigma_rule_raw(rule_id: str) -> Dict[str, Any]:
    """Raw YAML source for one Sigma rule (fetched lazily when a rule row is
    expanded in the browser), rather than embedding ~2000 YAMLs in /api/rules."""
    try:
        yaml_text = _get_sigma_engine().get_rule_yaml(rule_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if yaml_text is None:
        raise HTTPException(status_code=404, detail=f"No source for rule id {rule_id}")
    return {"id": rule_id, "yaml": yaml_text}


@app.get("/api/rules/cape/{sig_name}/raw")
def cape_rule_raw(sig_name: str) -> Dict[str, Any]:
    """Raw Python source of the module defining one CAPE signature (fetched
    lazily when a row is expanded in the Rules browser), mirroring the Sigma
    and YARA raw routes."""
    engine = cape_engine_mod.get_engine(_cfg())
    if engine is None:
        raise HTTPException(status_code=404, detail="CAPE integration disabled")
    source = engine.get_rule_source(sig_name)
    if source is None:
        raise HTTPException(status_code=404, detail=f"No source for signature {sig_name}")
    return {"name": sig_name, "source": source}


@app.get("/api/rules/yara/{rule_name}/raw")
def yara_rule_raw(rule_name: str) -> Dict[str, Any]:
    """Raw source for one YARA rule (fetched lazily when a rule row is expanded
    in the browser), rather than embedding thousands of rule bodies in
    /api/rules once a vendored ruleset is loaded -- mirrors the Sigma raw route
    above."""
    cfg = _cfg()
    source = static_analysis.get_yara_rule_source(rule_name, _yara_rule_dirs(cfg))
    if source is None:
        raise HTTPException(status_code=404, detail=f"No source for YARA rule {rule_name}")
    return {"name": rule_name, "source": source}


@app.get("/api/rules/summary")
def rules_summary() -> Dict[str, Any]:
    """Counts + metadata only (no ~2000-entry Sigma rule list) -- backs the
    per-report 'Detections applied' section's loaded-vs-fired header."""
    try:
        return _rules_catalog(_cfg(), include_sigma_rules=False)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/hookset")
def hookset() -> Dict[str, Any]:
    """The monitor's active hookset for the report page's Hooks/API-trace tab.

    Sourced from the curated orchestrator/data/coverage_map.yaml (one entry
    per kHooks[] row, drift-guarded by tests/test_coverage_map.py) plus the
    per-category descriptions in hookset_categories.json -- replacing the
    hand-mirrored HOOKSET constant the UI used to carry.
    """
    import json as _json

    import yaml

    data_dir = Path(__file__).resolve().parent / "data"
    entries = yaml.safe_load((data_dir / "coverage_map.yaml").read_text(encoding="utf-8")) or []
    cats_path = data_dir / "hookset_categories.json"
    cat_meta = _json.loads(cats_path.read_text(encoding="utf-8")) if cats_path.exists() else {}

    categories: Dict[str, Dict[str, Any]] = {}
    for e in entries:
        cat = e.get("category") or "misc"
        bucket = categories.setdefault(
            cat,
            {
                "name": cat,
                "description": (cat_meta.get(cat) or {}).get("description", ""),
                "order": (cat_meta.get(cat) or {}).get("order", 99),
                "hooks": [],
            },
        )
        bucket["hooks"].append(
            {
                "api": e.get("api"),
                "hook_module": e.get("hook_module"),
                "coverage": e.get("coverage"),
                "sysmon_counterparts": e.get("sysmon_counterparts") or [],
                "blind_spot": e.get("blind_spot") or [],
            }
        )

    ordered = sorted(categories.values(), key=lambda c: (c["order"], c["name"]))
    return {
        "total_hooks": len(entries),
        "categories": ordered,
    }


@app.post("/api/vm/restore")
def vm_restore() -> Dict[str, Any]:
    """Manually restore the clean snapshot."""
    try:
        hv = HyperVManager(_cfg())
        return hv.restore_snapshot()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/vm/snapshot")
def vm_ensure_snapshot() -> Dict[str, Any]:
    """Ensure the clean snapshot exists."""
    try:
        hv = HyperVManager(_cfg())
        return hv.ensure_snapshot()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/vm/provision-etw-ti")
def vm_provision_etw_ti() -> Any:
    """One-shot golden-image provisioning for ETW-Ti: restore -> boot -> copy
    agent -> configure the boot autologger -> reboot -> verify the live
    session -> re-capture the golden snapshot. Long-running (a reboot + a
    checkpoint swap). The re-capture is SKIPPED unless the autologger session
    is actually running after the reboot, so the golden image is never
    modified for a build where the non-PPL autologger yields nothing.
    """
    cfg = _cfg()
    agent_src = cfg.paths.get("agent_dir")
    guest_agent_dir = cfg.telemetry.get("guest_agent_dir", "C:\\SandboxAgent")
    steps: list = []

    def record(name: str, result: Any) -> Any:
        steps.append({"step": name, "result": result})
        return result

    try:
        hv = HyperVManager(cfg)
        record("restore_snapshot", hv.restore_snapshot())
        record("start_vm", hv.start_vm())
        record("copy_agent", hv.copy_agent(agent_source_dir=agent_src, destination_dir=guest_agent_dir))
        record("enable_autologger", hv.invoke_guest_python("etw_ti_manager.py", "enable", agent_dir=guest_agent_dir))
        record("reboot", hv.restart_guest())
        verify = record("verify", hv.invoke_guest_python("etw_ti_manager.py", "verify", agent_dir=guest_agent_dir))

        session_running = str(verify.get("ExitCode")) == "0"
        if not session_running:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "autologger_not_running",
                    "detail": (
                        "The autologger session is not running after reboot -- this Windows build likely won't "
                        "deliver TI events to a non-PPL autologger. Golden snapshot was NOT modified."
                    ),
                    "steps": steps,
                },
            )

        record("recapture_snapshot", hv.recapture_snapshot())
        return {"status": "provisioned", "detail": "Autologger live and baked into the golden snapshot.", "steps": steps}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"status": "failed", "error": str(exc), "steps": steps})


@app.post("/api/vm/provision-dressing")
def vm_provision_dressing() -> Any:
    """One-shot golden-image provisioning for anti-sandbox environment
    dressing: restore -> boot -> copy agent -> apply dressing (documents,
    browser history/bookmarks, recent-run artifacts) -> verify -> re-capture
    the golden snapshot. Re-capture is SKIPPED unless verification passes.
    Idempotent; safe to re-run to refresh the dressing.
    """
    cfg = _cfg()
    agent_src = cfg.paths.get("agent_dir")
    guest_agent_dir = cfg.telemetry.get("guest_agent_dir", "C:\\SandboxAgent")
    steps: list = []

    def record(name: str, result: Any) -> Any:
        steps.append({"step": name, "result": result})
        return result

    try:
        hv = HyperVManager(cfg)
        record("restore_snapshot", hv.restore_snapshot())
        record("start_vm", hv.start_vm())
        record("copy_agent", hv.copy_agent(agent_source_dir=agent_src, destination_dir=guest_agent_dir))
        record("apply", hv.invoke_guest_python("apply_dressing.py", "apply", agent_dir=guest_agent_dir))
        verify = record("verify", hv.invoke_guest_python("apply_dressing.py", "verify", agent_dir=guest_agent_dir))

        if str(verify.get("ExitCode")) != "0":
            return JSONResponse(
                status_code=200,
                content={
                    "status": "verification_failed",
                    "detail": "Dressing verification failed in the guest. Golden snapshot was NOT modified.",
                    "steps": steps,
                },
            )

        record("recapture_snapshot", hv.recapture_snapshot())
        return {"status": "provisioned", "detail": "Environment dressing applied and baked into the golden snapshot.", "steps": steps}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"status": "failed", "error": str(exc), "steps": steps})


@app.post("/api/vm/provision-noise-reduction")
def vm_provision_noise_reduction() -> Any:
    """One-shot golden-image provisioning for OS-noise reduction: restore ->
    boot -> copy agent -> apply_noise_reduction.py apply (disable updater/
    telemetry/CEIP/indexer tasks+services, telemetry policies) -> verify ->
    re-capture the golden snapshot. Re-capture is SKIPPED unless verification
    passes. Idempotent; Defender + wuauserv are deliberately kept (see
    agent/windows/apply_noise_reduction.py docstring). Same flow as
    provision-dressing, so the existing image gets it without full
    reprovisioning.
    """
    cfg = _cfg()
    agent_src = cfg.paths.get("agent_dir")
    guest_agent_dir = cfg.telemetry.get("guest_agent_dir", "C:\\SandboxAgent")
    steps: list = []

    def record(name: str, result: Any) -> Any:
        steps.append({"step": name, "result": result})
        return result

    try:
        hv = HyperVManager(cfg)
        record("restore_snapshot", hv.restore_snapshot())
        record("start_vm", hv.start_vm())
        record("copy_agent", hv.copy_agent(agent_source_dir=agent_src, destination_dir=guest_agent_dir))
        record("apply", hv.invoke_guest_python("apply_noise_reduction.py", "apply", agent_dir=guest_agent_dir))
        verify = record("verify", hv.invoke_guest_python("apply_noise_reduction.py", "verify", agent_dir=guest_agent_dir))

        if str(verify.get("ExitCode")) != "0":
            return JSONResponse(
                status_code=200,
                content={
                    "status": "verification_failed",
                    "detail": "Noise-reduction verification failed in the guest. Golden snapshot was NOT modified.",
                    "steps": steps,
                },
            )

        record("recapture_snapshot", hv.recapture_snapshot())
        return {"status": "provisioned", "detail": "OS noise reduction applied and baked into the golden snapshot.", "steps": steps}
    except Exception as exc:
        return JSONResponse(status_code=500, content={"status": "failed", "error": str(exc), "steps": steps})


@app.post("/api/vm/provision-defender-off")
def vm_provision_defender_off() -> Any:
    """One-shot golden-image provisioning: disable Microsoft Defender real-time
    protection so samples run to completion and our own instrumentation (Sysmon
    + Sigma + YARA + heuristics) observes their full behavior, instead of
    Defender killing them mid-execution (e.g. a certutil download cradle
    terminated before Sysmon logs ProcessCreate, so the LOLBin rule can't fire).

    restore -> boot -> copy agent -> status -> disable -> reboot -> verify ->
    (only if verify passes) re-capture the golden snapshot. The reboot-then-
    verify gate means a disable that Tamper Protection blocked never corrupts
    the golden image -- it just reports Tamper Protection is on so it can be
    turned off once via the VM's Windows Security UI.
    """
    cfg = _cfg()
    agent_src = cfg.paths.get("agent_dir")
    guest_agent_dir = cfg.telemetry.get("guest_agent_dir", "C:\\SandboxAgent")
    steps: list = []

    def record(name: str, result: Any) -> Any:
        steps.append({"step": name, "result": result})
        return result

    try:
        hv = HyperVManager(cfg)
        record("restore_snapshot", hv.restore_snapshot())
        record("start_vm", hv.start_vm())
        record("copy_agent", hv.copy_agent(agent_source_dir=agent_src, destination_dir=guest_agent_dir))
        record("status_before", hv.invoke_guest_python("defender_manager.py", "status", agent_dir=guest_agent_dir))
        record("disable", hv.invoke_guest_python("defender_manager.py", "disable", agent_dir=guest_agent_dir))
        record("reboot", hv.restart_guest())
        verify = record("verify", hv.invoke_guest_python("defender_manager.py", "verify", agent_dir=guest_agent_dir))

        realtime_off = str(verify.get("ExitCode")) == "0"
        if not realtime_off:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "realtime_still_on",
                    "detail": (
                        "Real-time protection is still on after the disable+reboot -- almost certainly "
                        "Tamper Protection blocking it (see the status_before step). Turn Tamper Protection "
                        "off once via the VM's Windows Security UI, then re-run. Golden snapshot was NOT modified."
                    ),
                    "steps": steps,
                },
            )

        record("recapture_snapshot", hv.recapture_snapshot())
        return {
            "status": "provisioned",
            "detail": "Defender real-time protection disabled and baked into the golden snapshot.",
            "steps": steps,
        }
    except Exception as exc:
        return JSONResponse(status_code=500, content={"status": "failed", "error": str(exc), "steps": steps})


@app.post("/api/vm/provision-defender-on")
def vm_provision_defender_on() -> Any:
    """Re-enable Microsoft Defender real-time protection in the golden image --
    the reverse of provision-defender-off. Same restore -> boot -> copy agent ->
    enable -> reboot -> verify -> recapture-if-verified sequence, so a re-enable
    that didn't take never corrupts the golden image.
    """
    cfg = _cfg()
    agent_src = cfg.paths.get("agent_dir")
    guest_agent_dir = cfg.telemetry.get("guest_agent_dir", "C:\\SandboxAgent")
    steps: list = []

    def record(name: str, result: Any) -> Any:
        steps.append({"step": name, "result": result})
        return result

    try:
        hv = HyperVManager(cfg)
        record("restore_snapshot", hv.restore_snapshot())
        record("start_vm", hv.start_vm())
        record("copy_agent", hv.copy_agent(agent_source_dir=agent_src, destination_dir=guest_agent_dir))
        record("enable", hv.invoke_guest_python("defender_manager.py", "enable", agent_dir=guest_agent_dir))
        record("reboot", hv.restart_guest())
        verify = record("verify", hv.invoke_guest_python("defender_manager.py", "verify-on", agent_dir=guest_agent_dir))

        realtime_on = str(verify.get("ExitCode")) == "0"
        if not realtime_on:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "realtime_still_off",
                    "detail": "Real-time protection is still off after enable+reboot -- golden snapshot was NOT modified.",
                    "steps": steps,
                },
            )

        record("recapture_snapshot", hv.recapture_snapshot())
        return {
            "status": "provisioned",
            "detail": "Defender real-time protection re-enabled and baked into the golden snapshot.",
            "steps": steps,
        }
    except Exception as exc:
        return JSONResponse(status_code=500, content={"status": "failed", "error": str(exc), "steps": steps})


@app.post("/api/vm/provision-clean-archive")
def vm_provision_clean_archive() -> Any:
    """Golden-image hygiene: empty Sysmon's deleted-file archive
    (C:\\SandboxArchive, SYSTEM-only ACL -> cleared via a SYSTEM scheduled
    task) so golden-image residue (e.g. tens of thousands of stale archived
    files) is not carried forward.

    restore -> boot -> clear (before/after counts) -> recapture the golden
    snapshot ONLY if the archive is verifiably empty afterwards. No reboot
    needed: file deletion is immediately visible.
    """
    steps: list = []

    def record(name: str, result: Any) -> Any:
        steps.append({"step": name, "result": result})
        return result

    try:
        hv = HyperVManager(_cfg())
        record("restore_snapshot", hv.restore_snapshot())
        record("start_vm", hv.start_vm())
        clear = record("clear_sandbox_archive", hv.clear_sandbox_archive())

        if clear.get("Status") != "cleaned" or clear.get("AfterFiles", -1) != 0:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "clean_failed",
                    "detail": "Archive not verifiably empty after clear -- golden snapshot was NOT modified.",
                    "steps": steps,
                },
            )

        record("recapture_snapshot", hv.recapture_snapshot())
        return {
            "status": "provisioned",
            "detail": (
                f"Sandbox archive purged ({clear.get('BeforeFiles')} files, "
                f"{clear.get('BeforeBytes')} bytes) and baked into the golden snapshot."
            ),
            "steps": steps,
        }
    except Exception as exc:
        return JSONResponse(status_code=500, content={"status": "failed", "error": str(exc), "steps": steps})


def _prepare_submission(
    cfg: Any,
    samples: SampleManager,
    file: Optional[UploadFile],
    url: Optional[str],
    url_mode: Optional[str],
    sample_type_override: Optional[str],
    dll_entry_point: Optional[str],
    archive_entry: Optional[str],
    archive_password: Optional[str],
    source: str,
) -> Dict[str, Any]:
    """Resolves a file-or-URL submission into the kwargs SandboxExecutor.
    run_analysis / jobs.submit_analysis_job need (sample_path, sample_type,
    launcher_path/arguments, etc. -- see orchestrator/sample_types.py).
    Raises HTTPException for any resolution failure (bad URL, ambiguous/
    encrypted/oversized archive, invalid sample_type override) so neither
    caller needs its own try/except around this.
    """
    if bool(file) == bool(url):
        raise HTTPException(status_code=400, detail="Submit exactly one of 'file' or 'url'")

    sec_cfg = cfg.sample_execution
    guest_destination_folder = sec_cfg.get("guest_destination_folder", "C:\\Sandbox")
    launcher_paths = sec_cfg.get("launcher_paths") or None

    if url is not None:
        url_cfg = sec_cfg.get("url", {})
        mode = url_mode or url_cfg.get("default_mode", "browse")
        try:
            plan = sample_types.build_url_launch_plan(
                url,
                mode,
                guest_destination_folder,
                launcher_paths=launcher_paths,
                fetch_curl_args=url_cfg.get("fetch_curl_args", "-s -k -L"),
                fetch_default_filename=url_cfg.get("fetch_default_filename", "download.bin"),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "sample_path": None,
            "sample_filename": url,
            "sample_type": "url",
            "launcher_path": plan.launcher_path,
            "launcher_arguments": plan.launcher_arguments,
            "destination_filename": plan.destination_filename,
            "working_directory_in_vm": plan.working_directory,
            "url": url,
            "url_mode": mode,
            "execution_error": None,
            "execution_error_detail": None,
        }

    # File path
    content = file.file.read()
    if len(content) > cfg.api.get("max_upload_size_bytes", 100 * 1024 * 1024):
        raise HTTPException(status_code=413, detail="Sample too large")

    filename = file.filename or "unknown"
    try:
        resolved_type = sample_types.resolve_sample_type(filename, content, override=sample_type_override)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if resolved_type == "url":
        raise HTTPException(
            status_code=400, detail="sample_type 'url' is not valid for file uploads; submit the 'url' field instead"
        )

    final_filename, final_content, final_type = filename, content, resolved_type
    archive_path: Optional[str] = None

    if resolved_type == "zip":
        archive_cfg = sec_cfg.get("archive", {})
        # Store the archive itself for provenance; the executor re-opens it
        # to stage ALL entries guest-side (multi-file zip staging). Keeping
        # the stored path in the job kwargs avoids holding bytes across the
        # async job queue.
        archive_meta = samples.store_sample(filename=filename, data=content, source=source, sample_type="zip")
        archive_path = archive_meta["stored_path"]
        try:
            entry_name, entry_content = sample_types.resolve_archive_entry(
                content,
                archive_entry=archive_entry,
                archive_password=archive_password,
                extra_passwords=archive_cfg.get("passwords_to_try", []),
                max_entry_size_bytes=archive_cfg.get("max_entry_size_bytes", 104857600),
                max_total_entries=archive_cfg.get("max_total_entries", 2000),
            )
        except sample_types.ArchiveResolutionError as exc:
            raise HTTPException(
                status_code=400, detail={"code": exc.code, "message": str(exc), "entries": exc.entries}
            ) from exc

        inner_type = sample_types.resolve_sample_type(entry_name, entry_content)
        if inner_type == "zip":
            raise HTTPException(
                status_code=400, detail="Nested archives are not supported -- extract manually and resubmit"
            )
        final_filename, final_content, final_type = entry_name, entry_content, inner_type

    sample_meta = samples.store_sample(filename=final_filename, data=final_content, source=source, sample_type=final_type)
    sample_path = sample_meta["stored_path"]

    plan = sample_types.build_launch_plan(
        final_type,
        guest_destination_folder,
        sample_data=final_content if final_type == "dll" else None,
        dll_entry_point_override=dll_entry_point,
        launcher_paths=launcher_paths,
        script_engine=sec_cfg.get("script_engine", "wscript"),
        powershell_args=sec_cfg.get("powershell_args", "-NoProfile -ExecutionPolicy Bypass"),
    )

    return {
        "sample_path": sample_path,
        "sample_filename": final_filename,
        "sample_type": final_type,
        "launcher_path": plan.launcher_path,
        "launcher_arguments": plan.launcher_arguments,
        "destination_filename": plan.destination_filename,
        "working_directory_in_vm": plan.working_directory,
        "url": None,
        "url_mode": None,
        "execution_error": plan.execution_error,
        "execution_error_detail": plan.execution_error_detail,
        "archive_path": archive_path,
        "archive_password": archive_password if archive_path else None,
    }


@app.post("/api/analyze")
def analyze_sample(
    file: Optional[UploadFile] = File(None, description="Malware sample to analyze"),
    url: Optional[str] = Form(None, description="URL to analyze instead of a file"),
    url_mode: Optional[str] = Form(None, description="'browse' (default) or 'fetch'"),
    arguments: Optional[str] = Form(""),
    timeout: Optional[int] = Form(None),
    sample_type: Optional[str] = Form(None, description="Override auto-detected sample type"),
    dll_entry_point: Optional[str] = Form(None, description="DLL export to invoke via rundll32 if ambiguous"),
    archive_entry: Optional[str] = Form(None, description="Which file to run from a multi-file ZIP"),
    archive_password: Optional[str] = Form(None, description="ZIP password, if encrypted"),
    interactive: Optional[bool] = Form(None, description="Run the sample on the visible console session (interactive mode)"),
) -> Dict[str, Any]:
    """
    Submit a sample (file upload) or a URL and run it inside the existing
    Hyper-V VM.

    The VM is reverted to its clean snapshot before execution and stopped
    afterward. The sample is never executed on the host.
    """
    cfg = _cfg()
    samples = SampleManager(cfg)

    plan_kwargs = _prepare_submission(
        cfg, samples, file, url, url_mode, sample_type, dll_entry_point, archive_entry, archive_password,
        source="api_upload",
    )

    # Claim the single-flight slot: there is exactly one VM behind this
    # orchestrator, so this run must not race against a dashboard-submitted
    # job (POST /api/jobs) or another /api/analyze call.
    job_id = str(uuid.uuid4())
    if not jobs.try_acquire(job_id):
        raise HTTPException(
            status_code=409,
            detail={"detail": "A job is already running", "active_job_id": jobs.get_active_job_id()},
        )

    # Run analysis
    try:
        executor = SandboxExecutor(cfg)
        report = executor.run_analysis(
            arguments=arguments or "",
            timeout_seconds=timeout,
            interactive=bool(interactive),
            **plan_kwargs,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc
    finally:
        jobs.release()

    return report


@app.post("/api/jobs", status_code=202)
def submit_job(
    file: Optional[UploadFile] = File(None, description="Malware sample to analyze"),
    url: Optional[str] = Form(None, description="URL to analyze instead of a file"),
    url_mode: Optional[str] = Form(None, description="'browse' (default) or 'fetch'"),
    arguments: Optional[str] = Form(""),
    timeout: Optional[int] = Form(None),
    sample_type: Optional[str] = Form(None, description="Override auto-detected sample type"),
    dll_entry_point: Optional[str] = Form(None, description="DLL export to invoke via rundll32 if ambiguous"),
    archive_entry: Optional[str] = Form(None, description="Which file to run from a multi-file ZIP"),
    archive_password: Optional[str] = Form(None, description="ZIP password, if encrypted"),
    interactive: Optional[bool] = Form(None, description="Run the sample on the visible console session (interactive mode)"),
) -> Dict[str, Any]:
    """
    Submit a sample (file upload) or a URL and run it asynchronously.
    Returns immediately with a job_id; poll GET /api/jobs/{job_id} for live
    step-by-step progress.

    Unlike /api/analyze, this does not block until the run finishes, and it
    always accepts the submission — there is exactly one VM, so if a job is
    already active this one is queued (FIFO) and starts automatically as
    soon as its turn comes up. Check the returned record's "status"
    ("queued" vs "running") and "queue_position" to see where it landed.
    """
    cfg = _cfg()
    samples = SampleManager(cfg)

    plan_kwargs = _prepare_submission(
        cfg, samples, file, url, url_mode, sample_type, dll_entry_point, archive_entry, archive_password,
        source="api_upload",
    )

    return jobs.submit_analysis_job(
        config=cfg,
        arguments=arguments or "",
        timeout_seconds=timeout,
        interactive=bool(interactive),
        **plan_kwargs,
    )


@app.get("/api/jobs")
def list_jobs(limit: int = 50) -> Dict[str, Any]:
    active_job_id, queue_length = jobs.get_queue_snapshot()
    return {"active_job_id": active_job_id, "queue_length": queue_length, "jobs": jobs.list_jobs(limit=limit)}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> Dict[str, Any]:
    job = jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# ---------------------------------------------------------------------------
# Interactive browser console (docs/interactive-console-streaming.md)
# ---------------------------------------------------------------------------
# On-demand live view (~1 fps WMI thumbnails, zero guest footprint) + input
# injection into the VM's visible console session. Opt-in: nothing here runs
# unless the console is explicitly opened. Opening it during a run tags the
# report (interactive_console: true) -- interaction changes the detonation.

@app.post("/api/console/open")
def console_open() -> Dict[str, Any]:
    try:
        return _console().open()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/console/close")
def console_close() -> Dict[str, Any]:
    return _console().close()


@app.get("/api/console/status")
def console_status() -> Dict[str, Any]:
    return _console().status()


@app.get("/api/console/frame")
def console_frame() -> Response:
    try:
        data, frame_id = _console().frame()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(
        content=data,
        media_type="image/png",
        headers={"Cache-Control": "no-store", "X-Frame-Id": str(frame_id)},
    )


@app.post("/api/console/input")
def console_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return _console().input(payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/reports/list")
def list_reports_summary(limit: int = 100, since_hours: Optional[float] = None) -> Dict[str, Any]:
    """One-line-per-report projection for a history table.

    Distinct path from GET /api/reports (which stays untouched, id-only).
    Must be registered before GET /api/reports/{analysis_id} or Starlette
    would match "list" as an analysis_id.

    since_hours: only include reports modified in the last N hours (the web
    app defaults to 24 so opening the history doesn't drag in months of old
    runs).
    """
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    reports_dir = Path(cfg.paths["reports_dir"])
    # Sort by mtime and truncate BEFORE parsing so cost is bounded as the
    # reports directory grows past today's size. Skip the summary sidecars
    # themselves ("*.summary.json").
    candidates = [p for p in reports_dir.glob("*.json") if not p.name.endswith(".summary.json")]
    if since_hours is not None and since_hours > 0:
        cutoff = time.time() - since_hours * 3600
        candidates = [p for p in candidates if p.stat().st_mtime >= cutoff]
    paths = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[:limit]

    summaries = []
    for p in paths:
        # Fast path: the tiny sidecar written at save time. Slow path (older
        # reports): one full parse, then backfill the sidecar so the next
        # list load is instant.
        summary = reporter.load_report_summary(p.stem)
        if summary is None or "verdict_level" not in summary:
            # Slow path: one full parse, then (re)write the sidecar. Also the
            # upgrade path for sidecars written before verdict fields existed.
            report = reporter.load_report_cached(p.stem)
            if not report:
                continue
            summary = report_view.summarize_report(report)
            try:
                reporter.save_report_summary(p.stem, summary)
            except OSError:
                pass
        summaries.append(summary)

    return {"count": len(summaries), "reports": summaries}


@app.get("/api/reports/{analysis_id}")
def get_report(analysis_id: str) -> Dict[str, Any]:
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/api/reports/{analysis_id}/summary")
def get_report_summary(
    analysis_id: str,
    include_raw_events: bool = False,
    max_events: int = 200,
) -> Dict[str, Any]:
    """Trimmed report view (raw events omitted by default) for the detail page."""
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_view.trim_report(report, include_raw_events, max_events)


@app.get("/api/reports/{analysis_id}/events")
def get_report_events(
    analysis_id: str,
    offset: int = 0,
    limit: int = 200,
    event_type: Optional[str] = None,
    q: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """Paginated/searchable raw event browser for the report detail page."""
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_view.paginate_events(report, offset=offset, limit=limit, event_type=event_type, q=q, source=source)


@app.get("/api/reports/{analysis_id}/alerts")
def get_report_alerts(
    analysis_id: str,
    offset: int = 0,
    limit: int = 200,
    scope: Optional[str] = None,
    event_type: Optional[str] = None,
    q: Optional[str] = None,
) -> Dict[str, Any]:
    """Paginated/searchable alert browser -- trim_report() drops
    environment-scoped alerts from the initial /summary payload (they can
    number in the tens of thousands), fetched on demand here instead.
    scope: "sample" | "environment" | None (all).
    """
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_view.paginate_alerts(report, offset=offset, limit=limit, scope=scope, event_type=event_type, q=q)


@app.get("/api/reports")
def list_reports() -> Dict[str, Any]:
    cfg = _cfg()
    reports_dir = Path(cfg.paths["reports_dir"])
    reports = [p.stem for p in reports_dir.glob("*.json")]
    return {"reports": reports, "count": len(reports)}


@app.get("/api/reports/{analysis_id}/harness-validation")
def get_harness_validation(analysis_id: str) -> Dict[str, Any]:
    """Check whether an InjectionHarness.exe run produced the expected
    Sysmon signals for each technique. Mirrors scripts/harness_assertions.py.
    """
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    stdout = (report.get("execution_info") or {}).get("Stdout", "")
    alerts = report.get("alerts", [])
    result = harness_validation.validate_harness_alerts(stdout, alerts)
    result["analysis_id"] = analysis_id
    return result


@app.post("/api/harness/run", status_code=202)
def run_harness(
    vm_name: Optional[str] = None,
    snapshot_name: Optional[str] = None,
    timeout: int = 120,
) -> Dict[str, Any]:
    """Rebuild samples/InjectionHarness from source and run it in the
    sandbox. Shells out to scripts/run_injection_harness.ps1 (bypasses
    SandboxExecutor directly, so progress is coarse: queued/running/
    completed/failed only). Shares the same single-flight slot as
    /api/jobs and /api/analyze.
    """
    job = jobs.submit_harness_job(vm_name=vm_name, snapshot_name=snapshot_name, timeout_seconds=timeout)
    if job is None:
        raise HTTPException(
            status_code=409,
            detail={"detail": "A job is already running", "active_job_id": jobs.get_active_job_id()},
        )
    return job


@app.post("/api/guardian/run", status_code=202)
def run_guardian(action: str) -> Dict[str, Any]:
    """Run a SandboxGuard driver stage against the analysis VM
    (guardian\\*.ps1 via PowerShell Direct). The orchestrator must run
    ELEVATED for VM stages (Hyper-V PSDirect).

    Actions: build (compile+sign the driver, host-side), load / test /
    cleanup (the repeatable A1a functional flow), provision (bake the driver
    into the golden snapshot), verifier-soak (A4: Driver Verifier standard
    flags on SandboxGuard.sys + A1a battery, then restores the snapshot so
    normal runs stay verifier-free), and the one-time A0 spike stages
    spike-inspect / spike-enable / spike-load / spike-diag / spike-cleanup.

    Returns immediately with a job record; poll GET /api/jobs/{job_id}.
    For action=test/verifier-soak the job's report_status is "all_pass" |
    "checks_failed" and the script output tail is on the record's "output"
    field. Shares the single-flight VM slot with /api/jobs and
    /api/harness/run.
    """
    try:
        job = jobs.submit_guardian_job(action)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if job is None:
        raise HTTPException(
            status_code=409,
            detail={"detail": "A job is already running", "active_job_id": jobs.get_active_job_id()},
        )
    return job


def _resolve_capture(report: Dict[str, Any]) -> Dict[str, Any]:
    """Check whether a report's network_capture actually has a usable file
    on disk. A report simply lacking a capture is a normal, expected state
    (disabled, never started, or deleted after the fact) -- not an error.
    """
    nc = report.get("network_capture") or {}
    if not nc.get("enabled"):
        return {"available": False, "reason": "disabled", "detail": "Network capture was not enabled for this run."}
    if not nc.get("started"):
        return {"available": False, "reason": "not_started", "detail": "Network capture did not start successfully."}
    host_path = nc.get("HostPath")
    if not host_path:
        return {"available": False, "reason": "no_metadata", "detail": "No capture file path recorded for this run."}
    if not Path(host_path).exists():
        return {"available": False, "reason": "missing_file", "detail": f"Capture file not found on disk: {host_path}"}
    return {"available": True, "path": host_path}


@app.get("/api/reports/{analysis_id}/network-summary")
def get_network_summary(analysis_id: str) -> Dict[str, Any]:
    """Protocol breakdown, top conversations, and DNS queries for a report's
    network capture. See orchestrator/pcap_view.py for the scapy parsing.
    """
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    capture = _resolve_capture(report)
    if not capture["available"]:
        return {
            "analysis_id": analysis_id,
            "capture_available": False,
            "reason": capture["reason"],
            "detail": capture["detail"],
        }

    summary = pcap_view.summarize_capture(capture["path"])
    return {"analysis_id": analysis_id, "capture_available": True, "host_path": capture["path"], **summary}


@app.get("/api/reports/{analysis_id}/network-packets")
def get_network_packets(
    analysis_id: str,
    offset: int = 0,
    limit: int = 100,
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    port: Optional[int] = None,
    q: Optional[str] = None,
) -> Dict[str, Any]:
    """Paginated/searchable packet browser for a report's network capture."""
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    capture = _resolve_capture(report)
    if not capture["available"]:
        return {
            "analysis_id": analysis_id,
            "capture_available": False,
            "reason": capture["reason"],
            "detail": capture["detail"],
        }

    result = pcap_view.paginate_packets(
        capture["path"], offset=offset, limit=limit, protocol=protocol, ip=ip, port=port, q=q
    )
    return {"analysis_id": analysis_id, "capture_available": True, **result}


@app.get("/api/reports/{analysis_id}/network-packets/{packet_index}")
def get_network_packet_detail(analysis_id: str, packet_index: int) -> Dict[str, Any]:
    """Full dissection (layer tree + hex dump) of one packet in a report's
    capture -- backs the packet-detail popup in the dashboard's packet
    browser. Re-reads the pcapng on demand (per-click, so cheap)."""
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    capture = _resolve_capture(report)
    if not capture["available"]:
        return {
            "analysis_id": analysis_id,
            "capture_available": False,
            "reason": capture["reason"],
            "detail": capture["detail"],
        }

    detail = pcap_view.packet_detail(capture["path"], packet_index)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Packet index {packet_index} out of range")
    return {"analysis_id": analysis_id, "capture_available": True, **detail}


def _resolve_screenshot(report: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Same "absence is normal" philosophy as _resolve_capture, but scoped
    to a single indexed screenshot within report['screenshots']['items'].
    """
    sc = report.get("screenshots") or {}
    if not sc.get("enabled"):
        return {"available": False, "reason": "disabled", "detail": "Screenshots were not enabled for this run."}
    items = sc.get("items") or []
    item = next((i for i in items if i.get("index") == index), None)
    if item is None:
        return {"available": False, "reason": "not_found", "detail": f"No screenshot at index {index}."}
    path = item.get("path")
    if not path:
        return {"available": False, "reason": "capture_failed", "detail": item.get("error", "Capture failed.")}
    if not Path(path).exists():
        return {"available": False, "reason": "missing_file", "detail": f"Screenshot file not found on disk: {path}"}
    return {"available": True, "path": path}


@app.get("/api/reports/{analysis_id}/screenshots")
def get_screenshots(analysis_id: str) -> Dict[str, Any]:
    """Metadata list (index/timestamp/size or error) for a report's periodic
    VM console screenshots. See scripts/hyperv-vm.ps1::Get-SandboxVMThumbnail.
    """
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    sc = report.get("screenshots") or {"enabled": False}
    return {
        "analysis_id": analysis_id,
        "enabled": sc.get("enabled", False),
        "interval_seconds": sc.get("interval_seconds"),
        "count": sc.get("count", 0),
        "items": [{k: v for k, v in item.items() if k != "path"} for item in (sc.get("items") or [])],
    }


@app.get("/api/reports/{analysis_id}/screenshots/{index}")
def get_screenshot_image(analysis_id: str, index: int) -> FileResponse:
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    resolved = _resolve_screenshot(report, index)
    if not resolved["available"]:
        raise HTTPException(status_code=404, detail=resolved["detail"])
    return FileResponse(path=resolved["path"], media_type="image/png")


def _resolve_dump(report: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Same "absence is normal" philosophy as _resolve_capture/_resolve_screenshot,
    scoped to a single indexed process memory dump within
    report['process_dumps']['items'].
    """
    pd = report.get("process_dumps") or {}
    if not pd.get("enabled"):
        return {"available": False, "reason": "disabled", "detail": "Process dumps were not enabled for this run."}
    items = pd.get("items") or []
    if index < 0 or index >= len(items):
        return {"available": False, "reason": "not_found", "detail": f"No process dump at index {index}."}
    item = items[index]
    path = item.get("path")
    if not path:
        return {"available": False, "reason": "no_metadata", "detail": "No dump file path recorded."}
    if not Path(path).exists():
        return {"available": False, "reason": "missing_file", "detail": f"Dump file not found on disk: {path}"}
    return {"available": True, "path": path, "filename": item.get("filename")}


@app.get("/api/reports/{analysis_id}/process-dumps")
def get_process_dumps(analysis_id: str) -> Dict[str, Any]:
    """Metadata (filename/size/YARA matches) for a report's periodic
    process memory dumps ("passive" dynamic unpacking). See
    scripts/hyperv-vm.ps1::Invoke-SampleExecution's polling loop.
    """
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    pd = report.get("process_dumps") or {"enabled": False}
    items = []
    for i, item in enumerate(pd.get("items") or []):
        items.append(
            {
                "index": i,
                "filename": item.get("filename"),
                "size_bytes": item.get("size_bytes"),
                "yara_matches": item.get("yara_matches") or [],
            }
        )
    return {
        "analysis_id": analysis_id,
        "enabled": pd.get("enabled", False),
        "count": pd.get("count", 0),
        "items": items,
        "attempts": pd.get("attempts", []),
        "error": pd.get("error"),
    }


@app.get("/api/reports/{analysis_id}/process-dumps/{index}/download")
def get_process_dump_download(analysis_id: str, index: int) -> FileResponse:
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    resolved = _resolve_dump(report, index)
    if not resolved["available"]:
        raise HTTPException(status_code=404, detail=resolved["detail"])
    return FileResponse(
        path=resolved["path"],
        media_type="application/octet-stream",
        filename=resolved["filename"] or f"{analysis_id}_{index}.dmp",
    )


def _resolve_dropped_file(report: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Same "absence is normal" philosophy as _resolve_dump, scoped to a
    single indexed dropped file within report['dropped_files']['items'].
    Only items with status == "retrieved" have a usable path on disk --
    not_found/skipped_too_large/error entries exist for transparency but
    were never actually saved.
    """
    df = report.get("dropped_files") or {}
    if not df.get("enabled"):
        return {"available": False, "reason": "disabled", "detail": "Dropped-file retrieval was not enabled for this run."}
    items = df.get("items") or []
    if index < 0 or index >= len(items):
        return {"available": False, "reason": "not_found", "detail": f"No dropped file at index {index}."}
    item = items[index]
    if item.get("status") != "retrieved":
        return {"available": False, "reason": item.get("status", "unavailable"), "detail": f"File was not retrieved (status: {item.get('status')})."}
    path = item.get("path")
    if not path or not Path(path).exists():
        return {"available": False, "reason": "missing_file", "detail": f"Dropped file not found on disk: {path}"}
    return {"available": True, "path": path, "filename": item.get("filename")}


@app.get("/api/reports/{analysis_id}/dropped-files")
def get_dropped_files(analysis_id: str) -> Dict[str, Any]:
    """Metadata (filename/hash/size/YARA matches/status) for files the
    sample's own process tree dropped during execution. See
    executor.py::_select_dropped_files and
    scripts/hyperv-vm.ps1::Copy-DroppedFilesFromVM.
    """
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    df = report.get("dropped_files") or {"enabled": False}
    items = []
    for i, item in enumerate(df.get("items") or []):
        items.append(
            {
                "index": i,
                "filename": item.get("filename"),
                "original_path": item.get("original_path"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
                "status": item.get("status"),
                "yara_matches": item.get("yara_matches") or [],
            }
        )
    return {
        "analysis_id": analysis_id,
        "enabled": df.get("enabled", False),
        "count": df.get("count", 0),
        "items": items,
        "error": df.get("error"),
    }


@app.get("/api/reports/{analysis_id}/dropped-files/{index}/download")
def get_dropped_file_download(analysis_id: str, index: int) -> FileResponse:
    cfg = _cfg()
    reporter = ReportGenerator(cfg)
    report = reporter.load_report_cached(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    resolved = _resolve_dropped_file(report, index)
    if not resolved["available"]:
        raise HTTPException(status_code=404, detail=resolved["detail"])
    return FileResponse(
        path=resolved["path"],
        media_type="application/octet-stream",
        filename=resolved["filename"] or f"{analysis_id}_{index}",
    )


@app.post("/api/local-trace/start", status_code=201)
def local_trace_start(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Launch a local (host-side) program under the MinHook monitor and start
    streaming its hooked API calls (the Live Trace page polls /events)."""
    target = (payload or {}).get("target", "").strip()
    arguments = (payload or {}).get("arguments", "")
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    try:
        return _local_trace().start(target, arguments)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 -- surface the real cause to the UI/log
        local_trace._log_error(Path(_cfg().paths["logs_dir"]) / "local-trace", "start")
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}") from exc


@app.post("/api/local-trace/stop")
def local_trace_stop() -> Dict[str, Any]:
    try:
        return _local_trace().stop()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/local-trace/status")
def local_trace_status() -> Dict[str, Any]:
    return _local_trace().status()


@app.get("/api/local-trace/events")
def local_trace_events(offset: int = 0, limit: int = 500, q: str = "") -> Dict[str, Any]:
    """Live-tail cursor: pass next_offset from the previous response."""
    return _local_trace().events(offset=offset, limit=min(limit, 2000), q=q)


@app.get("/api/local-trace/history")
def local_trace_history() -> Dict[str, Any]:
    """Archived local-trace sessions (the Traces page)."""
    return _local_trace().history()


@app.get("/api/local-trace/history/{session_id}/events")
def local_trace_history_events(session_id: str, offset: int = 0, limit: int = 500, q: str = "") -> Dict[str, Any]:
    try:
        return _local_trace().history_events(session_id, offset=offset, limit=min(limit, 2000), q=q)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse(url="/ui/")


class Utf8StaticFiles(StaticFiles):
    """StaticFiles that always declares charset=utf-8 on text-ish responses.

    On Windows, Python's mimetypes module resolves .js to
    "application/javascript" (no "text/" prefix), so Starlette's own
    charset-appending logic (which only fires for "text/*") skips it —
    any non-ASCII character in a served .js file (e.g. an en dash or a
    middle dot) then gets misdecoded by the browser as it has no
    charset to go on.
    """

    async def get_response(self, path: str, scope: Scope):
        response = await super().get_response(path, scope)
        content_type = response.headers.get("content-type", "")
        if content_type and "charset=" not in content_type.lower():
            response.headers["content-type"] = f"{content_type}; charset=utf-8"
        # No build step here, so JS/CSS edits ship by just overwriting the
        # file -- but browsers heuristically cache these without a
        # Cache-Control header and then serve a stale api.js/report_detail.js
        # after an update. "no-cache" forces revalidation on every load (a
        # cheap 304 when unchanged), so an edit is always picked up without a
        # hard refresh.
        response.headers["Cache-Control"] = "no-cache"
        return response


# Web dashboard (plain HTML/CSS/JS, no build step). Mounted last so it never
# shadows the /api/* routes above.
app.mount(
    "/ui",
    Utf8StaticFiles(directory=str(Path(__file__).resolve().parent / "static"), html=True),
    name="ui",
)
