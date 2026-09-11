"""Sandbox execution engine.

Coordinates the analysis lifecycle around an existing Hyper-V VM using
snapshots for fast rollback. Telemetry is collected via Sysmon (and optional
ETW gap-fillers) inside the guest, not via a kernel EDR driver.
"""

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from orchestrator import capa_analysis
from orchestrator.config import SandboxConfig
from orchestrator.hyperv import HyperVManager
from orchestrator.pid_lineage import build_pid_lineage
from orchestrator.reporting import ReportGenerator
from orchestrator.sigma_engine import SigmaEngine
from orchestrator.static_analysis import StaticAnalyzer


class SandboxExecutor:
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.hv = HyperVManager(config)
        self.reporter = ReportGenerator(config)
        self.telemetry_cfg = config.telemetry
        vt_api_key = config.static_analysis.get("vt_api_key") or os.environ.get("VT_API_KEY")
        # Vendored (at-scale) ruleset + project-owned custom rules, mirroring
        # the sigma_rules vs sigma_rules_custom split. Either dir may be absent
        # (e.g. before vendoring) -- StaticAnalyzer tolerates missing dirs.
        yara_dir = config.paths.get("yara_rules_dir")
        yara_custom_dir = config.paths.get("yara_custom_rules_dir")
        self.static_analyzer = StaticAnalyzer(
            yara_rules_dir=Path(yara_dir) if yara_dir else None,
            custom_rules_dirs=[Path(yara_custom_dir)] if yara_custom_dir else None,
            vt_api_key=vt_api_key,
            capa_config=config.static_analysis.get("capa"),
        )

        # Loaded once per process (like static_analyzer's YARA rules above)
        # -- rule parsing is not cheap enough to redo per report. NOT
        # constructed inside ReportGenerator, which is instantiated on
        # nearly every main.py route including cheap read-only report-fetch
        # endpoints that never call build_report().
        sigma_cfg = config.sigma
        self.sigma_engine: Optional[SigmaEngine] = None
        if sigma_cfg.get("enabled", True):
            custom_dir = config.paths.get("sigma_custom_rules_dir")
            self.sigma_engine = SigmaEngine(
                rules_dir=Path(config.paths.get("sigma_rules_dir", "sigma_rules")),
                min_level=sigma_cfg.get("min_level", "medium"),
                excluded_categories=sigma_cfg.get("excluded_categories", []),
                disabled_rule_ids=sigma_cfg.get("disabled_rule_ids", []),
                custom_rules_dirs=[Path(custom_dir)] if custom_dir else None,
            )

    def _vm_ip(self) -> Optional[str]:
        status = self.hv.get_status()
        return status.get("IPAddress")

    def _agent_dir_host(self) -> str:
        return self.config.paths.get("agent_dir", str(Path(__file__).resolve().parent.parent / "agent" / "windows"))

    def _sources_str(self, include_apitrace: bool = False, include_guardian: bool = False) -> str:
        sources = list(self.telemetry_cfg.get("sources", ["sysmon"]))
        # apitrace is opt-in per-run (Track 3), not a static config entry --
        # only append it when this run actually started the collector, so a
        # non-traced run never asks telemetry_collector.py to look for a file
        # that (by design) was never created. Same contract for guardian.
        if include_apitrace and "apitrace" not in sources:
            sources.append("apitrace")
        if include_guardian and "guardian" not in sources:
            sources.append("guardian")
        return ",".join(sources)

    def _read_telemetry_events(self, path: Path) -> List[Dict[str, Any]]:
        if not path.exists():
            return []
        events = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events

    def _screenshot_loop(
        self,
        stop_event: threading.Event,
        screenshots_dir: Path,
        interval_seconds: float,
        width_pixels: int,
        height_pixels: int,
        max_screenshots: int,
        results: List[Dict[str, Any]],
    ) -> None:
        """Runs on a background thread for the duration of execute_sample.
        Host-side only (WMI thumbnail capture) -- a single failed capture
        must never kill the loop or the analysis.
        """
        index = 0
        while not stop_event.is_set() and index < max_screenshots:
            output_path = screenshots_dir / f"{index:04d}.png"
            try:
                capture_result = self.hv.capture_screenshot(
                    output_path=str(output_path),
                    width_pixels=width_pixels,
                    height_pixels=height_pixels,
                )
                if capture_result.get("Status") == "captured":
                    results.append(
                        {
                            "index": index,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "path": str(output_path),
                            "size_bytes": capture_result.get("SizeBytes", 0),
                        }
                    )
                else:
                    results.append(
                        {
                            "index": index,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "error": capture_result.get("Status", "unknown error"),
                        }
                    )
            except Exception as exc:
                results.append(
                    {
                        "index": index,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "error": str(exc),
                    }
                )
            index += 1
            stop_event.wait(interval_seconds)

    def _select_dropped_files(
        self,
        events: List[Dict[str, Any]],
        sample_pid: Optional[int],
        guest_agent_dir: str,
        max_files: int,
        launcher_path: Optional[str] = None,
    ) -> List[str]:
        """Scope dropped-file retrieval to the sample's own process lineage.
        A raw FileCreate event sweep would otherwise pull in the agent's own
        files too -- confirmed via a real historical event: logman.exe (our
        AMSI collector) creating C:\\SandboxAgent\\amsi.etl, unrelated to
        anything the sample did.
        """
        lineage = build_pid_lineage(events, sample_pid, launcher_path)
        if not lineage:
            return []

        guest_agent_dir_prefix = guest_agent_dir.rstrip("\\").lower()
        seen_paths = set()
        selected: List[str] = []
        for event in events:
            event_type = event.get("event_type") or event.get("EventType")
            if event_type != "FileCreate":
                continue
            data = event.get("data") or {}
            # Prefer ProcessGuid (immune to PID reuse -- see pid_lineage.py's
            # PidLineage docstring for the confirmed real-world collision
            # this closes) and fall back to ProcessId when a FileCreate
            # event doesn't carry one.
            guid = data.get("ProcessGuid")
            if guid and lineage.guids:
                if guid not in lineage.guids:
                    continue
            else:
                try:
                    pid = int(data.get("ProcessId"))
                except (TypeError, ValueError):
                    continue
                if pid not in lineage.pids:
                    continue
            path = data.get("TargetFilename")
            if not path or path.lower().startswith(guest_agent_dir_prefix):
                continue
            if path in seen_paths:
                continue
            seen_paths.add(path)
            selected.append(path)
            if len(selected) >= max_files:
                break
        return selected

    def _select_archive_deletions(
        self,
        events: List[Dict[str, Any]],
        sample_pid: Optional[int],
        max_files: int,
        launcher_path: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Hashes + original paths of files the sample's lineage DELETED
        (Sysmon EID 23 FileDelete -- the archived variant; EID 26
        FileDeleteDetected is log-only and its content is not recoverable).
        Sysmon's ArchiveDirectory preserves deleted content named
        '<ALGO>=<hash>'; these hashes are the retrieval+verification keys.
        Same lineage scoping as _select_dropped_files.
        """
        lineage = build_pid_lineage(events, sample_pid, launcher_path)
        if not lineage:
            return []
        out: List[Dict[str, str]] = []
        seen = set()
        for event in events:
            if (event.get("event_type") or event.get("EventType")) != "FileDelete":
                continue
            data = event.get("data") or {}
            guid = data.get("ProcessGuid")
            if guid and lineage.guids:
                if guid not in lineage.guids:
                    continue
            else:
                try:
                    pid = int(data.get("ProcessId"))
                except (TypeError, ValueError):
                    continue
                if pid not in lineage.pids:
                    continue
            target = data.get("TargetFilename") or ""
            for part in (data.get("Hashes") or "").split(","):
                if "=" not in part:
                    continue
                algo, h = part.split("=", 1)
                algo, h = algo.strip().lower(), h.strip().lower()
                if algo in ("md5", "sha256") and h and h not in seen:
                    seen.add(h)
                    out.append({"hash_algo": algo, "hash": h, "deleted_path": target})
            if len(out) >= max_files:
                break
        return out

    @staticmethod
    def _static_summary(res: Dict[str, Any]) -> Dict[str, Any]:
        """Trim a full StaticAnalyzer.analyze() result down to what a dropped-
        file report entry needs (a raw analyze() result -- full sections,
        imports with every function, 200 strings -- would bloat the report)."""
        pe = res.get("pe") or {}
        dotnet = pe.get("dotnet")
        dotnet_summary = None
        if dotnet:
            dotnet_summary = {
                "assembly_name": dotnet.get("assembly_name"),
                "runtime_version": dotnet.get("runtime_version"),
                "mixed_mode": dotnet.get("mixed_mode"),
                "entry_point_token": dotnet.get("entry_point_token"),
                "obfuscator_suspected": dotnet.get("obfuscator_suspected"),
                "obfuscator_markers": dotnet.get("obfuscator_markers"),
                "type_refs": (dotnet.get("type_refs") or [])[:25],
                "user_strings": (dotnet.get("user_strings") or [])[:25],
            }
        return {
            "file_type": (res.get("file_type") or {}).get("name"),
            "entropy": res.get("entropy"),
            "packed_suspected": res.get("packed_suspected"),
            "packing_reasons": res.get("packing_reasons"),
            "is_pe": bool(pe.get("is_pe")),
            "machine": pe.get("machine"),
            "import_dlls": [e.get("dll") for e in (pe.get("imports") or []) if e.get("dll")][:50],
            "dotnet": dotnet_summary,
            "yara": res.get("yara") or [],
            "strings_interesting": (res.get("strings") or {}).get("interesting", [])[:50],
        }

    def _analyze_retrieved_file(
        self,
        item: Dict[str, Any],
        host_path: str,
        df_cfg: Dict[str, Any],
        capa_budget: List[int],
    ) -> None:
        """Deep re-analysis of one retrieved dropped/archived file, in place.
        Full static pipeline minus capa (run_capa=False -- capa is a 180s-
        bounded subprocess per file, so it runs only on flagged PEs within a
        per-run budget); capa is attached as item['capa'] when it ran.
        """
        if not df_cfg.get("deep_analysis", True):
            try:
                data = Path(host_path).read_bytes()
                item["sha256"] = hashlib.sha256(data).hexdigest()
                item["yara_matches"] = self.static_analyzer.match_yara(Path(host_path))
            except Exception as exc:
                item["yara_matches"] = [{"error": str(exc)}]
            return
        try:
            res = self.static_analyzer.analyze(host_path, run_capa=False)
            item["sha256"] = (res.get("hashes") or {}).get("sha256")
            summary = self._static_summary(res)
            item["static"] = summary
            item["yara_matches"] = summary["yara"]
            yara_hits = [m for m in summary["yara"] if "error" not in m]
            obf = (summary.get("dotnet") or {}).get("obfuscator_suspected")
            flagged = bool(yara_hits) or summary.get("packed_suspected") or obf
            if summary.get("is_pe") and flagged and capa_budget[0] > 0:
                capa_budget[0] -= 1
                item["capa"] = capa_analysis.analyze_file(host_path, self.static_analyzer.capa_config)
        except Exception as exc:
            item["static_error"] = str(exc)
            try:
                item["yara_matches"] = self.static_analyzer.match_yara(Path(host_path))
            except Exception as yara_exc:
                item["yara_matches"] = [{"error": str(yara_exc)}]

    def _build_execution_error_report(
        self,
        analysis_id: str,
        sample_path: Optional[str],
        sample_type: str,
        execution_error: str,
        execution_error_detail: Any,
        url: Optional[str],
        url_mode: Optional[str],
        sample_filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Used when sample_types.py already determined dynamic execution
        can't proceed (e.g. a DLL with an ambiguous or missing entry point)
        -- runs static analysis + YARA on the sample file itself, but skips
        the VM lifecycle entirely rather than booting a VM for a run that
        was never going to execute anything.
        """
        static_results: Dict[str, Any] = {}
        sample_metadata: Dict[str, Any] = {
            "id": analysis_id,
            "sample_type": sample_type,
            "url": url,
            "url_mode": url_mode,
        }
        if sample_path is not None:
            sample_file = Path(sample_path)
            try:
                static_results = self.static_analyzer.analyze(sample_path)
            except Exception as exc:
                static_results = {"error": str(exc)}
            sample_metadata.update(
                {
                    # sample_path is the SHA256-keyed host storage path
                    # (see samples.py::store_sample) -- sample_filename is
                    # the original/resolved name and must be preferred when
                    # given, or every report would show a bare hash here.
                    "filename": sample_filename or sample_file.name,
                    "size": sample_file.stat().st_size,
                    "hashes": static_results.get("hashes", {}),
                    "tags": [],
                }
            )

        execution_info = {
            "Started": False,
            "execution_error": execution_error,
            "execution_error_detail": execution_error_detail,
        }

        # Interactive tags: interactive_launch marks a sample run on the
        # visible console session (per-job opt-in); interactive_console marks
        # that the browser console was opened at any point during the run
        # window (analyst input alters the detonation). Either one makes the
        # report non-comparable to corpus baselines.
        report = self.reporter.build_report(
            analysis_id=analysis_id,
            sample_metadata=sample_metadata,
            vm_name=self.config.hyperv["analysis_vm"],
            vm_ip=None,
            runtime_seconds=0.0,
            telemetry_events=[],
            static_analysis=static_results,
            network_capture={"enabled": False},
            screenshots={"enabled": False},
            process_dumps={"enabled": False},
            dropped_files={"enabled": False},
            execution_info=execution_info,
            status="completed",
            error=None,
            sigma_engine=self.sigma_engine,
        )
        report_path = self.reporter.save_report(analysis_id, report)
        report["report_path"] = str(report_path)
        return report

    def run_analysis(
        self,
        sample_path: Optional[str] = None,
        arguments: str = "",
        timeout_seconds: Optional[int] = None,
        on_step: Optional[Callable[..., None]] = None,
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
    ) -> Dict[str, Any]:
        """
        Run a sample inside the existing VM and return a structured report.

        Steps:
          1. Ensure clean snapshot exists.
          2. Restore snapshot.
          3. Start VM and wait for IP.
          4. Copy telemetry agent into VM.
          5. Initialize telemetry (install Sysmon, clear log, record baseline).
          6. Copy sample into VM.
          7. Execute sample.
          8. Collect telemetry JSONL from VM.
          9. Stop VM and leave it restored (ready for next run).

        on_step, if given, is called as on_step(step_name, **context) right
        before each lifecycle step starts. Exceptions raised by on_step are
        swallowed — a broken progress callback must never break an analysis.
        Optional so every existing caller (the /api/analyze route,
        run_injection_harness.ps1's inline `python -c`) is unaffected.

        sample_type/sample_filename/launcher_path/launcher_arguments/
        destination_filename/working_directory_in_vm/url/url_mode/
        execution_error(_detail) are produced by orchestrator/sample_types.py
        (see main.py's submission handling) for non-EXE formats.
        sample_filename is the original/resolved name (e.g. a ZIP entry's
        name) used for the report's sample.filename -- sample_path itself is
        always the SHA256-keyed host storage path, never a human-readable
        name (see samples.py::store_sample), so without this the report
        would show a bare hash instead of a filename. All of these default
        to values that reproduce today's exact raw-EXE-launch behavior when
        omitted, so existing callers passing only
        sample_path/arguments/timeout_seconds are unaffected.
        execution_error set means sample_types.py already determined dynamic
        execution can't proceed (e.g. an ambiguous-entry-point DLL) --
        short-circuits before any VM boot.

        interactive=True launches the sample on the VISIBLE console session
        (scheduled task, interactive token as the logged-on user) instead of
        the non-interactive PSDirect session, so UI-driven samples (message
        boxes, installers) can be watched and clicked via the browser
        console. Behavior differs from corpus runs (different parent chain,
        no process dumps) -- such reports are tagged interactive_launch and
        are not comparable to the corpus baseline.
        """

        def _step(name: str, **ctx: Any) -> None:
            if on_step is None:
                return
            try:
                on_step(name, **ctx)
            except Exception:
                pass

        analysis_id = str(uuid.uuid4())
        analysis_started_at = datetime.now(timezone.utc)
        _step("started", analysis_id=analysis_id)

        # Full static analysis (YARA-10.7k + capa subprocess) runs on a
        # background thread overlapping VM boot + the whole guest window --
        # it's pure host-side work on the uploaded file. One analysis at a
        # time (serial job queue), yara-python releases the GIL during scans,
        # capa/signature checks are subprocesses. Joined via _static_result()
        # at the final report build (and the exception path below).
        static_holder: Dict[str, Any] = {}
        static_thread: Optional[threading.Thread] = None
        if sample_path is not None and execution_error is None:
            def _static_worker() -> None:
                try:
                    static_holder["res"] = self.static_analyzer.analyze(sample_path)
                except Exception as exc:
                    static_holder["res"] = {"error": str(exc)}

            static_thread = threading.Thread(target=_static_worker, daemon=True)
            static_thread.start()

        def _static_result() -> Dict[str, Any]:
            if static_thread is None:
                return {}
            static_thread.join()
            return static_holder.get("res", {"error": "static worker produced no result"})

        if execution_error is not None:
            return self._build_execution_error_report(
                analysis_id=analysis_id,
                sample_path=sample_path,
                sample_type=sample_type,
                execution_error=execution_error,
                execution_error_detail=execution_error_detail,
                url=url,
                url_mode=url_mode,
                sample_filename=sample_filename,
            )

        timeout = timeout_seconds or self.config.analysis.get("default_timeout_seconds", 120)
        # Adaptive detonation window: stop a traced sample early once its
        # apitrace goes silent past the minimum window (staller class), and
        # track the whole sample tree for exit. See analysis.adaptive_window
        # in config.yaml.
        aw_cfg = self.config.analysis.get("adaptive_window", {}) or {}
        aw_enabled = bool(aw_cfg.get("enabled", False))
        vm_name = self.config.hyperv["analysis_vm"]
        agent_dir_host = self._agent_dir_host()
        guest_agent_dir = self.telemetry_cfg.get("guest_agent_dir", "C:\\SandboxAgent")
        guest_output_file = self.telemetry_cfg.get("guest_output_file", "C:\\SandboxAgent\\telemetry.jsonl")
        logs_dir = Path(self.config.paths.get("logs_dir", "logs"))
        host_telemetry_path = logs_dir / f"{analysis_id}.jsonl"

        error = None
        events: List[Dict[str, Any]] = []
        vm_ip: Optional[str] = None
        execution_info: Dict[str, Any] = {}
        runtime_seconds = 0.0

        net_cfg = self.config.network_capture
        network_capture_enabled = net_cfg.get("enabled", False)
        capture_started = False
        network_capture_info: Dict[str, Any] = {"enabled": network_capture_enabled}
        host_pcapng_path = logs_dir / f"{analysis_id}.pcapng"

        scr_cfg = self.config.screenshots
        screenshots_enabled = scr_cfg.get("enabled", False)
        screenshots_dir = logs_dir / f"{analysis_id}_screenshots"
        screenshot_results: List[Dict[str, Any]] = []
        screenshot_stop_event = threading.Event()
        screenshot_thread: Optional[threading.Thread] = None

        pd_cfg = self.config.process_dumps
        process_dumps_enabled = pd_cfg.get("enabled", False)
        host_dumps_dir = logs_dir / f"{analysis_id}_dumps"
        process_dumps_info: Dict[str, Any] = {"enabled": process_dumps_enabled}

        df_cfg = self.config.dropped_files
        dropped_files_enabled = df_cfg.get("enabled", False)
        host_dropped_files_dir = logs_dir / f"{analysis_id}_dropped_files"
        dropped_files_info: Dict[str, Any] = {"enabled": dropped_files_enabled}

        bt_cfg = self.config.behavioral_tracing
        behavioral_tracing_enabled = bt_cfg.get("enabled", False)
        apitrace_started = False
        apitrace_collector_pid = 0
        apitrace_guest_file = bt_cfg.get("guest_apitrace_file", "C:\\SandboxAgent\\apitrace.jsonl")
        apitrace_stop_file = bt_cfg.get("guest_stop_file", "C:\\SandboxAgent\\apitrace_stop.flag")

        # SandboxGuard kernel guardian (protect/verify/place). Fails open:
        # if the driver is absent in the guest, guardian_agent emits a
        # GuardianUnavailable meta event and exits -- the run is unaffected.
        g_cfg = self.config.guardian
        guardian_enabled = g_cfg.get("enabled", False)
        guardian_started = False
        guardian_agent_pid = 0
        guardian_guest_file = g_cfg.get("guest_output_file", "C:\\SandboxAgent\\guardian.jsonl")
        guardian_stop_file = g_cfg.get("guest_stop_file", "C:\\SandboxAgent\\guardian_stop.flag")

        sec_cfg = self.config.sample_execution
        guest_destination_folder = sec_cfg.get("guest_destination_folder", "C:\\Sandbox")

        start_time = time.time()
        try:
            # 1. Make sure the clean snapshot exists (one-time operation)
            _step("ensure_snapshot")
            self.hv.ensure_snapshot()

            # 2. Revert to clean state
            _step("restore_snapshot")
            self.hv.restore_snapshot()

            # 3. Start VM
            _step("start_vm")
            vm_startup_timeout = self.config.analysis.get("vm_startup_timeout_seconds", 240)
            start_result = self.hv.start_vm(timeout_seconds=vm_startup_timeout)
            vm_ip = start_result.get("IPAddress")

            if not vm_ip:
                raise RuntimeError("VM started but did not acquire an IP address")

            # 4. Copy telemetry agent into VM
            _step("copy_agent")
            self.hv.copy_agent(agent_source_dir=agent_dir_host, destination_dir=guest_agent_dir)

            # 4b. Defender/AMSI readiness gate. A freshly-booted Defender can
            # report enabled while its signatures are still loading, during which
            # AMSI scans return clean and AMSI-based detection silently misses
            # (~1-in-10 amsi runs). Wait (bounded) until Defender actually blocks
            # the AMSI test string. Runs BEFORE telemetry_init so the probe's own
            # AMSI/Defender events stay out of the sample's telemetry window.
            # Non-fatal -- we proceed either way but record the outcome so a run
            # where AMSI never armed is visible instead of a silent miss.
            defender_readiness = None
            dr_timeout = self.config.analysis.get("defender_readiness_timeout_seconds", 0)
            if dr_timeout and dr_timeout > 0:
                _step("defender_ready")
                try:
                    dr_result = self.hv.invoke_guest_python(
                        "defender_manager.py", f"wait-ready {int(dr_timeout)}", agent_dir=guest_agent_dir
                    )
                    defender_readiness = {
                        "ready": dr_result.get("ExitCode") == 0,
                        "detail": (dr_result.get("Output") or "").strip()[-600:],
                    }
                except Exception as exc:
                    defender_readiness = {"ready": None, "detail": f"readiness check failed: {exc}"}

            # 5. Initialize telemetry
            _step("telemetry_init")
            self.hv.telemetry_init(agent_dir=guest_agent_dir, sources=self._sources_str())

            # 6. Copy sample (skipped for URL submissions -- there's no
            # local file; the launcher targets the URL directly)
            sample_dest: Optional[str] = None
            if sample_path is not None:
                _step("copy_sample")
                sample_dest = self.hv.copy_sample(
                    sample_path,
                    destination_folder=guest_destination_folder,
                    destination_filename=destination_filename,
                )

            # 7. Start network capture before the sample runs
            if network_capture_enabled:
                _step("network_capture_start")
                try:
                    self.hv.network_capture_start(
                        agent_dir=guest_agent_dir,
                        output_dir=net_cfg.get("guest_output_dir", guest_agent_dir),
                        etl_filename=net_cfg.get("etl_filename", "network.etl"),
                        pcapng_filename=net_cfg.get("pcapng_filename", "network.pcapng"),
                        max_file_size_mb=net_cfg.get("max_file_size_mb", 256),
                        snaplen_bytes=net_cfg.get("snaplen_bytes", 0),
                        components=net_cfg.get("components", "all"),
                    )
                    capture_started = True
                    network_capture_info["started"] = True
                except Exception as exc:
                    network_capture_info["started"] = False
                    network_capture_info["error"] = f"Failed to start network capture: {exc}"

            # 7b. Start periodic VM screenshots before the sample runs
            if screenshots_enabled:
                _step("screenshot_capture_start")
                screenshots_dir.mkdir(parents=True, exist_ok=True)
                screenshot_thread = threading.Thread(
                    target=self._screenshot_loop,
                    args=(
                        screenshot_stop_event,
                        screenshots_dir,
                        scr_cfg.get("interval_seconds", 10),
                        scr_cfg.get("width_pixels", 320),
                        scr_cfg.get("height_pixels", 240),
                        scr_cfg.get("max_screenshots", 60),
                        screenshot_results,
                    ),
                    daemon=True,
                )
                screenshot_thread.start()

            # 7c. Start the API-trace collector before the sample runs (Track 3).
            # Mirrors network capture's start-before/stop-after lifecycle, but
            # the collector is a long-lived guest process (not a kernel
            # session), so start returns its PID for the stop step to target.
            apitrace_start_error: Optional[str] = None
            if behavioral_tracing_enabled:
                _step("apitrace_start")
                try:
                    at_result = self.hv.apitrace_start(
                        agent_dir=guest_agent_dir,
                        output_file=apitrace_guest_file,
                        stop_file=apitrace_stop_file,
                        max_seconds=max(timeout + 60, 120),
                    )
                    apitrace_started = True
                    apitrace_collector_pid = at_result.get("CollectorPid", 0)
                except Exception as exc:
                    apitrace_start_error = f"Failed to start API-trace collector: {exc}"

            # 7d. Start the guardian agent before the sample runs (kernel
            # protection + pre-entry injection placement). Target image = the
            # monitor LOADER (the true root of the traced sample tree): the
            # driver marks it pre-entry and lineage-follows every descendant,
            # so the sample + its children are placed even through
            # direct-syscall spawns. Do NOT target the sample/launcher image
            # (e.g. powershell.exe) -- that also matches the sandbox's own
            # tooling processes created mid-run (Execute-Sample host etc.),
            # and injecting the monitor into those intermittently broke the
            # loader launch (CreateProcess access-denied via the tooling
            # monitor's own child-following hook). Double-placement with the
            # loader is harmless (LoadLibrary refcounted, DllMain runs once).
            guardian_start_error: Optional[str] = None
            if guardian_enabled:
                _step("guardian_start")
                try:
                    if behavioral_tracing_enabled:
                        loader = bt_cfg.get("guest_loader_path", "")
                        target_image = loader.replace("/", "\\").rsplit("\\", 1)[-1] if loader else ""
                    else:
                        target_image = ""
                    g_result = self.hv.guardian_start(
                        agent_dir=guest_agent_dir,
                        output_file=guardian_guest_file,
                        stop_file=guardian_stop_file,
                        max_seconds=max(timeout + 60, 120),
                        target_image=target_image if behavioral_tracing_enabled else "",
                        dll_x64=bt_cfg.get("guest_dll_path", "") if behavioral_tracing_enabled else "",
                        dll_x86=bt_cfg.get("guest_dll_path", "").replace("monitor_x64.dll", "monitor_x86.dll")
                        if behavioral_tracing_enabled and bt_cfg.get("guest_dll_path") else "",
                    )
                    guardian_started = True
                    guardian_agent_pid = g_result.get("AgentPid", 0)
                except Exception as exc:
                    guardian_start_error = f"Failed to start guardian agent: {exc}"

            # 8. Execute sample
            _step("execute_sample")
            if interactive:
                # Interactive launch: scheduled task on the visible console
                # session (see run_analysis docstring). The guest-side merge
                # of launcher_arguments + arguments that Execute-Sample does
                # is mirrored here.
                merged_args = " ".join(p for p in (launcher_arguments, arguments) if p)
                execution_info = self.hv.execute_sample_interactive(
                    launcher_path=launcher_path or sample_dest,
                    launcher_arguments=merged_args,
                    working_directory=working_directory_in_vm,
                    timeout_seconds=timeout,
                    behavioral_tracing=behavioral_tracing_enabled,
                    monitor_dll_path=bt_cfg.get("guest_dll_path"),
                    monitor_loader_path=bt_cfg.get("guest_loader_path"),
                    monitor_pid_file=bt_cfg.get("guest_pid_file"),
                    agent_dir=guest_agent_dir,
                )
                process_dumps_info["enabled"] = False
                process_dumps_info["note"] = "process dumps are not taken in interactive mode"
                execution_info["interactive_launch"] = True
            else:
                execution_info = self.hv.execute_sample(
                    sample_path_in_vm=sample_dest,
                    arguments=arguments,
                    timeout_seconds=timeout,
                    dumps_dir=pd_cfg.get("guest_output_dir", "C:\\SandboxAgent\\dumps"),
                    dump_interval_seconds=pd_cfg.get("dump_interval_seconds", 15),
                    max_dumps=pd_cfg.get("max_dumps", 5),
                    max_working_set_bytes=pd_cfg.get("max_working_set_mb", 500) * 1024 * 1024,
                    poll_interval_ms=pd_cfg.get("poll_interval_ms", 250),
                    launcher_path=launcher_path,
                    launcher_arguments=launcher_arguments,
                    working_directory=working_directory_in_vm,
                    behavioral_tracing=behavioral_tracing_enabled,
                    monitor_dll_path=bt_cfg.get("guest_dll_path"),
                    monitor_loader_path=bt_cfg.get("guest_loader_path"),
                    monitor_pid_file=bt_cfg.get("guest_pid_file"),
                    monitor_pid_wait_seconds=bt_cfg.get("monitor_pid_wait_seconds"),
                    adaptive_min_window_seconds=(
                        aw_cfg.get("min_window_seconds", 45) if aw_enabled else 0
                    ),
                    adaptive_idle_grace_seconds=aw_cfg.get("idle_grace_seconds", 30),
                    activity_file_path=(
                        apitrace_guest_file if (aw_enabled and behavioral_tracing_enabled) else ""
                    ),
                )
            # Surface the pre-launch Defender/AMSI readiness result alongside the
            # execution record so the report shows whether AMSI was armed.
            if defender_readiness is not None:
                execution_info["defender_readiness"] = defender_readiness
            if apitrace_start_error is not None:
                execution_info["apitrace_start_error"] = apitrace_start_error
            if guardian_start_error is not None:
                execution_info["guardian_start_error"] = guardian_start_error
            if guardian_enabled:
                execution_info["guardian_requested"] = True
            if behavioral_tracing_enabled:
                execution_info["behavioral_tracing_requested"] = True

            # 8a. Stop the API-trace collector so apitrace.jsonl is fully
            # flushed/closed BEFORE telemetry_collect reads it below. Must run
            # even if execute_sample's traced launch degraded (no child pid
            # found) -- the collector may still hold useful events (e.g. just
            # the hello/attach) and must be torn down regardless.
            if apitrace_started:
                _step("apitrace_stop")
                try:
                    at_stop = self.hv.apitrace_stop(
                        collector_pid=apitrace_collector_pid,
                        stop_file=apitrace_stop_file,
                        wait_seconds=bt_cfg.get("collector_stop_wait_seconds", 8),
                    )
                    execution_info["apitrace_stop"] = at_stop
                except Exception as exc:
                    execution_info["apitrace_stop_error"] = f"Failed to stop API-trace collector: {exc}"

            # 8a-ii. Stop the guardian agent so guardian.jsonl is flushed and
            # the driver is back to inert (CLEAR_ALL) before collect reads it.
            if guardian_started:
                _step("guardian_stop")
                try:
                    execution_info["guardian_stop"] = self.hv.guardian_stop(
                        agent_pid=guardian_agent_pid,
                        stop_file=guardian_stop_file,
                    )
                except Exception as exc:
                    execution_info["guardian_stop_error"] = f"Failed to stop guardian agent: {exc}"

            # 8b. Copy any process memory dumps off the VM and rescan them
            # with the existing static-analysis YARA engine -- this is *why*
            # dynamic unpacking matters: a packed sample's on-disk YARA scan
            # can miss signatures only visible once unpacked in memory.
            if process_dumps_enabled and not interactive:
                _step("copy_process_dumps")
                try:
                    copy_result = self.hv.copy_process_dumps(
                        host_destination_dir=str(host_dumps_dir),
                        guest_source_dir=pd_cfg.get("guest_output_dir", "C:\\SandboxAgent\\dumps"),
                    )
                    dump_items = []
                    for f in copy_result.get("Files") or []:
                        host_path = f.get("HostPath")
                        yara_matches = []
                        if host_path:
                            try:
                                yara_matches = self.static_analyzer.match_yara(Path(host_path))
                            except Exception as yara_exc:
                                yara_matches = [{"error": str(yara_exc)}]
                        dump_items.append(
                            {
                                "filename": f.get("Filename"),
                                "path": host_path,
                                "size_bytes": f.get("SizeBytes"),
                                "yara_matches": yara_matches,
                            }
                        )
                    process_dumps_info["count"] = len(dump_items)
                    process_dumps_info["items"] = dump_items
                    process_dumps_info["attempts"] = execution_info.get("ProcessDumps", [])
                    if copy_result.get("Status") != "copied":
                        process_dumps_info["error"] = copy_result.get("Status")
                except Exception as exc:
                    process_dumps_info["error"] = f"Failed to copy process dumps: {exc}"

            # 8. Wait for telemetry to settle, then collect
            _step("telemetry_collect")
            time.sleep(2)
            self.hv.telemetry_collect(
                agent_dir=guest_agent_dir,
                sources=self._sources_str(include_apitrace=apitrace_started, include_guardian=guardian_started),
            )
            self.hv.copy_telemetry(
                host_destination_path=str(host_telemetry_path),
                guest_source_path=guest_output_file,
            )
            events = self._read_telemetry_events(host_telemetry_path)

            # 8b. Retrieve any files dropped by the sample's own process tree
            if dropped_files_enabled:
                _step("copy_dropped_files")
                try:
                    sample_pid: Optional[int] = None
                    try:
                        sample_pid = int(execution_info.get("ProcessId"))
                    except (TypeError, ValueError):
                        pass
                    selected_paths = self._select_dropped_files(
                        events,
                        sample_pid,
                        guest_agent_dir,
                        df_cfg.get("max_files", 20),
                        execution_info.get("LauncherPath"),
                    )
                    dropped_items: List[Dict[str, Any]] = []
                    capa_budget = [df_cfg.get("deep_analysis_capa_max_files", 3)]
                    if selected_paths:
                        copy_result = self.hv.copy_dropped_files(
                            host_destination_dir=str(host_dropped_files_dir),
                            guest_source_paths=selected_paths,
                        )
                        max_size_bytes = df_cfg.get("max_file_size_mb", 50) * 1024 * 1024
                        for f in copy_result.get("Files") or []:
                            if f.get("Status") != "copied":
                                dropped_items.append(
                                    {
                                        "filename": f.get("Filename"),
                                        "original_path": f.get("OriginalPath"),
                                        "status": f.get("Status"),
                                        "origin": "created",
                                    }
                                )
                                continue
                            size_bytes = f.get("SizeBytes") or 0
                            host_path = f.get("HostPath")
                            if size_bytes > max_size_bytes:
                                dropped_items.append(
                                    {
                                        "filename": f.get("Filename"),
                                        "original_path": f.get("OriginalPath"),
                                        "status": "skipped_too_large",
                                        "size_bytes": size_bytes,
                                        "origin": "created",
                                    }
                                )
                                try:
                                    Path(host_path).unlink()
                                except Exception:
                                    pass
                                continue
                            item: Dict[str, Any] = {
                                "filename": f.get("Filename"),
                                "original_path": f.get("OriginalPath"),
                                "path": host_path,
                                "size_bytes": size_bytes,
                                "status": "retrieved",
                                "origin": "created",
                            }
                            self._analyze_retrieved_file(item, host_path, df_cfg, capa_budget)
                            dropped_items.append(item)
                        if copy_result.get("Status") != "copied":
                            dropped_files_info["error"] = copy_result.get("Status")

                    # 8c. Sysmon deleted-file archive: content of files the
                    # sample created AND deleted survives in the guest's
                    # ArchiveDirectory (SYSTEM-ACL-protected, staged via a
                    # SYSTEM scheduled task in Copy-SandboxArchiveFromVM).
                    # Archived filenames are the configured hash algorithms
                    # joined + original extension (NOT a fixed 'ALGO=hash'
                    # form), so matching is by hash-substring on the filename
                    # followed by content-hash verification against the
                    # sample-lineage FileDelete events. Closes the
                    # self-cleaning-dropper blind spot (drop -> run -> delete
                    # used to lose the payload entirely).
                    if df_cfg.get("retrieve_deleted_archive", True):
                        _step("copy_sandbox_archive")
                        deletions = self._select_archive_deletions(
                            events,
                            sample_pid,
                            df_cfg.get("max_archive_files", 20),
                            execution_info.get("LauncherPath"),
                        )
                        if deletions:
                            # Deterministic archive names: '<md5><sha256><ext>'
                            # (uppercase hex, no separators) under our config's
                            # md5+sha256 HashAlgorithms; single-hash forms as
                            # fallback if the hash config ever changes.
                            archive_dir = df_cfg.get("guest_archive_dir", "C:\\SandboxArchive")
                            by_deleted_path: Dict[str, List[Dict[str, str]]] = {}
                            for d in deletions:
                                by_deleted_path.setdefault(d["deleted_path"], []).append(d)
                            candidates: List[str] = []
                            cand_map: Dict[str, Dict[str, str]] = {}  # leaf name -> deletion
                            for deleted_path, dlist in by_deleted_path.items():
                                ext = Path(deleted_path).suffix
                                hashes = {d["hash_algo"]: d for d in dlist}
                                names = []
                                if "md5" in hashes and "sha256" in hashes:
                                    names.append((hashes["md5"]["hash"] + hashes["sha256"]["hash"]).upper() + ext)
                                for algo in ("sha256", "md5"):
                                    if algo in hashes:
                                        names.append(hashes[algo]["hash"].upper() + ext)
                                for name in names:
                                    if name not in cand_map:
                                        # verify against sha256 when present
                                        cand_map[name] = hashes.get("sha256") or hashes.get("md5")
                                        candidates.append(archive_dir + "\\" + name)
                            arch_result = self.hv.copy_sandbox_archive(
                                host_destination_dir=str(host_dropped_files_dir / "archive"),
                                guest_file_candidates=candidates,
                            )
                            if arch_result.get("Status") != "copied":
                                dropped_files_info["archive_error"] = arch_result.get("Status")
                            max_size_bytes = df_cfg.get("max_file_size_mb", 50) * 1024 * 1024
                            retrieved_hashes = set()
                            for f in arch_result.get("Files") or []:
                                host_path = f.get("HostPath")
                                leaf = f.get("Filename") or ""
                                if not host_path:
                                    continue
                                match = cand_map.get(leaf.upper()) or cand_map.get(leaf)
                                if match is None:
                                    # staged but not one of ours (name-collision
                                    # safety net): drop it
                                    Path(host_path).unlink(missing_ok=True)
                                    continue
                                try:
                                    data = Path(host_path).read_bytes()
                                except Exception:
                                    continue
                                # Verify content hash against the FileDelete
                                # event's -- never trust the filename form.
                                actual = hashlib.new(match["hash_algo"], data).hexdigest().lower()
                                if actual != match["hash"]:
                                    Path(host_path).unlink(missing_ok=True)
                                    continue
                                if match["hash"] in retrieved_hashes:
                                    Path(host_path).unlink(missing_ok=True)
                                    continue  # same content archived twice
                                retrieved_hashes.add(match["hash"])
                                if len(data) > max_size_bytes:
                                    Path(host_path).unlink(missing_ok=True)
                                    dropped_items.append(
                                        {
                                            "filename": f.get("Filename"),
                                            "original_path": match["deleted_path"],
                                            "status": "skipped_too_large",
                                            "size_bytes": len(data),
                                            "origin": "sysmon_archive",
                                        }
                                    )
                                    continue
                                item = {
                                    "filename": f.get("Filename"),
                                    "original_path": match["deleted_path"],
                                    "path": host_path,
                                    "size_bytes": len(data),
                                    "status": "retrieved",
                                    "origin": "sysmon_archive",
                                }
                                self._analyze_retrieved_file(item, host_path, df_cfg, capa_budget)
                                dropped_items.append(item)

                    dropped_files_info["count"] = len(
                        [i for i in dropped_items if i.get("status") == "retrieved"]
                    )
                    dropped_files_info["items"] = dropped_items
                except Exception as exc:
                    dropped_files_info["error"] = f"Failed to retrieve dropped files: {exc}"

        except Exception as exc:
            error = str(exc)
            raise
        finally:
            runtime_seconds = time.time() - start_time

            # 8c. Stop periodic screenshot capture
            if screenshot_thread is not None:
                _step("screenshot_capture_stop")
                screenshot_stop_event.set()
                screenshot_thread.join(timeout=10)

            # 9. Stop network capture and copy PCAPNG off the VM
            if network_capture_enabled and capture_started:
                _step("network_capture_stop")
                try:
                    self.hv.network_capture_stop(
                        agent_dir=guest_agent_dir,
                        output_dir=net_cfg.get("guest_output_dir", guest_agent_dir),
                        etl_filename=net_cfg.get("etl_filename", "network.etl"),
                        pcapng_filename=net_cfg.get("pcapng_filename", "network.pcapng"),
                    )
                    copy_result = self.hv.copy_network_capture(
                        host_destination_path=str(host_pcapng_path),
                        guest_source_path=str(
                            Path(net_cfg.get("guest_output_dir", guest_agent_dir))
                            / net_cfg.get("pcapng_filename", "network.pcapng")
                        ),
                    )
                    network_capture_info.update(copy_result)
                except Exception as exc:
                    existing = network_capture_info.get("error")
                    network_capture_info["error"] = (
                        f"{existing}; " if existing else ""
                    ) + f"Failed to stop/copy network capture: {exc}"

            # 10. Stop VM (turn off)
            _step("stop_vm")
            try:
                self.hv.stop_vm(force=True)
            except Exception as stop_exc:
                if error is None:
                    error = f"Analysis succeeded but failed to stop VM: {stop_exc}"

        # ETW-TI is configured as a gap-filler source but etw_ti_collector.py's
        # collect() always returns an empty list (ETL decoding not yet
        # implemented) -- make that visible in the report instead of a
        # silent absence.
        if "etw_ti" in self.telemetry_cfg.get("sources", []):
            execution_info["etw_ti_status"] = "not_implemented"

        # Build sample metadata with static analysis results. URL
        # submissions have no local file to analyze -- for fetch-mode, the
        # actually-downloaded payload's identity surfaces under
        # dropped_files instead (curl.exe is the launched process, so its
        # own download is captured by the existing dropped-file PID-lineage
        # retrieval; no separate download-handling code needed).
        if sample_path is not None:
            sample_file = Path(sample_path)
            # The background static-analysis thread started at run-entry has
            # had the whole VM window to finish; join it here instead of
            # re-running analyze() serially.
            static_results = _static_result()

            sample_metadata = {
                "id": analysis_id,
                # sample_path is the SHA256-keyed host storage path (see
                # samples.py::store_sample) -- sample_filename is the
                # original/resolved name (e.g. from a ZIP entry) and must
                # be preferred when given, or the report would show a bare
                # hash instead of a filename.
                "filename": sample_filename or sample_file.name,
                "size": sample_file.stat().st_size,
                "hashes": static_results.get("hashes", {}),
                "tags": [],
                "sample_type": sample_type,
                "static_analysis": static_results,
            }
        else:
            static_results = {}
            sample_metadata = {
                "id": analysis_id,
                "filename": url or "unknown",
                "size": None,
                "hashes": {},
                "tags": [],
                "sample_type": sample_type,
                "url": url,
                "url_mode": url_mode,
                "static_analysis": static_results,
            }

        screenshots_info: Dict[str, Any] = {
            "enabled": screenshots_enabled,
            "interval_seconds": scr_cfg.get("interval_seconds", 10),
            "count": len([r for r in screenshot_results if "path" in r]),
            "items": screenshot_results,
        }

        report = self.reporter.build_report(
            analysis_id=analysis_id,
            sample_metadata=sample_metadata,
            vm_name=vm_name,
            vm_ip=vm_ip,
            runtime_seconds=round(runtime_seconds, 2),
            telemetry_events=events,
            static_analysis=static_results,
            network_capture=network_capture_info,
            screenshots=screenshots_info,
            process_dumps=process_dumps_info,
            dropped_files=dropped_files_info,
            execution_info=execution_info,
            status="completed" if error is None else "failed",
            error=error,
            sigma_engine=self.sigma_engine,
        )

        report["interactive_launch"] = bool(interactive)
        try:
            from orchestrator.console import get_console_manager
            console_mgr = get_console_manager(create=False)
            if console_mgr is not None and console_mgr.used_between(analysis_started_at, datetime.now(timezone.utc)):
                report["interactive_console"] = True
        except Exception:
            pass  # tagging must never fail the report

        report_path = self.reporter.save_report(analysis_id, report)
        report["report_path"] = str(report_path)
        return report
