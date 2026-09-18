"""Hyper-V VM lifecycle manager (snapshot-based, existing VM only).

This module wraps the PowerShell helper (scripts/hyperv-vm.ps1) so the Python
orchestrator can start, revert, and stop an existing sandbox VM. It explicitly
never creates or deletes VMs.
"""

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from orchestrator.config import SandboxConfig

# Guest-health probe cache (module-level: main.py builds a fresh HyperVManager
# per request, so instance state would never survive between /api/vm/status
# polls). Keyed by VM name so the fleet endpoint can probe several VMs. The
# dashboard polls every few seconds while a PSDirect probe costs ~1-3s, so
# probes are refreshed at most every TTL seconds per VM.
_GUEST_HEALTH_CACHE: Dict[str, Dict[str, Any]] = {}
GUEST_HEALTH_TTL_SECONDS = 30.0

# Local instrumentation probe cache: the probe is a ~1.7s powershell.exe spawn
# (script load + CIM + Get-MpComputerStatus) and the fleet page polls every
# 10s -- cache it the same way. Staleness is display-only; every detonation
# re-verifies its own environment at run time.
_LOCAL_STATUS_CACHE: Dict[str, Any] = {"ts": 0.0, "data": None}
LOCAL_STATUS_TTL_SECONDS = 30.0

# Host VM inventory cache: Get-FleetVMs is a ~2s powershell.exe spawn (script
# load + Hyper-V module + Get-VM) and the fleet page polls every 10s.
_FLEET_VMS_CACHE: Dict[str, Any] = {"ts": 0.0, "data": None}
FLEET_VMS_TTL_SECONDS = 15.0


class HyperVManager:
    def __init__(self, config: SandboxConfig, vm_name: Optional[str] = None):
        self.config = config
        # Fleet provisioning/status can target any registered VM; the
        # analysis default remains config.hyperv.analysis_vm.
        self.vm_name = vm_name or config.hyperv["analysis_vm"]
        self.snapshot_name = config.hyperv.get("snapshot_name", "SANDBOX-CLEAN")
        self.script_path = Path(config.paths["scripts_dir"]) / "hyperv-vm.ps1"
        if not self.script_path.exists():
            raise FileNotFoundError(f"Hyper-V PowerShell script not found: {self.script_path}")

    def _run_ps(self, command: str, **params) -> Dict[str, Any]:
        """Execute a function in the PowerShell helper and parse JSON output."""
        args = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(self.script_path), command]

        # Always inject VM name from config unless explicitly overridden
        if "VMName" not in params:
            params["VMName"] = self.vm_name

        # Inject guest credentials for PowerShell Direct if configured.
        # Only commands that talk to the guest OS need credentials.
        commands_needing_credentials = {
            "Copy-Sample",
            "Copy-SampleFolder",
            "Execute-Sample",
            "Copy-Agent",
            "Telemetry-Init",
            "Telemetry-Collect",
            "Copy-Telemetry",
            "NetworkCapture-Start",
            "NetworkCapture-Stop",
            "Apitrace-Start",
            "Apitrace-Stop",
            "Guardian-Start",
            "Guardian-Stop",
            "Copy-NetworkCapture",
            "Copy-ProcessDumps",
            "Copy-DroppedFiles",
            "Copy-SandboxArchive",
            "Clear-SandboxArchive",
            "Invoke-GuestPython",
            "Get-GuestHealth",
            "Get-TelemetryTail",
            "Restart-Guest",
            "Console-InputServer-Start",
            "Console-InputServer-Stop",
            "Execute-Sample-Interactive",
        }
        vm_username, vm_password = self.config.vm_creds(params.get("VMName", self.vm_name))
        if command in commands_needing_credentials and vm_username and vm_password:
            if "CredentialUsername" not in params:
                params["CredentialUsername"] = vm_username
            if "CredentialPassword" not in params:
                params["CredentialPassword"] = vm_password

        for key, value in params.items():
            if value is None:
                continue
            if isinstance(value, bool):
                if value:
                    args.append(f"-{key}")
            else:
                args.append(f"-{key}")
                args.append(str(value))

        result = subprocess.run(args, capture_output=True, text=True, shell=False)
        if result.returncode != 0:
            raise RuntimeError(f"PowerShell command '{command}' failed: {result.stderr}")

        stdout = result.stdout.strip()
        if not stdout:
            return {}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Failed to parse PowerShell output: {stdout}") from exc

    def ensure_snapshot(self) -> Dict[str, Any]:
        """Create the clean snapshot if it does not exist."""
        return self._run_ps(
            "Ensure-Snapshot",
            SnapshotName=self.snapshot_name,
        )

    def restore_snapshot(self) -> Dict[str, Any]:
        """Revert VM to the clean snapshot."""
        return self._run_ps(
            "Restore-Snapshot",
            SnapshotName=self.snapshot_name,
        )

    def start_vm(self, timeout_seconds: Optional[int] = None) -> Dict[str, Any]:
        if timeout_seconds is None:
            timeout_seconds = self.config.analysis.get("vm_startup_timeout_seconds", 240)
        return self._run_ps("Start-VM", TimeoutSeconds=timeout_seconds)

    def stop_vm(self, force: bool = True) -> Dict[str, Any]:
        return self._run_ps("Stop-VM", Force=force)

    def invoke_guest_python(
        self, script_name: str, script_args: str = "", agent_dir: str = "C:\\SandboxAgent"
    ) -> Dict[str, Any]:
        """Run a python script from the guest agent dir (for one-off
        provisioning steps), returning {ExitCode, Output}."""
        return self._run_ps(
            "Invoke-GuestPython",
            ScriptName=script_name,
            ScriptArgs=script_args,
            AgentDir=agent_dir,
        )

    def restart_guest(self, timeout_seconds: int = 300) -> Dict[str, Any]:
        """Reboot the guest OS and wait until it responds again."""
        return self._run_ps("Restart-Guest", TimeoutSeconds=timeout_seconds)

    def recapture_snapshot(self) -> Dict[str, Any]:
        """Replace the golden snapshot in place with the VM's current state
        (new-then-swap; the VM must be running/ready when called)."""
        return self._run_ps("Recapture-Snapshot", SnapshotName=self.snapshot_name)

    def list_vms(self) -> List[Dict[str, Any]]:
        """Host-side inventory of ALL Hyper-V VMs (fleet page): name, state,
        uptime, first IPv4. Read-only, no guest contact. 15s TTL cache --
        power-state staleness is acceptable for an inventory display and the
        probe costs ~2s per spawn."""
        now = time.monotonic()
        if _FLEET_VMS_CACHE["data"] is None or (now - _FLEET_VMS_CACHE["ts"]) > FLEET_VMS_TTL_SECONDS:
            result = self._run_ps("Get-FleetVMs")
            if isinstance(result, list):
                vms = result
            else:
                vms = [result] if result else []
            _FLEET_VMS_CACHE["data"] = vms
            _FLEET_VMS_CACHE["ts"] = now
        return _FLEET_VMS_CACHE["data"]

    def get_status(self, vm_name: Optional[str] = None) -> Dict[str, Any]:
        """VM power state plus (when Running) guest instrumentation health,
        merged from the Get-GuestHealth probe with a module-level TTL cache.
        Probe failures never fail the status call: Checks stays None and
        ChecksError carries the reason (dashboard renders 'unavailable').
        vm_name defaults to the configured analysis VM; the fleet endpoint
        passes explicit names."""
        vm_name = vm_name or self.vm_name
        status = self._run_ps("Get-Status", VMName=vm_name)
        if not isinstance(status, dict):
            return status
        if status.get("State") != "Running":
            # Keep the last-known health in the cache (marked by state) so
            # the fleet detail view can show "last recorded" data; force a
            # fresh probe on the next Running transition (stale guest state
            # after a reboot is worthless).
            slot = _GUEST_HEALTH_CACHE.get(vm_name)
            if slot is not None:
                slot["state"] = status.get("State")
            status["Checks"] = None
            return status
        slot = _GUEST_HEALTH_CACHE.get(vm_name)
        now = time.monotonic()
        if (
            slot is None
            or slot.get("state") != "Running"
            or (now - slot["ts"]) > GUEST_HEALTH_TTL_SECONDS
        ):
            try:
                data = self._run_ps("Get-GuestHealth", VMName=vm_name)
            except Exception as exc:  # PSDirect down, guest wedged, ...
                data = {"Checks": None, "GuestSystem": None, "ChecksError": str(exc)}
            slot = {"ts": now, "wall": time.time(), "state": "Running", "data": data}
            _GUEST_HEALTH_CACHE[vm_name] = slot
        health = slot["data"] or {}
        status["Checks"] = health.get("Checks")
        if health.get("GuestSystem"):
            status["GuestSystem"] = health["GuestSystem"]
        if health.get("ChecksError"):
            status["ChecksError"] = health["ChecksError"]
        return status

    @staticmethod
    def last_guest_health(vm_name: str) -> Optional[Dict[str, Any]]:
        """Last recorded guest-health snapshot for the fleet detail view:
        {recorded_at (epoch), age_seconds, state_at_probe, data} or None when
        the VM was never probed this process lifetime."""
        slot = _GUEST_HEALTH_CACHE.get(vm_name)
        if slot is None:
            return None
        return {
            "recorded_at": slot.get("wall"),
            "age_seconds": round(time.monotonic() - slot["ts"], 1),
            "state_at_probe": slot.get("state"),
            "data": slot.get("data"),
        }

    def copy_sample(
        self,
        sample_path: str,
        destination_folder: str = "C:\\Sandbox",
        destination_filename: Optional[str] = None,
    ) -> str:
        result = self._run_ps(
            "Copy-Sample",
            SamplePath=sample_path,
            DestinationFolder=destination_folder,
            DestinationFileName=destination_filename,
        )
        return result.get("DestinationPath", result)

    def copy_sample_folder(
        self,
        staging_zip_path: str,
        destination_folder: str = "C:\\Sandbox",
    ) -> Dict[str, Any]:
        """Extract a staging zip (all archive entries, sanitized relative
        paths) into the guest working dir -- multi-file zip staging."""
        return self._run_ps(
            "Copy-SampleFolder",
            StagingZipPath=staging_zip_path,
            DestinationFolder=destination_folder,
        )

    def execute_sample(
        self,
        sample_path_in_vm: Optional[str] = None,
        arguments: str = "",
        timeout_seconds: int = 120,
        dumps_dir: str = "C:\\SandboxAgent\\dumps",
        dump_interval_seconds: int = 15,
        max_dumps: int = 5,
        max_working_set_bytes: int = 524288000,
        poll_interval_ms: int = 250,
        launcher_path: Optional[str] = None,
        launcher_arguments: Optional[str] = None,
        working_directory: Optional[str] = None,
        behavioral_tracing: bool = False,
        monitor_dll_path: Optional[str] = None,
        monitor_loader_path: Optional[str] = None,
        monitor_pid_file: Optional[str] = None,
        monitor_pid_wait_seconds: Optional[int] = None,
        adaptive_min_window_seconds: int = 0,
        adaptive_idle_grace_seconds: int = 45,
        activity_file_path: str = "",
        adopted_pids_file: str = "",
        min_runtime_seconds: int = 30,
    ) -> Dict[str, Any]:
        return self._run_ps(
            "Execute-Sample",
            SamplePathInVM=sample_path_in_vm,
            Arguments=arguments,
            TimeoutSeconds=timeout_seconds,
            DumpsDir=dumps_dir,
            DumpIntervalSeconds=dump_interval_seconds,
            MaxDumps=max_dumps,
            MaxWorkingSetBytes=max_working_set_bytes,
            PollIntervalMs=poll_interval_ms,
            LauncherPath=launcher_path,
            LauncherArguments=launcher_arguments,
            WorkingDirectory=working_directory,
            BehavioralTracing=behavioral_tracing,
            MonitorDllPath=monitor_dll_path,
            MonitorLoaderPath=monitor_loader_path,
            MonitorPidFile=monitor_pid_file,
            MonitorPidWaitSeconds=monitor_pid_wait_seconds,
            AdaptiveMinWindowSeconds=adaptive_min_window_seconds,
            AdaptiveIdleGraceSeconds=adaptive_idle_grace_seconds,
            ActivityFilePath=activity_file_path,
            AdoptedPidsFile=adopted_pids_file,
            MinRuntimeSeconds=min_runtime_seconds,
        )

    def apitrace_start(
        self,
        agent_dir: str = "C:\\SandboxAgent",
        output_file: str = "C:\\SandboxAgent\\apitrace.jsonl",
        stop_file: str = "C:\\SandboxAgent\\apitrace_stop.flag",
        max_seconds: int = 900,
        pids_file: str = "",
    ) -> Dict[str, Any]:
        return self._run_ps(
            "Apitrace-Start",
            AgentDir=agent_dir,
            OutputFile=output_file,
            StopFile=stop_file,
            MaxSeconds=max_seconds,
            PidsFile=pids_file,
        )

    def apitrace_stop(
        self,
        collector_pid: int = 0,
        stop_file: str = "C:\\SandboxAgent\\apitrace_stop.flag",
        wait_seconds: int = 8,
    ) -> Dict[str, Any]:
        return self._run_ps(
            "Apitrace-Stop",
            CollectorPid=collector_pid,
            StopFile=stop_file,
            WaitSeconds=wait_seconds,
        )

    def guardian_start(
        self,
        agent_dir: str = "C:\\SandboxAgent",
        output_file: str = "C:\\SandboxAgent\\guardian.jsonl",
        stop_file: str = "C:\\SandboxAgent\\guardian_stop.flag",
        max_seconds: int = 900,
        target_image: str = "",
        dll_x64: str = "",
        dll_x86: str = "",
    ) -> Dict[str, Any]:
        return self._run_ps(
            "Guardian-Start",
            AgentDir=agent_dir,
            OutputFile=output_file,
            StopFile=stop_file,
            MaxSeconds=max_seconds,
            TargetImage=target_image,
            DllX64=dll_x64,
            DllX86=dll_x86,
        )

    def guardian_stop(
        self,
        agent_pid: int = 0,
        stop_file: str = "C:\\SandboxAgent\\guardian_stop.flag",
        wait_seconds: int = 8,
    ) -> Dict[str, Any]:
        return self._run_ps(
            "Guardian-Stop",
            AgentPid=agent_pid,
            StopFile=stop_file,
            WaitSeconds=wait_seconds,
        )

    def tail_telemetry(self, path: str, offset: int = 0) -> Dict[str, Any]:
        """Incremental tail of a telemetry JSONL file (live run streaming).
        Works in both modes: PSDirect into the VM (hyperv) or in-process on
        the host (local, via the -LocalMode seam)."""
        return self._run_ps("Get-TelemetryTail", Path=path, Offset=offset)

    def copy_agent(self, agent_source_dir: str, destination_dir: str = "C:\\SandboxAgent") -> Dict[str, Any]:
        return self._run_ps(
            "Copy-Agent",
            AgentSourceDir=agent_source_dir,
            DestinationDir=destination_dir,
        )

    def telemetry_init(self, agent_dir: str = "C:\\SandboxAgent", sources: str = "sysmon") -> Dict[str, Any]:
        return self._run_ps(
            "Telemetry-Init",
            AgentDir=agent_dir,
            Sources=sources,
        )

    def telemetry_collect(self, agent_dir: str = "C:\\SandboxAgent", sources: str = "sysmon") -> Dict[str, Any]:
        return self._run_ps(
            "Telemetry-Collect",
            AgentDir=agent_dir,
            Sources=sources,
        )

    def copy_telemetry(
        self,
        host_destination_path: str,
        guest_source_path: str = "C:\\SandboxAgent\\telemetry.jsonl",
    ) -> Dict[str, Any]:
        return self._run_ps(
            "Copy-Telemetry",
            HostDestinationPath=host_destination_path,
            GuestSourcePath=guest_source_path,
        )

    def network_capture_start(
        self,
        agent_dir: str = "C:\\SandboxAgent",
        output_dir: str = "C:\\SandboxAgent",
        etl_filename: str = "network.etl",
        pcapng_filename: str = "network.pcapng",
        max_file_size_mb: int = 256,
        snaplen_bytes: int = 0,
        components: str = "all",
    ) -> Dict[str, Any]:
        return self._run_ps(
            "NetworkCapture-Start",
            AgentDir=agent_dir,
            OutputDir=output_dir,
            EtlFilename=etl_filename,
            PcapngFilename=pcapng_filename,
            MaxFileSizeMB=max_file_size_mb,
            SnaplenBytes=snaplen_bytes,
            Components=components,
        )

    def network_capture_stop(
        self,
        agent_dir: str = "C:\\SandboxAgent",
        output_dir: str = "C:\\SandboxAgent",
        etl_filename: str = "network.etl",
        pcapng_filename: str = "network.pcapng",
    ) -> Dict[str, Any]:
        return self._run_ps(
            "NetworkCapture-Stop",
            AgentDir=agent_dir,
            OutputDir=output_dir,
            EtlFilename=etl_filename,
            PcapngFilename=pcapng_filename,
        )

    def copy_network_capture(
        self,
        host_destination_path: str,
        guest_source_path: str = "C:\\SandboxAgent\\network.pcapng",
    ) -> Dict[str, Any]:
        return self._run_ps(
            "Copy-NetworkCapture",
            HostDestinationPath=host_destination_path,
            GuestSourcePath=guest_source_path,
        )

    def copy_process_dumps(
        self,
        host_destination_dir: str,
        guest_source_dir: str = "C:\\SandboxAgent\\dumps",
    ) -> Dict[str, Any]:
        return self._run_ps(
            "Copy-ProcessDumps",
            HostDestinationDir=host_destination_dir,
            GuestSourceDir=guest_source_dir,
        )

    def copy_dropped_files(
        self,
        host_destination_dir: str,
        guest_source_paths: List[str],
    ) -> Dict[str, Any]:
        """guest_source_paths: list of full guest-side file paths. Joined with
        "|" for the CLI hop -- see Copy-DroppedFilesFromVM's docstring for why.
        """
        return self._run_ps(
            "Copy-DroppedFiles",
            HostDestinationDir=host_destination_dir,
            GuestSourcePaths="|".join(guest_source_paths),
        )

    def copy_sandbox_archive(
        self,
        host_destination_dir: str,
        guest_file_candidates: List[str],
    ) -> Dict[str, Any]:
        """Copy selected files out of Sysmon's SYSTEM-ACL-protected deleted-
        file archive (staged via a SYSTEM scheduled task). Candidates are
        full guest paths; names are the deterministic '<md5><sha256><ext>'
        archive form computed from FileDelete event hashes host-side."""
        return self._run_ps(
            "Copy-SandboxArchive",
            HostDestinationDir=host_destination_dir,
            GuestFileCandidates="|".join(guest_file_candidates),
        )

    def clear_sandbox_archive(
        self,
        archive_dir: str = "C:\\SandboxArchive",
    ) -> Dict[str, Any]:
        """Empty Sysmon's deleted-file archive in the guest (golden-image
        hygiene). Runs as SYSTEM via a one-shot scheduled task -- the dir has
        a SYSTEM-only ACL. Returns before/after file+byte counts."""
        return self._run_ps(
            "Clear-SandboxArchive",
            ArchiveDir=archive_dir,
        )

    def capture_screenshot(
        self,
        output_path: str,
        width_pixels: int = 320,
        height_pixels: int = 240,
    ) -> Dict[str, Any]:
        """Host-side VM console screenshot via Hyper-V's WMI thumbnail API.
        No guest credentials involved -- this never touches the guest.
        """
        return self._run_ps(
            "Get-Thumbnail",
            OutputPath=output_path,
            WidthPixels=width_pixels,
            HeightPixels=height_pixels,
        )

    def console_input_server_start(
        self, agent_dir: str = "C:\\SandboxAgent", ready_timeout_seconds: int = 15
    ) -> Dict[str, Any]:
        """Start the guest console-input server in the INTERACTIVE session
        (scheduled task as the logged-on user). See
        docs/interactive-console-streaming.md."""
        return self._run_ps(
            "Console-InputServer-Start",
            AgentDir=agent_dir,
            ReadyTimeoutSeconds=ready_timeout_seconds,
        )

    def console_input_server_stop(self) -> Dict[str, Any]:
        return self._run_ps("Console-InputServer-Stop")

    def execute_sample_interactive(
        self,
        launcher_path: str,
        launcher_arguments: str = "",
        working_directory: Optional[str] = None,
        timeout_seconds: int = 120,
        behavioral_tracing: bool = False,
        monitor_dll_path: Optional[str] = None,
        monitor_loader_path: Optional[str] = None,
        monitor_pid_file: Optional[str] = None,
        agent_dir: str = "C:\\SandboxAgent",
    ) -> Dict[str, Any]:
        """Launch the sample on the VISIBLE console session (scheduled task,
        interactive token) instead of the non-interactive PSDirect session.
        Same result shape as execute_sample minus process dumps."""
        return self._run_ps(
            "Execute-Sample-Interactive",
            LauncherPath=launcher_path,
            LauncherArguments=launcher_arguments,
            WorkingDirectory=working_directory,
            TimeoutSeconds=timeout_seconds,
            BehavioralTracing=behavioral_tracing,
            MonitorDllPath=monitor_dll_path,
            MonitorLoaderPath=monitor_loader_path,
            MonitorPidFile=monitor_pid_file,
            AgentDir=agent_dir,
        )


class LocalTransport(HyperVManager):
    """Local-mode backend: the orchestrator's OWN machine is the analysis
    environment (standalone/emergency package -- see docs/local-mode.md).

    Reuses the exact same PowerShell helper and its battle-tested execution
    scriptblocks; every call just carries ``-LocalMode``, which makes the
    script invoke them locally instead of via PowerShell Direct. Only the
    VM-lifecycle surface is redefined here:

    - snapshot/VM power verbs become structured no-ops (the operator owns
      machine hygiene -- there is no rollback);
    - ``start_vm``/``get_status`` report the local machine;
    - ``copy_agent`` is a no-op (the installer owns C:\\SandboxAgent
      freshness -- a per-run wipe would also delete the agent venv and the
      runtime artifacts of the run in progress);
    - Hyper-V-only features (console thumbnails, interactive console input)
      raise loudly -- callers gate on ``config.is_local_mode`` first.
    """

    def __init__(self, config: SandboxConfig):
        # Deliberately NOT super().__init__: the hyperv: section (incl.
        # analysis_vm) may be entirely absent in a standalone deployment.
        # vm_name is always "local": this machine IS the analysis
        # environment, and reports must not inherit the hyperv section's VM
        # name when one happens to be configured alongside.
        self.config = config
        self.vm_name = "local"
        self.snapshot_name = config.hyperv.get("snapshot_name", "")
        self.script_path = Path(config.paths["scripts_dir"]) / "hyperv-vm.ps1"
        if not self.script_path.exists():
            raise FileNotFoundError(f"PowerShell helper not found: {self.script_path}")

    def _run_ps(self, command: str, **params) -> Dict[str, Any]:
        # True renders as a bare `-LocalMode` switch; the script's entrypoint
        # strips the token and flips every guest operation to local execution.
        params["LocalMode"] = True
        return super()._run_ps(command, **params)

    # -- VM lifecycle: structured no-ops ------------------------------------

    @staticmethod
    def _skipped(verb: str) -> Dict[str, Any]:
        return {"Status": "skipped", "Reason": "local-mode", "Verb": verb}

    def ensure_snapshot(self) -> Dict[str, Any]:
        return self._skipped("Ensure-Snapshot")

    def restore_snapshot(self) -> Dict[str, Any]:
        return self._skipped("Restore-Snapshot")

    def recapture_snapshot(self) -> Dict[str, Any]:
        return self._skipped("Recapture-Snapshot")

    def stop_vm(self, force: bool = True) -> Dict[str, Any]:
        return self._skipped("Stop-VM")

    def restart_guest(self, timeout_seconds: int = 300) -> Dict[str, Any]:
        return self._skipped("Restart-Guest")

    def start_vm(self, timeout_seconds: Optional[int] = None) -> Dict[str, Any]:
        # The "guest" is already running -- it's this machine. The IP is a
        # readiness signal + report field only (no comms use it).
        return {"VMName": "local", "State": "Running", "IPAddress": "127.0.0.1"}

    def get_status(self) -> Dict[str, Any]:
        # 30s TTL cache (module-level: a fresh LocalTransport is built per
        # request): the probe is a ~1.7s powershell.exe spawn and the fleet
        # page polls every 10s. Display staleness only -- detonation runs
        # re-verify their own environment.
        now = time.monotonic()
        if _LOCAL_STATUS_CACHE["data"] is None or (now - _LOCAL_STATUS_CACHE["ts"]) > LOCAL_STATUS_TTL_SECONDS:
            status = self._run_ps("Get-LocalStatus")
            if isinstance(status, dict):
                status["Mode"] = "local"
            _LOCAL_STATUS_CACHE["data"] = status
            _LOCAL_STATUS_CACHE["ts"] = now
            _LOCAL_STATUS_CACHE["wall"] = time.time()
        return _LOCAL_STATUS_CACHE["data"]

    @staticmethod
    def last_local_status() -> Optional[Dict[str, Any]]:
        """Last recorded local-status snapshot for the fleet detail view."""
        if _LOCAL_STATUS_CACHE["data"] is None:
            return None
        return {
            "recorded_at": _LOCAL_STATUS_CACHE.get("wall"),
            "age_seconds": round(time.monotonic() - _LOCAL_STATUS_CACHE["ts"], 1),
            "data": _LOCAL_STATUS_CACHE["data"],
        }

    def copy_agent(self, agent_source_dir: str, destination_dir: str = "C:\\SandboxAgent") -> Dict[str, Any]:
        # The installer deploys C:\SandboxAgent once; a per-run re-sync would
        # wipe the venv and the run's own runtime artifacts.
        return self._skipped("Copy-Agent")

    # -- Hyper-V-only features: fail loudly ---------------------------------

    def capture_screenshot(self, *args, **kwargs) -> Dict[str, Any]:
        raise RuntimeError("screenshots require the Hyper-V backend (WMI thumbnails); disabled in local mode")

    def console_input_server_start(self, *args, **kwargs) -> Dict[str, Any]:
        raise RuntimeError("interactive console requires the Hyper-V backend; disabled in local mode")

    def console_input_server_stop(self) -> Dict[str, Any]:
        return self._skipped("Console-InputServer-Stop")

    # -- Local-mode extras ----------------------------------------------------

    def clean_local_state(self) -> Dict[str, Any]:
        """Per-run hygiene (local mode has no snapshot revert): remove the
        previous run's runtime artifacts so telemetry starts clean.

        Safety: only deletes files under the CONFIGURED sandbox locations
        (agent dir / sample destination folder / process-dumps dir), and only
        known artifact names. Never touches anything else on the host.
        """
        removed: List[str] = []
        errors: List[str] = []

        agent_dir = Path(self.config.telemetry.get("guest_agent_dir", "C:\\SandboxAgent"))
        dest_folder = Path(self.config.sample_execution.get("guest_destination_folder", "C:\\Sandbox"))
        dumps_dir = Path(self.config.process_dumps.get("guest_output_dir", str(agent_dir / "dumps")))

        # Exact known artifact files (under the agent dir)
        bt = self.config.behavioral_tracing
        g = self.config.guardian
        net = self.config.network_capture
        artifact_files = [
            self.config.telemetry.get("guest_output_file", str(agent_dir / "telemetry.jsonl")),
            str(agent_dir / "telemetry_baseline.json"),
            bt.get("guest_apitrace_file", str(agent_dir / "apitrace.jsonl")),
            bt.get("guest_apitrace_file", str(agent_dir / "apitrace.jsonl")) + ".pids",
            bt.get("guest_stop_file", str(agent_dir / "apitrace_stop.flag")),
            bt.get("guest_pid_file", str(agent_dir / "sample_pid.txt")),
            g.get("guest_output_file", str(agent_dir / "guardian.jsonl")),
            g.get("guest_stop_file", str(agent_dir / "guardian_stop.flag")),
            str(Path(net.get("guest_output_dir", str(agent_dir))) / net.get("etl_filename", "network.etl")),
            str(Path(net.get("guest_output_dir", str(agent_dir))) / net.get("pcapng_filename", "network.pcapng")),
        ]

        def _under(p: Path, root: Path) -> bool:
            try:
                p.resolve().relative_to(root.resolve())
                return True
            except (ValueError, OSError):
                return False

        allowed_roots = [agent_dir, dest_folder, dumps_dir]
        for f in artifact_files:
            p = Path(f)
            if not any(_under(p, r) for r in allowed_roots):
                errors.append(f"refused (outside sandbox dirs): {p}")
                continue
            try:
                if p.is_file():
                    p.unlink()
                    removed.append(str(p))
            except OSError as exc:
                errors.append(f"{p}: {exc}")

        # Directory contents (previous run's samples, dumps, interactive run dir)
        for d in (dest_folder, dumps_dir, agent_dir / "interactive_run"):
            if not d.is_dir():
                continue
            for child in d.iterdir():
                try:
                    if child.is_dir():
                        import shutil
                        shutil.rmtree(child, ignore_errors=True)
                    else:
                        child.unlink()
                    removed.append(str(child))
                except OSError as exc:
                    errors.append(f"{child}: {exc}")

        # Sysmon deleted-file archive grows unboundedly without VM revert.
        # Previous run's harvest happens before this point in the flow, so
        # clearing here loses nothing. Non-fatal.
        try:
            self.clear_sandbox_archive()
        except Exception as exc:
            errors.append(f"clear_sandbox_archive: {exc}")

        return {"Status": "cleaned", "Removed": removed, "Errors": errors}
