"""Hyper-V VM lifecycle manager (snapshot-based, existing VM only).

This module wraps the PowerShell helper (scripts/hyperv-vm.ps1) so the Python
orchestrator can start, revert, and stop an existing sandbox VM. It explicitly
never creates or deletes VMs.
"""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from orchestrator.config import SandboxConfig


class HyperVManager:
    def __init__(self, config: SandboxConfig):
        self.config = config
        self.vm_name = config.hyperv["analysis_vm"]
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
            "Restart-Guest",
            "Console-InputServer-Start",
            "Console-InputServer-Stop",
            "Execute-Sample-Interactive",
        }
        vm_username = self.config.hyperv.get("vm_username")
        vm_password = self.config.hyperv.get("vm_password")
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

    def get_status(self) -> Dict[str, Any]:
        return self._run_ps("Get-Status")

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
