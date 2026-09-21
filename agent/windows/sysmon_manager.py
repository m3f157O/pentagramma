"""Install, start, stop, and uninstall Sysmon for sandbox telemetry."""

import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import List, Optional

import proc_util


class SysmonManager:
    def __init__(self, agent_dir: Optional[Path] = None):
        self.agent_dir = Path(agent_dir) if agent_dir else Path(__file__).parent
        self.sysmon_exe = self.agent_dir / "Sysmon64.exe"
        self.config_file = self.agent_dir / "sysmonconfig.xml"

    def _find_sysmon(self) -> Path:
        if not self.sysmon_exe.exists():
            raise FileNotFoundError(
                f"Sysmon64.exe not found at {self.sysmon_exe}. "
                "Download Sysmon from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon "
                "and place Sysmon64.exe in the agent/windows directory."
            )
        return self.sysmon_exe

    def is_installed(self) -> bool:
        """Check if Sysmon service exists."""
        try:
            result = proc_util.run_text(
                ["sc", "query", "Sysmon64"],
                timeout=10,
            )
            return result.returncode == 0 and "RUNNING" in result.stdout
        except Exception:
            return False

    def install(self) -> None:
        """Install Sysmon with the bundled config."""
        exe = self._find_sysmon()
        if not self.config_file.exists():
            raise FileNotFoundError(f"Sysmon config not found: {self.config_file}")

        print(f"[sysmon] installing with config {self.config_file}")
        proc = proc_util.run_text(
            [str(exe), "-accepteula", "-i", str(self.config_file)],
            timeout=120,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip()
            raise RuntimeError(f"Sysmon install failed ({proc.returncode}): {err}")
        print("[sysmon] installed")

    def uninstall(self) -> None:
        """Uninstall Sysmon."""
        exe = self._find_sysmon()
        print("[sysmon] uninstalling")
        proc = proc_util.run_text(
            [str(exe), "-u"],
            timeout=120,
        )
        # Sysmon -u returns 0 even if partially installed
        if proc.returncode != 0 and "not installed" not in proc.stderr.lower():
            err = proc.stderr.strip() or proc.stdout.strip()
            print(f"[sysmon] uninstall warning ({proc.returncode}): {err}")
        print("[sysmon] uninstalled")

    def update_config(self) -> None:
        """Re-load the bundled Sysmon configuration (in-place update)."""
        exe = self._find_sysmon()
        if not self.config_file.exists():
            raise FileNotFoundError(f"Sysmon config not found: {self.config_file}")
        if not self.is_installed():
            self.install()
            return
        print(f"[sysmon] updating configuration from {self.config_file}")
        proc = proc_util.run_text(
            [str(exe), "-c", str(self.config_file)],
            timeout=120,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip()
            raise RuntimeError(f"Sysmon config update failed ({proc.returncode}): {err}")
        print("[sysmon] configuration updated")

    # The Sysmon Operational channel defaults to 64MB / overwrite retention.
    # A single analysis run now generates 70-90MB of events, so the oldest
    # portion of every run -- the sample's own launch chain -- was silently
    # overwritten before collection (root-caused 2026-09-21 with an in-guest
    # record-ID probe: chain events sat just behind the wrap horizon while a
    # canary written ~1MB later survived). 512MB ~= 5x the worst observed run.
    SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
    SYSMON_LOG_MAX_BYTES = 512 * 1024 * 1024

    def set_log_size(self, max_bytes: Optional[int] = None) -> None:
        """Grow the Sysmon channel so a full analysis always fits. Non-fatal
        on failure (collection still works, just with the historical wrap
        risk)."""
        size = max_bytes or self.SYSMON_LOG_MAX_BYTES
        result = proc_util.run_text(
            ["wevtutil", "sl", self.SYSMON_LOG_NAME, f"/ms:{size}"],
            timeout=30,
        )
        if result.returncode != 0:
            print(f"[sysmon] warning: could not set log size: {result.stderr.strip()}")
        else:
            print(f"[sysmon] log max size set to {size // (1024 * 1024)}MB")

    def ensure_running(self) -> None:
        """Install Sysmon if not already running."""
        if self.is_installed():
            print("[sysmon] already running")
            return
        self.install()
        # Wait for the service to start and the event log to become available
        for attempt in range(20):
            if self.is_installed():
                return
            time.sleep(0.5)
        raise RuntimeError("Sysmon service did not start after install")

    def wait_ready(self, timeout_seconds: int = 30) -> bool:
        """Prove Sysmon is CURRENTLY logging process creation before the
        sample launches. Mirrors the Defender/AMSI readiness gate: without it,
        a run can launch the sample inside a transient Sysmon blind window and
        silently lose the sample's whole process chain from telemetry
        (confirmed live 2026-09-21: the MachineGUID atomic's loader/cmd/reg
        ProcessCreate events were absent from 3/3 runs while other processes'
        events flowed; the apitrace proved the processes existed).

        Spawns a uniquely-marked canary process and polls the Sysmon log
        (last 60s) until its ProcessCreate shows up. RETRIES the spawn every
        poll -- if the first canary itself falls in the blind window, the
        next one may not. Returns True as soon as one canary is seen.
        The canary PC lands in the run's telemetry; it is a plain
        `cmd /c echo`, which matches no alert rule (EID 1 alerting is
        conditional on LOLBin/encoded patterns)."""
        from sysmon_parser import SysmonParser

        deadline = time.monotonic() + timeout_seconds
        parser = SysmonParser()
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            marker = f"sysmon-ready-{uuid.uuid4()}"
            subprocess.run(
                ["cmd.exe", "/c", "echo", marker],
                capture_output=True,
                timeout=10,
            )
            if _canary_seen(parser, marker):
                print(f"[sysmon] process-create flow confirmed (attempt {attempt})")
                return True
            time.sleep(1.0)
        print(f"[sysmon] WARNING: no canary ProcessCreate seen within {timeout_seconds}s")
        return False

    def stop(self) -> None:
        """Stop the Sysmon service without uninstalling."""
        subprocess.run(
            ["net", "stop", "Sysmon64"],
            capture_output=True,
            timeout=30,
        )

    def start(self) -> None:
        """Start the Sysmon service."""
        subprocess.run(
            ["net", "start", "Sysmon64"],
            capture_output=True,
            timeout=30,
        )


def _canary_seen(parser, marker: str, attempts: int = 3) -> bool:
    """Poll the last-60s Sysmon slice for the canary's ProcessCreate.
    Kept separate (and parser-injectable) so the matching logic is unit-
    testable without a live Sysmon log."""
    for _ in range(attempts):
        try:
            events = parser.query_events(since_iso=None)
        except Exception:
            events = []
        for ev in events:
            data = ev.get("data") or {}
            if (ev.get("event_type") or ev.get("EventType")) != "ProcessCreate":
                continue
            if marker in str(data.get("CommandLine") or ""):
                return True
        time.sleep(1.0)
    return False


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: sysmon_manager.py <install|uninstall|status|ensure|wait-ready [seconds]>")
        return 1

    action = sys.argv[1].lower()
    mgr = SysmonManager()

    if action == "wait-ready":
        timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        return 0 if mgr.wait_ready(timeout) else 1

    if action == "install":
        mgr.install()
    elif action == "uninstall":
        mgr.uninstall()
    elif action == "status":
        print("running" if mgr.is_installed() else "not running")
    elif action == "ensure":
        mgr.ensure_running()
    else:
        print(f"Unknown action: {action}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
