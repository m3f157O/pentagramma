"""Install, start, stop, and uninstall Sysmon for sandbox telemetry."""

import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

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


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: sysmon_manager.py <install|uninstall|status|ensure>")
        return 1

    action = sys.argv[1].lower()
    mgr = SysmonManager()

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
