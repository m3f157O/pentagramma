"""Enable/check PowerShell script-block logging for sandbox telemetry.

Windows PowerShell 5.1 writes script block text to
Microsoft-Windows-PowerShell/Operational (EID 4104) once the
EnableScriptBlockLogging policy is set -- no service install needed, unlike
Sysmon. The channel itself is enabled by default on Windows 10/11/Server;
the wevtutil call below is a defensive no-op that removes all doubt.
"""

import sys
import winreg

import proc_util

POLICY_KEY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
POLICY_VALUE_NAME = "EnableScriptBlockLogging"
LOG_CHANNEL = "Microsoft-Windows-PowerShell/Operational"


class PowerShellLoggingManager:
    def is_enabled(self) -> bool:
        """Check whether the ScriptBlockLogging registry policy is set."""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY_PATH) as key:
                value, _ = winreg.QueryValueEx(key, POLICY_VALUE_NAME)
                return value == 1
        except FileNotFoundError:
            return False

    def enable(self) -> None:
        """Write the ScriptBlockLogging registry policy and ensure the event
        log channel is enabled.
        """
        print(f"[powershell] enabling script-block logging at HKLM\\{POLICY_KEY_PATH}")
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY_PATH) as key:
            winreg.SetValueEx(key, POLICY_VALUE_NAME, 0, winreg.REG_DWORD, 1)

        proc = proc_util.run_text(
            ["wevtutil", "sl", LOG_CHANNEL, "/e:true"],
            timeout=30,
        )
        if proc.returncode != 0:
            print(f"[powershell] warning: could not enable log channel: {proc.stderr.strip()}")

    def ensure_enabled(self) -> None:
        """Enable script-block logging if not already active."""
        if self.is_enabled():
            print("[powershell] script-block logging already enabled")
            return
        self.enable()


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: powershell_logging_manager.py <enable|status|ensure>")
        return 1

    action = sys.argv[1].lower()
    mgr = PowerShellLoggingManager()

    if action == "enable":
        mgr.enable()
    elif action == "status":
        print("enabled" if mgr.is_enabled() else "not enabled")
    elif action == "ensure":
        mgr.ensure_enabled()
    else:
        print(f"Unknown action: {action}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
