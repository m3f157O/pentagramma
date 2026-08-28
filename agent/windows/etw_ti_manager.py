"""Configure a boot autologger for the ETW Threat-Intelligence provider.

The TI provider ({f4e1897c-...}) only delivers events to a Protected-Process
consumer or to a boot autologger. We can't be PPL (would need anti-malware
code-signing), so we use an autologger: a trace session the OS starts at boot,
before anything the sample does, writing TI events to an ETL file that
etw_ti_collector.py flushes and decodes at collect time.

This is a GOLDEN-IMAGE setup step, not a per-run one: autologger changes only
take effect after a reboot. Apply once to the analysis VM, then re-capture the
SANDBOX_READY snapshot -- the same procedure used for the Sysmon install /
auto-logon golden-image changes. Run inside the guest as admin:

    python etw_ti_manager.py enable     # configure the autologger
    python etw_ti_manager.py status     # is it configured?

Efficacy note: whether a non-PPL autologger actually receives TI events is
Windows-build-dependent. If it doesn't, the collector simply returns no events
(the source degrades cleanly). Verify with a live run after applying.
"""

import subprocess
import sys
import winreg

AUTOLOGGER_NAME = "SandboxEtwTi"
AUTOLOGGER_KEY = r"SYSTEM\CurrentControlSet\Control\WMI\Autologger\SandboxEtwTi"
ETW_TI_PROVIDER_GUID = "{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}"
# A unique GUID for the trace *session* (distinct from the provider GUID).
SESSION_GUID = "{b6a1f4c2-0e77-4c1a-9d3e-5a0dbea50c10}"
ETL_PATH = r"C:\Windows\Temp\sandbox_etw_ti.etl"

# EVENT_TRACE_FILE_MODE_SEQUENTIAL
_LOG_FILE_MODE_SEQUENTIAL = 0x00000001
_ENABLE_LEVEL_VERBOSE = 0xFF


class EtwTiAutologgerManager:
    def is_enabled(self) -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AUTOLOGGER_KEY) as key:
                start, _ = winreg.QueryValueEx(key, "Start")
                if start != 1:
                    return False
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AUTOLOGGER_KEY + "\\" + ETW_TI_PROVIDER_GUID) as pkey:
                enabled, _ = winreg.QueryValueEx(pkey, "Enabled")
                return enabled == 1
        except FileNotFoundError:
            return False

    def enable(self) -> None:
        print(f"[etw-ti] configuring autologger '{AUTOLOGGER_NAME}' -> {ETL_PATH}")
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, AUTOLOGGER_KEY) as key:
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "Guid", 0, winreg.REG_SZ, SESSION_GUID)
            winreg.SetValueEx(key, "FileName", 0, winreg.REG_EXPAND_SZ, ETL_PATH)
            winreg.SetValueEx(key, "LogFileMode", 0, winreg.REG_DWORD, _LOG_FILE_MODE_SEQUENTIAL)
            winreg.SetValueEx(key, "BufferSize", 0, winreg.REG_DWORD, 64)
            winreg.SetValueEx(key, "MaximumFileSize", 0, winreg.REG_DWORD, 64)  # MB
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, AUTOLOGGER_KEY + "\\" + ETW_TI_PROVIDER_GUID) as pkey:
            winreg.SetValueEx(pkey, "Enabled", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(pkey, "EnableLevel", 0, winreg.REG_DWORD, _ENABLE_LEVEL_VERBOSE)
            winreg.SetValueEx(pkey, "MatchAnyKeyword", 0, winreg.REG_QWORD, 0)
        print("[etw-ti] autologger configured -- takes effect after reboot; re-capture the golden snapshot")

    def ensure_enabled(self) -> None:
        if self.is_enabled():
            print("[etw-ti] autologger already configured")
            return
        self.enable()

    def verify(self) -> bool:
        """Report whether the autologger is configured (registry) AND its live
        session is running now -- the meaningful post-reboot check. Returns
        True only if the live session is up.
        """
        configured = self.is_enabled()
        print(f"[etw-ti] autologger configured (registry): {configured}")
        running = False
        try:
            proc = subprocess.run(
                ["logman", "query", AUTOLOGGER_NAME, "-ets"],
                capture_output=True, text=True, timeout=15, errors="replace",
            )
            running = proc.returncode == 0
            print(f"[etw-ti] live session '{AUTOLOGGER_NAME}' running: {running}")
            if proc.stdout:
                print(proc.stdout.strip()[:800])
            if not running and proc.stderr:
                print(proc.stderr.strip()[:400])
        except Exception as exc:  # noqa: BLE001
            print(f"[etw-ti] logman query failed: {exc}")
        return running


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: etw_ti_manager.py <enable|status|ensure|verify>")
        return 1
    action = sys.argv[1].lower()
    mgr = EtwTiAutologgerManager()
    if action == "enable":
        mgr.enable()
    elif action == "status":
        print("configured" if mgr.is_enabled() else "not configured")
    elif action == "ensure":
        mgr.ensure_enabled()
    elif action == "verify":
        return 0 if mgr.verify() else 2  # non-zero => live session not running
    else:
        print(f"Unknown action: {action}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
