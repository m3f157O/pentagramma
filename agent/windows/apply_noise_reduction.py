"""OS-noise reduction for the analysis VM golden image.

Run in the guest via PSDirect (provision-noise-reduction endpoint or
provision_golden_image.ps1), same contract as apply_dressing.py:

    python apply_noise_reduction.py apply    # disable noise sources (idempotent)
    python apply_noise_reduction.py verify   # exit 0 iff all quiet

Targets only background CHURN measured in real runs (see
docs/emotet-investigation.md and the noise quantification on canary d89f08b6):
Edge/OneDrive updaters, telemetry (DiagTrack/CEIP), CompatTelRunner, Windows
Search indexing, Windows Update workers, WER. Defender and wuauserv are
deliberately kept (Defender detections are a scoring source; signature updates
need the update stack). No user-profile/dressing artifact is touched: kill the
churn, keep the signs of life (a sterile VM is itself a sandbox tell).

Services/tasks/registry are manipulated via PowerShell (Get/Set cmdlets have
localization-invariant state names, unlike sc.exe/schtasks.exe output).
Best-effort per item — one failure never aborts the rest; every item is
individually reported and verify() checks the same list.
"""

import json
import subprocess
import sys
import winreg

# (TaskPath, TaskName) pairs to disable. Exact paths; absent tasks are "absent",
# not errors (image variants differ).
TASKS = [
    (r"\\", "MicrosoftEdgeUpdateTaskMachineCore"),
    (r"\\", "MicrosoftEdgeUpdateTaskMachineUA"),
    (r"\\Microsoft\\Windows\\Application Experience\\", "Microsoft Compatibility Appraiser"),
    (r"\\Microsoft\\Windows\\Application Experience\\", "ProgramDataUpdater"),
    (r"\\Microsoft\\Windows\\Application Experience\\", "StartupAppTask"),
    (r"\\Microsoft\\Windows\\Customer Experience Improvement Program\\", "Consolidator"),
    (r"\\Microsoft\\Windows\\Customer Experience Improvement Program\\", "UsbCeip"),
    (r"\\Microsoft\\Windows\\Customer Experience Improvement Program\\", "KernelCeipTask"),
    (r"\\Microsoft\\Windows\\DiskFootprint\\", "Diagnostics"),
    (r"\\Microsoft\\Windows\\Maps\\", "MapsUpdateTask"),
    (r"\\Microsoft\\Windows\\Maps\\", "MapsToastTask"),
    (r"\\Microsoft\\Windows\\Autochk\\", "Proxy"),
    (r"\\Microsoft\\Windows\\Windows Error Reporting\\", "QueueReporting"),
]

# Root tasks matched by name prefix (per-user SID suffix varies).
TASK_PREFIXES = ["OneDrive Standalone Update Task"]

# Services to set to Disabled. Kept on purpose: wuauserv, WinDefend, MpsSvc,
# Winmgmt, Schedule, Sysmon64, all SandboxAgent tooling.
SERVICES = [
    "DiagTrack",                    # Connected User Experiences and Telemetry
    "dmwappushservice",             # WAP push message routing (telemetry)
    "WSearch",                      # Windows Search indexer
    "RetailDemo",                   # retail demo content
    "MapsBroker",                   # downloaded maps manager
    "edgeupdate",                   # Edge update
    "edgeupdatem",                  # Edge update (m)
    "MicrosoftEdgeElevationService",
    "OneDrive Updater Service",
]

# (hive, subkey, value_name, dword) policies to set.
REG_DWORD = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "Disabled", 1),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\OneDrive", "DisableFileSyncNGSC", 1),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled", 0),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "BackgroundModeEnabled", 0),
]

# (hive, subkey, value_name) values to delete (autostarts).
REG_DELETE = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive"),
]

_HIVE_NAME = {winreg.HKEY_LOCAL_MACHINE: "HKLM", winreg.HKEY_CURRENT_USER: "HKCU"}


def _ps(script: str) -> str:
    """Run a PowerShell snippet in the guest; return stdout (never raises)."""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=120,
        )
        return proc.stdout or ""
    except Exception:
        return ""


def _ps_task_state(task_path: str, task_name: str) -> str:
    out = _ps(
        f"$t = Get-ScheduledTask -TaskPath '{task_path}' -TaskName '{task_name}' "
        "-ErrorAction SilentlyContinue; if ($t) { $t.State } else { 'Absent' }"
    ).strip()
    return out.splitlines()[-1].strip() if out.strip() else "Unknown"


def _ps_service_starttype(name: str) -> str:
    out = _ps(
        f"$s = Get-Service -Name '{name}' -ErrorAction SilentlyContinue; "
        "if ($s) { $s.StartType } else { 'Absent' }"
    ).strip()
    return out.splitlines()[-1].strip() if out.strip() else "Unknown"


def _apply_tasks() -> dict:
    results = {}
    for task_path, task_name in TASKS:
        key = task_path + task_name
        if _ps_task_state(task_path, task_name) == "Absent":
            results[key] = "absent"
            continue
        _ps(f"Disable-ScheduledTask -TaskPath '{task_path}' -TaskName '{task_name}' | Out-Null")
        results[key] = _ps_task_state(task_path, task_name).lower()
    for prefix in TASK_PREFIXES:
        _ps(
            f"Get-ScheduledTask -TaskPath '\\' -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.TaskName -like '{prefix}*' }} | "
            "Disable-ScheduledTask | Out-Null"
        )
        out = _ps(
            f"$t = Get-ScheduledTask -TaskPath '\\' -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.TaskName -like '{prefix}*' }}; "
            "if ($t) { ($t | ForEach-Object { $_.State }) -join ',' } else { 'Absent' }"
        ).strip()
        results[prefix + "*"] = (out or "unknown").lower()
    return results


def _apply_services() -> dict:
    results = {}
    for name in SERVICES:
        if _ps_service_starttype(name) == "Absent":
            results[name] = "absent"
            continue
        _ps(f"Stop-Service -Name '{name}' -Force -ErrorAction SilentlyContinue; "
            f"Set-Service -Name '{name}' -StartupType Disabled")
        results[name] = _ps_service_starttype(name).lower()
    return results


def _apply_registry() -> dict:
    results = {}
    for hive, subkey, value_name, dword in REG_DWORD:
        key = f"{_HIVE_NAME[hive]}\\{subkey}\\{value_name}"
        try:
            with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, value_name, 0, winreg.REG_DWORD, dword)
            results[key] = dword
        except OSError as exc:
            results[key] = f"error: {exc}"
    for hive, subkey, value_name in REG_DELETE:
        key = f"{_HIVE_NAME[hive]}\\{subkey}\\{value_name}"
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, value_name)
            results[key] = "deleted"
        except FileNotFoundError:
            results[key] = "absent"
        except OSError as exc:
            results[key] = f"error: {exc}"
    return results


def apply() -> dict:
    return {
        "tasks": _apply_tasks(),
        "services": _apply_services(),
        "registry": _apply_registry(),
    }


def verify() -> dict:
    tasks = {}
    for task_path, task_name in TASKS:
        tasks[task_path + task_name] = _ps_task_state(task_path, task_name)
    services = {name: _ps_service_starttype(name) for name in SERVICES}
    registry = {}
    for hive, subkey, value_name, dword in REG_DWORD:
        key = f"{_HIVE_NAME[hive]}\\{subkey}\\{value_name}"
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                registry[key] = winreg.QueryValueEx(k, value_name)[0]
        except OSError:
            registry[key] = "missing"
    tasks_ok = all(s.lower() in ("disabled", "absent") for s in tasks.values())
    services_ok = all(s.lower() in ("disabled", "absent") for s in services.values())
    registry_ok = all(registry[f"{_HIVE_NAME[h]}\\{s}\\{v}"] == d for h, s, v, d in REG_DWORD)
    return {"tasks": tasks, "services": services, "registry": registry,
            "ok": tasks_ok and services_ok and registry_ok}


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "apply"
    if mode == "apply":
        out = apply()
    elif mode == "verify":
        out = verify()
    else:
        print(f"unknown mode {mode}")
        sys.exit(2)
    print(json.dumps(out, indent=2))
    sys.exit(0 if (mode != "verify" or out.get("ok")) else 1)
