"""Golden-image step: disable Microsoft Defender real-time protection so the
analysis VM observes FULL sample behavior instead of having samples neutered
mid-execution.

Rationale: this is a malware-analysis sandbox whose job is to observe what a
sample does and detect it with our OWN instrumentation (Sysmon + Sigma + YARA
+ heuristics). Defender's real-time protection kills samples before that
instrumentation sees them -- e.g. it terminates a certutil download cradle
before Sysmon ever logs the ProcessCreate, so the LOLBin Sigma rule can't fire
(confirmed 2026-07-04: 0 certutil ProcessCreate events; Defender logged
Trojan:Win32/Ceprolad.A and killed it). Standard sandbox practice is to run
with AV real-time protection off.

GOLDEN-IMAGE step, not per-run: run once inside the guest as admin, reboot,
verify, then re-capture the SANDBOX_READY snapshot -- same procedure as the
Sysmon install / ETW-TI autologger golden-image changes. Run in the guest:

    python defender_manager.py status    # dump Defender + Tamper Protection state
    python defender_manager.py disable    # turn real-time protection off
    python defender_manager.py verify     # exit 0 ONLY if real-time is off now

Tamper Protection: when ON (Windows 11 default) it BLOCKS programmatic
disabling of real-time protection -- both Set-MpPreference and the registry.
`status`/`disable` report it explicitly; if it's on it must be turned off once
via the VM's Windows Security UI (Virus & threat protection > Manage settings >
Tamper Protection) before this can succeed. The `verify` gate means the golden
snapshot is never re-captured for a disable that didn't actually take.

Deliberately uses the Real-Time Protection GROUP-POLICY subkey
(...\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring), which is
a DIFFERENT registry key than the top-level ...\Windows Defender\
DisableRealtimeMonitoring value that the defender_tampering detection sample
writes+deletes -- so this golden-image change can't taint that test.
"""

import json
import subprocess
import sys
import time
import winreg

_STATUS_FIELDS = [
    "AMServiceEnabled",
    "AntivirusEnabled",
    "RealTimeProtectionEnabled",
    "BehaviorMonitorEnabled",
    "IoavProtectionEnabled",
    "OnAccessProtectionEnabled",
    "IsTamperProtected",
    "AntivirusSignatureVersion",
]

# Microsoft's official AMSI test string (the AMSI analogue of EICAR). When
# Defender's AMSI provider is armed, any script containing it is blocked with
# "This script contains malicious content and has been blocked by your antivirus
# software" and the hosting powershell exits non-zero.
#
# Assembled from fragments on purpose: the CONTIGUOUS string must never appear
# in this file's bytes, or Defender's on-access file scan would quarantine
# defender_manager.py itself in the guest (whose Defender is armed -- a host
# exclusion doesn't cover it). We only ever form the whole string in memory,
# passed to a throwaway child powershell.
#
# 2026-09-18: '"a" + "b"' literal concatenation is CONSTANT-FOLDED at compile
# time, so the contiguous string still landed in __pycache__\*.pyc -- and
# Defender engine 4.18.26080 started flagging exactly that file mid-run
# (regression: benign canary scored suspicious/25). A method call is never
# folded, so the .pyc now stores only harmless fragments.
_AMSI_TEST_STRING = " ".join(["AMSI", "Test", "Sample:", "7e72c3ce-861b-4339-8740-0ac1484c1386"])

# GPO path for "Turn off real-time protection" -- distinct from the top-level
# key defender_tampering.ps1 exercises (see module docstring).
_RTP_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"


def _ps(script: str, timeout: int = 60):
    """Run a PowerShell one-liner. Never raises: Defender's self-protection can
    DENY the very CreateProcess for a command that disables it (observed
    2026-07-04: WinError 5 spawning `Set-MpPreference -DisableRealtimeMonitoring`,
    while `Get-MpComputerStatus` spawned fine) -- so a blocked spawn must not
    crash the caller before it reaches the registry-based disable below."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except OSError as exc:
        return -1, "", f"spawn blocked/failed: {exc}"


def get_status() -> dict:
    fields = ",".join(_STATUS_FIELDS)
    rc, out, err = _ps(
        f"Get-MpComputerStatus | Select-Object {fields} | ConvertTo-Json -Compress"
    )
    if rc != 0 or not out:
        return {"error": err or "Get-MpComputerStatus failed", "raw_rc": rc}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"error": "unparseable status", "raw": out[:400]}


def print_status(status: dict) -> None:
    for k in _STATUS_FIELDS:
        print(f"  {k} = {status.get(k)}")
    if "error" in status:
        print(f"  ERROR: {status['error']}")


# GPO Real-Time Protection values to disable (name -> DWORD 1). Turning off
# realtime monitoring is the load-bearing one; the rest give fuller behavioral
# visibility (download/attachment scanning, behavior monitoring, on-access).
_RTP_POLICY_VALUES = [
    "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring",
    "DisableIOAVProtection",
    "DisableOnAccessProtection",
    "DisableScanOnRealtimeEnable",
]


def _set_rtp_policy() -> None:
    """Set the GPO Real-Time Protection disable values via direct registry API.
    This is the RELIABLE disable path: unlike `Set-MpPreference`, a winreg write
    is not a flagged process spawn, so Defender's self-protection can't deny it
    (with Tamper Protection off), and being group policy it's honored at service
    start and durable across the reboot."""
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, _RTP_POLICY_KEY) as key:
        for name in _RTP_POLICY_VALUES:
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, 1)


def disable() -> None:
    status = get_status()
    print("[defender] before:")
    print_status(status)

    if status.get("IsTamperProtected"):
        print(
            "[defender] WARNING: Tamper Protection is ON -- it will block disabling "
            "real-time protection even via policy. Turn it off once via the VM's "
            "Windows Security UI, then re-run. verify will fail until then."
        )

    # PRIMARY, reliable path: GPO Real-Time Protection registry policy (winreg,
    # not a spawn -> not subject to the self-protection block that denies the
    # Set-MpPreference command; group policy -> durable across reboot).
    try:
        _set_rtp_policy()
        print(f"[defender] set GPO policy under {_RTP_POLICY_KEY}: {', '.join(_RTP_POLICY_VALUES)} = 1")
    except OSError as exc:
        print(f"[defender] policy key write FAILED: {exc}")

    # Best-effort, non-fatal: also nudge the active config. Expected to be
    # denied by Defender's self-protection (the registry policy above is what
    # actually carries the change); logged either way for evidence.
    rc, out, err = _ps(
        "Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop; Write-Output OK"
    )
    if rc == 0 and "OK" in out:
        print("[defender] Set-MpPreference disable also issued")
    else:
        print(f"[defender] Set-MpPreference not applied (expected; rc={rc}): {(err or out)[:200]}")

    print("[defender] after:")
    print_status(get_status())


def verify() -> bool:
    status = get_status()
    print("[defender] current state:")
    print_status(status)
    rtp = status.get("RealTimeProtectionEnabled")
    off = rtp is False or rtp == 0
    print(f"[defender] real-time protection OFF: {off}")
    if not off and status.get("IsTamperProtected"):
        print("[defender] (still on because Tamper Protection is blocking the change)")
    return off


def _clear_rtp_policy() -> None:
    """Delete the Real-Time Protection disable-values so Defender reverts to its
    default (protection ON) at the next service start / reboot. Reverses
    _set_rtp_policy()."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _RTP_POLICY_KEY, 0, winreg.KEY_SET_VALUE) as key:
            for name in _RTP_POLICY_VALUES:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass  # policy key doesn't exist -> nothing to clear


def enable() -> None:
    status = get_status()
    print("[defender] before:")
    print_status(status)

    # Reliable path: remove the GPO disable-values (winreg). Re-enabling is not
    # subject to the self-protection block that denies *disabling*.
    try:
        _clear_rtp_policy()
        print(f"[defender] cleared GPO disable-values under {_RTP_POLICY_KEY}")
    except OSError as exc:
        print(f"[defender] policy clear FAILED: {exc}")

    rc, out, err = _ps(
        "Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false "
        "-DisableIOAVProtection $false -DisableOnAccessProtection $false -ErrorAction Stop; Write-Output OK"
    )
    if rc == 0 and "OK" in out:
        print("[defender] Set-MpPreference re-enable issued")
    else:
        print(f"[defender] Set-MpPreference re-enable rc={rc}: {(err or out)[:200]}")

    print("[defender] after:")
    print_status(get_status())


def verify_on() -> bool:
    status = get_status()
    print("[defender] current state:")
    print_status(status)
    rtp = status.get("RealTimeProtectionEnabled")
    on = rtp is True or rtp == 1
    print(f"[defender] real-time protection ON: {on}")
    return on


def _amsi_flags_test() -> bool:
    """True iff Defender's AMSI provider is armed RIGHT NOW -- proven by having
    it block the AMSI test string in a throwaway child powershell. This is a
    functional check (does AMSI actually flag known-bad?), stronger than any
    Get-MpComputerStatus flag: a freshly-booted Defender can report
    RealTimeProtectionEnabled=true while its signatures are still loading, during
    which AMSI scans return clean and AMSI-based detection silently misses."""
    # Wrap as a single-quoted string literal: a valid PS expression that simply
    # echoes the string when AMSI is NOT armed (rc 0), and is BLOCKED before it
    # runs when AMSI is armed (rc != 0 + block message). That keeps "armed" and
    # "not armed" unambiguous (vs. a bare unparseable command, which also errors).
    rc, out, err = _ps("'" + _AMSI_TEST_STRING + "'", timeout=30)
    blob = (out + " " + err).lower()
    # AMSI block message; exact wording varies by Windows build, so match stable
    # fragments plus the non-zero exit that always accompanies a block.
    return rc != 0 and ("malicious content" in blob or "blocked by your antivirus" in blob)


def wait_ready(timeout_seconds: int = 90, poll_interval: int = 3) -> bool:
    """Block until AMSI is armed (or timeout). Returns True once the test string
    is flagged. Non-fatal by design: the caller proceeds either way, but records
    the result so a run where AMSI never armed is visible rather than a silent
    under-detection."""
    status = get_status()
    print(f"[defender] RealTimeProtectionEnabled={status.get('RealTimeProtectionEnabled')} "
          f"AMServiceEnabled={status.get('AMServiceEnabled')} "
          f"SignatureVersion={status.get('AntivirusSignatureVersion')}")
    deadline = time.time() + max(0, timeout_seconds)
    attempt = 0
    while True:
        attempt += 1
        if _amsi_flags_test():
            print(f"[defender] AMSI ARMED: test string flagged (attempt {attempt})")
            return True
        if time.time() >= deadline:
            print(f"[defender] TIMEOUT after {timeout_seconds}s: AMSI did not flag the test "
                  f"string ({attempt} attempts) -- AMSI-based detection may under-detect this run")
            return False
        print(f"[defender] AMSI not armed yet (attempt {attempt}); waiting {poll_interval}s...")
        time.sleep(poll_interval)


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: defender_manager.py <status|disable|verify|enable|verify-on|wait-ready [timeout]>")
        return 1
    action = sys.argv[1].lower()
    if action == "status":
        print_status(get_status())
    elif action == "disable":
        disable()
    elif action == "verify":
        return 0 if verify() else 2  # non-zero => real-time protection still on
    elif action == "enable":
        enable()
    elif action == "verify-on":
        return 0 if verify_on() else 2  # non-zero => real-time protection still off
    elif action == "wait-ready":
        timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 90
        return 0 if wait_ready(timeout) else 2  # non-zero => AMSI not armed within timeout
    else:
        print(f"Unknown action: {action}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
