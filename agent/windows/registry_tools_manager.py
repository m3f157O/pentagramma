"""Golden-image step: re-enable registry tools (reg.exe) in the analysis VM.

Rationale: the golden image carries the DisableRegistryTools policy, so any
process in the guest that shells out to reg.exe gets "Registry editing has
been disabled by your administrator" and rc=1. That neuters an entire class
of attacker behavior this sandbox exists to OBSERVE (confirmed 2026-09-21 via
ART atomics: prefetch-disable, TelemetryController persistence, CredSSP
weakening, Recycle-Bin CLSID hijack -- all four did nothing in the guest, and
a probe .bat's `reg add HKLM` returned rc=1 while the token was High-IL
Administrator, i.e. policy, not privilege). Malware using direct registry
APIs is unaffected by the policy, so the block buys no realism -- it only
blinds us to the large share of samples (and ART atomics) that drive the
registry through reg.exe.

GOLDEN-IMAGE step, not per-run: run once inside the guest as admin, verify,
then re-capture the SANDBOX_READY snapshot -- same procedure as
defender_manager.py / the Sysmon install. Run in the guest:

    python registry_tools_manager.py status    # dump policy state + reg.exe probe
    python registry_tools_manager.py enable    # delete DisableRegistryTools (both hives)
    python registry_tools_manager.py verify    # exit 0 ONLY if reg.exe works now

Deliberately uses winreg for the removal: reg.exe itself is blocked until the
policy is gone (chicken-and-egg). No reboot is needed -- reg.exe evaluates the
policy at process launch, so `verify` can run immediately. If the policy was
set via LGPO it could reappear after a gpupdate; the standalone guest has no
domain and no scheduled refresh, and the verify gate means a removal that
didn't take never gets baked into the snapshot.
"""

import json
import subprocess
import sys
import winreg

_POLICY_SUBKEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_VALUE_NAME = "DisableRegistryTools"
_HIVES = [("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)]


def _read_policy() -> dict:
    """DisableRegistryTools value per hive (None = absent)."""
    out = {}
    for hive_name, hive in _HIVES:
        try:
            with winreg.OpenKey(hive, _POLICY_SUBKEY) as key:
                value, _type = winreg.QueryValueEx(key, _VALUE_NAME)
            out[hive_name] = value
        except OSError:
            out[hive_name] = None
    return out


def _probe_reg_exe() -> dict:
    """Actually exercise reg.exe end-to-end (add + delete a throwaway HKLM
    key). This is the ground truth: policy removed but reg.exe still failing
    (e.g. WDAC) must fail verification."""
    probe_key = r"HKLM\SOFTWARE\SandboxRegProbe"
    try:
        add = subprocess.run(
            ["reg", "add", probe_key, "/v", "x", "/t", "REG_DWORD", "/d", "1", "/f"],
            capture_output=True, text=True, timeout=30, errors="replace",
        )
        delete = subprocess.run(
            ["reg", "delete", probe_key, "/f"],
            capture_output=True, text=True, timeout=30, errors="replace",
        )
        return {
            "add_rc": add.returncode,
            "delete_rc": delete.returncode,
            "stderr": (add.stderr or delete.stderr or "").strip()[:300],
            "works": add.returncode == 0 and delete.returncode == 0,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"add_rc": -1, "delete_rc": -1, "stderr": str(exc), "works": False}


def get_status() -> dict:
    return {"policy": _read_policy(), "reg_exe": _probe_reg_exe()}


def enable() -> dict:
    removed = {}
    for hive_name, hive in _HIVES:
        try:
            with winreg.OpenKey(hive, _POLICY_SUBKEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, _VALUE_NAME)
            removed[hive_name] = True
        except FileNotFoundError:
            removed[hive_name] = "absent"
        except OSError as exc:
            removed[hive_name] = f"error: {exc}"
    return {"removed": removed, "policy_after": _read_policy()}


def verify() -> int:
    status = get_status()
    print(json.dumps(status, indent=2))
    policy_gone = all(v in (None, 0) for v in status["policy"].values())
    ok = policy_gone and status["reg_exe"]["works"]
    print(f"verify: policy_gone={policy_gone} reg_exe_works={status['reg_exe']['works']} -> {'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


def main() -> None:
    verb = sys.argv[1] if len(sys.argv) > 1 else "status"
    if verb == "status":
        print(json.dumps(get_status(), indent=2))
        return
    if verb == "enable":
        print(json.dumps(enable(), indent=2))
        return
    if verb == "verify":
        sys.exit(verify())
    print(f"unknown verb: {verb}", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
