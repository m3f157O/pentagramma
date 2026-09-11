"""Guest-side guardian agent -- user-mode client for SandboxGuard.sys.

Runs inside the analysis VM for the duration of one analysis run (mirrors
apitrace_collector.py's lifecycle: started detached before the sample
launches, stopped via stop-file right before telemetry_collect).

Responsibilities:
  1. Handshake with the driver (IOCTL PING); if absent, emit a single
     GuardianUnavailable meta event and exit 0 -- the run continues exactly
     as if guardian were disabled (fail-open, loader stays the placement path).
  2. CLEAR_ALL, then register:
       - protected PIDs: ourselves + Sysmon64 (Ob/Cm protection)
       - injection config: monitor DLL paths + kernel32!LoadLibraryW VA
         (only when behavioral tracing is on -- the caller passes the DLLs)
       - targeting: standalone image-name rule for the sample's image +
         follow-children (pre-entry placement, survives direct-syscall spawns)
  3. Drain the driver event ring (~1s poll) and append guardian-specific
     events (types 3-7; proc create/exit are Sysmon's job) to
     guardian.jsonl as normalized telemetry events (source "guardian",
     synthetic EIDs 9400-9405).
  4. On stop: CLEAR_ALL (driver goes inert) and exit.

    python guardian_agent.py --out C:\SandboxAgent\guardian.jsonl
        --stop-file C:\SandboxAgent\guardian_stop.flag --max-seconds 900
        [--target-image sample.exe] [--dll-x64 C:\...\monitor_x64.dll
         [--dll-x86 C:\...\monitor_x86.dll]] [--quiet]
"""

import argparse
import ctypes
import json
import os
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
# ctypes defaults restype to c_int -- 64-bit pointers would be truncated.
_k32.GetModuleHandleW.restype = wintypes.HMODULE
_k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

GENERIC_READ_WRITE = 0xC0000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


def _ctl(function, access):
    return (0x22 << 16) | (access << 14) | (function << 2)


IOCTL_PING = _ctl(0x800, 0)
IOCTL_DRAIN = _ctl(0x801, 1)
IOCTL_PROTECT_PID = _ctl(0x802, 2)
IOCTL_SET_TARGETING = _ctl(0x803, 2)
IOCTL_SET_INJECTION = _ctl(0x804, 2)
IOCTL_CLEAR_ALL = _ctl(0x805, 2)

GUARDIAN_PING_SIGNATURE = 0x3144524155474253

# Driver ring event types -> synthetic EIDs / event types in telemetry.
# proc_create(1)/proc_exit(2) are deliberately NOT forwarded (Sysmon's job).
EVT_TO_EID = {
    3: (9401, "GuardianProtectedAccess"),
    4: (9402, "GuardianProtectedRegistry"),
    5: (9403, "GuardianModuleRemap"),
    6: (9404, "GuardianInjectionPlaced"),
    7: (9405, "GuardianInjectionFailed"),
}
EID_UNAVAILABLE = 9400

# GUARDIAN_EVENT (pack 8): i64 ts, 7x u32, 160x u16 text, tail-padded to 360.
EVENT_FMT = "@q7I320s0q"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
assert EVENT_SIZE == 360, EVENT_SIZE

FILETIME_EPOCH_DELTA_100NS = 116444736000000000

AGENT_LOG_FILE = Path(r"C:\SandboxAgent\guardian_agent.log")


def _harden_console() -> None:
    """Same contract as telemetry_collector: PSDirect turns any stderr bytes
    into a NativeCommandError that fails the calling step -- redirect."""
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    try:
        AGENT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        sys.stderr = open(AGENT_LOG_FILE, "a", encoding="utf-8", errors="replace")
    except OSError:
        pass


def _iso_from_filetime(ft: int) -> str:
    epoch_s = (ft - FILETIME_EPOCH_DELTA_100NS) / 10_000_000
    try:
        return datetime.fromtimestamp(epoch_s, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return datetime.now(timezone.utc).isoformat()


def _ioctl(handle, code, inbuf=None, outbuf=None):
    returned = wintypes.DWORD(0)
    ok = _k32.DeviceIoControl(
        handle, code,
        inbuf, len(inbuf) if inbuf else 0,
        outbuf, len(outbuf) if outbuf else 0,
        ctypes.byref(returned), None)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return returned.value


def _wchars(text, count):
    data = text.encode("utf-16-le")[: (count - 1) * 2]
    return data + b"\x00" * (count * 2 - len(data))


def _open_device():
    handle = _k32.CreateFileW(r"\\.\SandboxGuard", GENERIC_READ_WRITE, 0, None,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if handle == INVALID_HANDLE_VALUE:
        return None
    outbuf = ctypes.create_string_buffer(8)
    try:
        _ioctl(handle, IOCTL_PING, None, outbuf)
    except OSError:
        _k32.CloseHandle(handle)
        return None
    if struct.unpack("<Q", outbuf.raw)[0] != GUARDIAN_PING_SIGNATURE:
        _k32.CloseHandle(handle)
        return None
    return handle


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * wintypes.MAX_PATH),
    ]


_k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
# Without explicit argtypes, ctypes truncates the 64-bit byref pointer
# (Process32FirstW fails with ERROR_BAD_LENGTH).
_k32.Process32FirstW.restype = wintypes.BOOL
_k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
_k32.Process32NextW.restype = wintypes.BOOL
_k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]


def _find_pids_by_image(image_name: str):
    """PIDs of ALL processes whose image matches (Toolhelp32 snapshot via
    ctypes -- pure stdlib, spawns no child process; the previous per-tick
    tasklist.exe spawn was pure Sysmon ProcessCreate/ImageLoad noise, ~1
    process pair per second for the whole run). There can be several: the
    Sysmon64 service AND transient `sysmon64.exe -c` config-update instances
    coexist -- returning only the first tasklist row once protected the CLI
    process while the real service stayed killable (A4 tamper canary)."""
    TH32CS_SNAPPROCESS = 0x2
    pids = []
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return pids
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        ok = _k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == image_name.lower():
                pids.append(entry.th32ProcessID)
            ok = _k32.Process32NextW(snap, ctypes.byref(entry))
    except Exception:
        pass
    finally:
        _k32.CloseHandle(snap)
    return pids


def _register_protections(handle, quiet):
    pids = {os.getpid()}
    sysmon_pids = _find_pids_by_image("Sysmon64.exe")
    pids.update(sysmon_pids)
    registered = []
    for pid in pids:
        try:
            _ioctl(handle, IOCTL_PROTECT_PID, struct.pack("<II", pid, 0))
            registered.append(pid)
            if not quiet:
                print(f"[guardian] protecting pid {pid}")
        except OSError as exc:
            print(f"[guardian] protect pid {pid} failed: {exc}", file=sys.stderr)
    return registered, sysmon_pids


def _find_loadlibraryw_x86(quiet=False):
    """32-bit kernel32!LoadLibraryW VA via the shipped x86 helper.

    System DLL bases are per-boot/per-bitness, so the address the 32-bit
    helper prints is valid for every WoW64 process until reboot. Fail-open
    (return 0): the driver then reports inject_failed for WoW64 targets
    instead of queueing a bad APC.
    """
    helper = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "guardian_loadlib_x86.exe")
    try:
        out = subprocess.check_output([helper], timeout=15).decode().strip()
        va = int(out, 16)
        if not (0x10000 <= va < 0x80000000):
            raise ValueError(f"implausible VA {out!r}")
        return va
    except Exception as exc:
        if not quiet:
            print(f"[guardian] x86 LoadLibraryW helper failed ({exc}); "
                  "WoW64 injection disabled", file=sys.stderr)
        return 0


def _register_injection(handle, dll_x64, dll_x86, quiet):
    """Returns (loadlibrary_x64_va, loadlibrary_x86_va) for the meta event."""
    if not dll_x64 and not dll_x86:
        return 0, 0
    # LoadLibraryW VA in this (x64) process is valid for every x64 target
    # (system DLL bases are per-boot/per-bitness). The x86 VA comes from the
    # shipped 32-bit helper (a 64-bit process cannot load 32-bit kernel32).
    hmod = _k32.GetModuleHandleW("kernel32.dll")
    load_x64 = _k32.GetProcAddress(hmod, b"LoadLibraryW") or 0
    load_x86 = _find_loadlibraryw_x86(quiet) if dll_x86 else 0
    inbuf = struct.pack("<QQ", load_x64, load_x86)
    inbuf += _wchars(dll_x64 or "", 260) + _wchars(dll_x86 or "", 260)
    _ioctl(handle, IOCTL_SET_INJECTION, inbuf)
    if not quiet:
        print(f"[guardian] injection: x64={dll_x64 or '-'} x86={dll_x86 or '-'} "
              f"LoadLibraryW=0x{load_x64:x}/0x{load_x86:x}")
    return load_x64, load_x86


def _register_targeting(handle, target_image, quiet):
    if not target_image:
        return
    # standalone mode (2), follow children (1)
    inbuf = struct.pack("<IIII", 2, 0, 1, 0)
    names = [target_image.lower()]
    # Loader family: x86 samples are launched by monitor_loader_x86.exe
    # (chosen guest-side by PE sniff in Execute-Sample), which neither matches
    # a "monitor_loader.exe" rule nor descends from it -- without the family
    # entry, WoW64 sample trees escape driver injection entirely (confirmed
    # 2026-09-03: wow64_benign.exe run, zero guardian injection events).
    for companion in ("monitor_loader.exe", "monitor_loader_x86.exe"):
        if companion not in names and any(n in ("monitor_loader.exe", "monitor_loader_x86.exe") for n in names):
            names.append(companion)
    for i in range(8):
        inbuf += _wchars(names[i] if i < len(names) else "", 64)
    _ioctl(handle, IOCTL_SET_TARGETING, inbuf)
    if not quiet:
        print(f"[guardian] targeting: image={target_image} follow_children=1")


def _drain(handle, last_seen):
    """Page through the ring until caught up (one DRAIN returns <=64)."""
    events = []
    while True:
        inbuf = struct.pack("<I", last_seen)
        outbuf = ctypes.create_string_buffer(64 * EVENT_SIZE)
        returned = _ioctl(handle, IOCTL_DRAIN, inbuf, outbuf)
        n = 0
        for off in range(0, returned, EVENT_SIZE):
            ts, seq, etype, pid, target, ppid, wow64, value, raw_text = struct.unpack_from(
                EVENT_FMT, outbuf.raw, off)
            last_seen = max(last_seen, seq)
            n += 1
            spec = EVT_TO_EID.get(etype)
            if spec is None:
                continue  # proc create/exit: Sysmon's domain
            eid, event_type = spec
            text = raw_text.decode("utf-16-le", errors="replace").split("\x00")[0]
            events.append({
                "source": "guardian",
                "event_id": eid,
                "timestamp": _iso_from_filetime(ts),
                "event_type": event_type,
                "data": {
                    "ProcessId": pid,
                    "TargetProcessId": target,
                    "Value": value,
                    "Text": text,
                    "Wow64": bool(wow64),
                    "Sequence": seq,
                },
            })
        if n < 64:
            return events, last_seen


def main() -> int:
    _harden_console()
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--stop-file", required=True)
    ap.add_argument("--max-seconds", type=int, default=900)
    ap.add_argument("--target-image", default="")
    ap.add_argument("--dll-x64", default="")
    ap.add_argument("--dll-x86", default="")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    handle = _open_device()
    if handle is None:
        # Fail-open: record why, exit 0 -- the run proceeds on the loader path.
        with out_path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "source": "guardian",
                "event_id": EID_UNAVAILABLE,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "GuardianUnavailable",
                "data": {"Text": "SandboxGuard device not present or PING failed (driver not loaded)"},
            }) + "\n")
        print("[guardian] driver not present -- guardian inactive this run")
        return 0

    try:
        _ioctl(handle, IOCTL_CLEAR_ALL)
        protected_pids, sysmon_pids = _register_protections(handle, args.quiet)
        load_x64, load_x86 = _register_injection(handle, args.dll_x64, args.dll_x86, args.quiet)
        _register_targeting(handle, args.target_image, args.quiet)
        # Registration meta event: makes the protected set auditable from the
        # report (a silent tasklist-lookup miss must not look like a driver
        # bug). The LoadLibraryW VAs let the orchestrator fingerprint the
        # monitor's own LoadLibraryW-style child-following injections
        # (Sysmon EID 8 StartAddress == VA) as tooling noise.
        with out_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "source": "guardian",
                "event_id": EID_UNAVAILABLE,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "GuardianRegistered",
                "data": {"Text": f"protected_pids={protected_pids} sysmon_pids={sysmon_pids} "
                                 f"target={args.target_image or '-'} "
                                 f"loadlibrary_x64=0x{load_x64:x} loadlibrary_x86=0x{load_x86:x}"},
            }) + "\n")
        if not args.quiet:
            print("[guardian] active -- draining event ring")

        deadline = time.time() + args.max_seconds
        last_seen = 0
        known_sysmon_pids = set(sysmon_pids)
        with out_path.open("a", encoding="utf-8") as fh:
            while time.time() < deadline:
                if Path(args.stop_file).exists():
                    break
                # Sysmon's service can restart mid-run (crash recovery) and a
                # transient `sysmon64 -c` instance can mask the service pid --
                # re-resolve ALL instances each tick and protect any new one.
                for sp in _find_pids_by_image("Sysmon64.exe"):
                    if sp not in known_sysmon_pids:
                        try:
                            _ioctl(handle, IOCTL_PROTECT_PID, struct.pack("<II", sp, 0))
                            known_sysmon_pids.add(sp)
                        except OSError:
                            pass
                try:
                    events, last_seen = _drain(handle, last_seen)
                except OSError as exc:
                    print(f"[guardian] drain error: {exc}", file=sys.stderr)
                    time.sleep(1)
                    continue
                for ev in events:
                    fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
                if events:
                    fh.flush()
                time.sleep(1)
    finally:
        try:
            _ioctl(handle, IOCTL_CLEAR_ALL)
        except OSError:
            pass
        _k32.CloseHandle(handle)
        if not args.quiet:
            print("[guardian] stopped (driver state cleared)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
