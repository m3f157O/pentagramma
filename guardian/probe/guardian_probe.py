"""SandboxGuard A1a probe -- user-mode client for the driver IOCTL ABI.

Runs GUEST-side (pure stdlib ctypes, like apitrace_collector.py):
  1. opens \\.\SandboxGuard
  2. IOCTL_GUARDIAN_PING -- verifies the handshake signature
  3. optional registrations: protect PID, set targeting, set injection
  4. drains the event ring a few times and prints JSONL

    python guardian_probe.py [--rounds 5] [--interval 1.0]
                             [--protect-add PID] [--protect-remove PID]
                             [--target-sandbox ROOT_PID]
                             [--target-standalone name.exe[,name2.exe] [--follow-children]]
                             [--set-injection C:\\path\\x64.dll [C:\\path\\x86.dll]]
                             [--clear-all]

Registrations are applied BEFORE the drain loop (order: clear, protect,
injection, targeting -- so targeting can reference a root PID registered in
the same invocation).

Exit code 0 = ping signature matched (driver present and ours).
"""

import argparse
import ctypes
import json
import struct
import sys
import time
from ctypes import wintypes

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
# ctypes defaults restype to c_int -- 64-bit pointers (module handles, proc
# addresses) would be silently truncated. Declare the ones we rely on.
_k32.GetModuleHandleW.restype = wintypes.HMODULE
_k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

GENERIC_READ_WRITE = 0xC0000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


def _ctl(function, access):
    # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function, METHOD_BUFFERED=0, access)
    return (0x22 << 16) | (access << 14) | (function << 2)


IOCTL_GUARDIAN_PING = _ctl(0x800, 0)          # FILE_ANY_ACCESS
IOCTL_GUARDIAN_DRAIN = _ctl(0x801, 1)         # FILE_READ_DATA
IOCTL_GUARDIAN_PROTECT_PID = _ctl(0x802, 2)   # FILE_WRITE_DATA
IOCTL_GUARDIAN_SET_TARGETING = _ctl(0x803, 2)
IOCTL_GUARDIAN_SET_INJECTION = _ctl(0x804, 2)
IOCTL_GUARDIAN_CLEAR_ALL = _ctl(0x805, 2)

GUARDIAN_PING_SIGNATURE = 0x3144524155474253

EVENT_TYPES = {
    1: "proc_create",
    2: "proc_exit",
    3: "access_denied",
    4: "reg_denied",
    5: "module_remap",
    6: "inject_queued",
    7: "inject_failed",
}

# GUARDIAN_EVENT (pack 8): i64 ts, 7x u32, 160x u16 text, end-padded to 360.
# Python struct never adds C-style tail padding, so force it with "0q".
EVENT_FMT = "@q7I320s0q"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
assert EVENT_SIZE == 360, EVENT_SIZE

MAX_IMAGE_RULES = 8
RULE_NAME_LEN = 64


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


def load_library_w_addr():
    """User-mode VA of kernel32!LoadLibraryW in this (x64) process; system DLL
    bases are per-boot/per-bitness, so it is valid for every x64 process."""
    hmod = _k32.GetModuleHandleW("kernel32.dll")
    return _k32.GetProcAddress(hmod, b"LoadLibraryW")


def drain(handle, last_seen):
    """Fetch all events with seq > last_seen, paging until caught up
    (one DRAIN IOCTL returns at most `outcap` events)."""
    outcap = 64
    events = []
    while True:
        inbuf = struct.pack("<I", last_seen)
        outbuf = ctypes.create_string_buffer(outcap * EVENT_SIZE)
        returned = _ioctl(handle, IOCTL_GUARDIAN_DRAIN, inbuf, outbuf)
        n = 0
        for off in range(0, returned, EVENT_SIZE):
            ts, seq, etype, pid, target, ppid, wow64, value, raw_text = struct.unpack_from(
                EVENT_FMT, outbuf.raw, off)
            text = raw_text.decode("utf-16-le", errors="replace").split("\x00")[0]
            events.append({
                "seq": seq, "type": EVENT_TYPES.get(etype, f"type_{etype}"),
                "pid": pid, "target_pid": target, "ppid": ppid,
                "wow64": bool(wow64), "value": value, "text": text,
                "ts_filetime": ts,
            })
            last_seen = max(last_seen, seq)
            n += 1
        if n < outcap:
            return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--protect-add", type=int, metavar="PID")
    ap.add_argument("--protect-remove", type=int, metavar="PID")
    ap.add_argument("--target-sandbox", type=int, metavar="ROOT_PID")
    ap.add_argument("--target-standalone", metavar="NAME[,NAME...]")
    ap.add_argument("--follow-children", action="store_true")
    ap.add_argument("--set-injection", nargs="+", metavar="DLL")
    ap.add_argument("--clear-all", action="store_true")
    args = ap.parse_args()

    handle = _k32.CreateFileW(r"\\.\SandboxGuard", GENERIC_READ_WRITE, 0, None,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if handle == INVALID_HANDLE_VALUE:
        print(f"[probe] open failed: {ctypes.get_last_error()} (driver loaded?)", file=sys.stderr)
        sys.exit(1)

    outbuf = ctypes.create_string_buffer(8)
    _ioctl(handle, IOCTL_GUARDIAN_PING, None, outbuf)
    sig = struct.unpack("<Q", outbuf.raw)[0]
    if sig != GUARDIAN_PING_SIGNATURE:
        print(f"[probe] PING signature mismatch: 0x{sig:016x}", file=sys.stderr)
        sys.exit(1)
    print("[probe] PING ok -- SandboxGuard present")

    if args.clear_all:
        _ioctl(handle, IOCTL_GUARDIAN_CLEAR_ALL)
        print("[probe] CLEAR_ALL ok")

    for pid, remove in ((args.protect_add, 0), (args.protect_remove, 1)):
        if pid is None:
            continue
        _ioctl(handle, IOCTL_GUARDIAN_PROTECT_PID, struct.pack("<II", pid, remove))
        print(f"[probe] protect {'remove' if remove else 'add'} pid={pid} ok")

    if args.set_injection:
        dll_x64 = args.set_injection[0]
        dll_x86 = args.set_injection[1] if len(args.set_injection) > 1 else ""
        # GUARDIAN_INJECTION (pack 8): u64 x64 addr, u64 x86 addr, 260 wchars x2
        inbuf = struct.pack("<QQ", load_library_w_addr(), 0)
        inbuf += _wchars(dll_x64, 260) + _wchars(dll_x86, 260)
        _ioctl(handle, IOCTL_GUARDIAN_SET_INJECTION, inbuf)
        print(f"[probe] injection set: x64={dll_x64} x86={dll_x86 or '-'} "
              f"LoadLibraryW=0x{load_library_w_addr():x}")

    if args.target_sandbox is not None or args.target_standalone is not None:
        mode = 1 if args.target_sandbox is not None else 2
        names = [n.strip().lower() for n in (args.target_standalone or "").split(",") if n.strip()]
        names = names[:MAX_IMAGE_RULES]
        inbuf = struct.pack("<IIII", mode, args.target_sandbox or 0,
                            1 if args.follow_children else 0, 0)
        for i in range(MAX_IMAGE_RULES):
            inbuf += _wchars(names[i] if i < len(names) else "", RULE_NAME_LEN)
        _ioctl(handle, IOCTL_GUARDIAN_SET_TARGETING, inbuf)
        print(f"[probe] targeting set: mode={'sandbox' if mode == 1 else 'standalone'} "
              f"root={args.target_sandbox or '-'} names={names or '-'} follow={args.follow_children}")

    last_seen = 0
    for i in range(args.rounds):
        events = drain(handle, last_seen)
        if events:
            last_seen = max(e["seq"] for e in events)
        for e in events:
            print(json.dumps(e))
        if args.rounds > 1 and i < args.rounds - 1:
            time.sleep(args.interval)

    _k32.CloseHandle(handle)


if __name__ == "__main__":
    main()
