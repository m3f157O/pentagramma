"""SandboxGuard A0 spike probe -- user-mode client for the driver IOCTL ABI.

Runs GUEST-side (pure stdlib ctypes, like apitrace_collector.py):
  1. opens \\.\SandboxGuard
  2. IOCTL_GUARDIAN_PING -- verifies the handshake signature
  3. drains the process-event ring a few times and prints JSONL

    python guardian_probe.py [--rounds 5] [--interval 1.0]

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

GENERIC_READ_WRITE = 0xC0000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

# CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function, METHOD_BUFFERED=0, access):
#   code = (0x22 << 16) | (access << 14) | (function << 2)
IOCTL_GUARDIAN_PING = (0x22 << 16) | (0x800 << 2)                       # 0x222000
IOCTL_GUARDIAN_DRAIN = (0x22 << 16) | (0x1 << 14) | (0x801 << 2)        # 0x226004

GUARDIAN_PING_SIGNATURE = 0x3144524155474253

# GUARDIAN_PROC_EVENT (pack 8): i64 ts, 6x u32, 128x u16 image name
EVENT_FMT = "<q6I256s"
EVENT_SIZE = struct.calcsize(EVENT_FMT)


def drain(handle, last_seen):
    inbuf = struct.pack("<I", last_seen)
    outcap = 64
    outbuf = ctypes.create_string_buffer(outcap * EVENT_SIZE)
    returned = wintypes.DWORD(0)
    ok = _k32.DeviceIoControl(handle, IOCTL_GUARDIAN_DRAIN,
                              inbuf, len(inbuf), outbuf, len(outbuf),
                              ctypes.byref(returned), None)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    events = []
    for off in range(0, returned.value, EVENT_SIZE):
        ts, seq, pid, ppid, is_create, is_wow64, _reserved, raw_name = struct.unpack_from(
            EVENT_FMT, outbuf.raw, off)
        name = raw_name.decode("utf-16-le", errors="replace").split("\x00")[0]
        events.append({
            "seq": seq, "pid": pid, "ppid": ppid,
            "kind": "create" if is_create else "exit",
            "wow64": bool(is_wow64), "image": name, "ts_filetime": ts,
        })
    return events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()

    handle = _k32.CreateFileW(r"\\.\SandboxGuard", GENERIC_READ_WRITE, 0, None,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if handle == INVALID_HANDLE_VALUE:
        print(f"[probe] open failed: {ctypes.get_last_error()} (driver loaded?)", file=sys.stderr)
        sys.exit(1)

    outbuf = ctypes.create_string_buffer(8)
    returned = wintypes.DWORD(0)
    ok = _k32.DeviceIoControl(handle, IOCTL_GUARDIAN_PING, None, 0,
                              outbuf, 8, ctypes.byref(returned), None)
    if not ok:
        print(f"[probe] PING failed: {ctypes.get_last_error()}", file=sys.stderr)
        sys.exit(1)
    sig = struct.unpack("<Q", outbuf.raw)[0]
    if sig != GUARDIAN_PING_SIGNATURE:
        print(f"[probe] PING signature mismatch: 0x{sig:016x}", file=sys.stderr)
        sys.exit(1)
    print("[probe] PING ok -- SandboxGuard present")

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
