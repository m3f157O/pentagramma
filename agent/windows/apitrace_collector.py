"""API-trace collector -- named-pipe server for the behavioral monitor DLL.

Runs guest-side, started BEFORE the sample launches and stopped after (mirrors
network_capture.py's start-before / stop-after lifecycle). The injected
monitor DLL (agent/windows/monitor_src) connects to \\.\pipe\sandbox_apitrace
and streams newline-delimited JSON API events; this server accepts one pipe
instance per traced process (the sample and, later, each child the monitor
follows), stamps each event with a receive timestamp, and appends it to an
apitrace.jsonl file the telemetry collector later merges into the event stream.

Pure stdlib (ctypes Win32) so it needs no extra wheel in the guest image.

Standalone use (also how the host-local feasibility spike drives it):

    python apitrace_collector.py --out apitrace.jsonl --max-seconds 20
    python apitrace_collector.py --out apitrace.jsonl --stop-file stop.flag
"""

import argparse
import ctypes
import json
import os
import sys
import threading
import time
from ctypes import wintypes
from typing import Optional

PIPE_PREFIX = r"\\.\pipe" "\\"

# --- Win32 ---
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PIPE_ACCESS_INBOUND = 0x00000001
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_UNLIMITED_INSTANCES = 255
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
ERROR_PIPE_CONNECTED = 535
ERROR_BROKEN_PIPE = 109
ERROR_MORE_DATA = 234
# 256 KB (was 64 KB): bigger pipe buffers absorb burst writes from heavily
# hooked samples without the monitor blocking on a full pipe.
_BUFSIZE = 262144

_k32.CreateNamedPipeW.restype = wintypes.HANDLE
_k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
_k32.ConnectNamedPipe.restype = wintypes.BOOL
_k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
_k32.DisconnectNamedPipe.restype = wintypes.BOOL
_k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
_k32.ReadFile.restype = wintypes.BOOL
_k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CreateFileW.restype = wintypes.HANDLE
_k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]


class ApiTraceCollector:
    """Accepts monitor connections on a named pipe and writes their events to a
    JSONL file. Thread-per-connection; one always-pending listener so a new
    child's monitor never races a closed pipe."""

    def __init__(self, pipe_name: str, out_path: str, max_events: int = 0, quiet: bool = False,
                 pids_path: Optional[str] = None):
        self.pipe_path = PIPE_PREFIX + pipe_name
        self.out_path = out_path
        self.pids_path = pids_path
        self.max_events = max_events
        self.quiet = quiet
        self._stop = threading.Event()
        self._threads = []
        self._out_lock = threading.Lock()
        self._out = None
        self.event_count = 0
        self.connections = 0
        # Distinct pids seen across all monitor connections (the sample, its
        # children, AND any process the sample injected into that the monitor
        # followed). Mirrored to pids_path so the guest wait-loop can adopt
        # injected processes into the sample tree (2026-09-11).
        self.pids = set()
        self._pids_dirty = False

    def start(self):
        self._out = open(self.out_path, "w", encoding="utf-8", buffering=1)
        if self.pids_path:
            self._write_pids()  # truncate any stale state from a prior run
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _write_pids(self):
        """Atomically mirror the attached-pid set (tmp + replace) so the
        wait-loop never reads a partial file."""
        try:
            tmp = self.pids_path + ".tmp"
            with open(tmp, "w", encoding="ascii") as f:
                for pid in sorted(self.pids):
                    f.write(f"{pid}\n")
            os.replace(tmp, self.pids_path)
            self._pids_dirty = False
        except OSError:
            pass

    def _accept_loop(self):
        while not self._stop.is_set():
            h = _k32.CreateNamedPipeW(
                self.pipe_path,
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                _BUFSIZE, _BUFSIZE, 0, None,
            )
            if h == INVALID_HANDLE_VALUE or h is None:
                if not self.quiet:
                    print(f"[collector] CreateNamedPipe failed: {ctypes.get_last_error()}", file=sys.stderr)
                return
            ok = _k32.ConnectNamedPipe(h, None)
            if self._stop.is_set():
                _k32.CloseHandle(h)
                return
            if ok or ctypes.get_last_error() == ERROR_PIPE_CONNECTED:
                self.connections += 1
                t = threading.Thread(target=self._read_client, args=(h,), daemon=True)
                t.start()
                self._threads.append(t)
            else:
                _k32.CloseHandle(h)

    def _read_client(self, h):
        buf = ctypes.create_string_buffer(_BUFSIZE)
        nread = wintypes.DWORD(0)
        pending = b""
        events_before = self.event_count
        err = 0
        try:
            while not self._stop.is_set():
                ok = _k32.ReadFile(h, buf, _BUFSIZE, ctypes.byref(nread), None)
                if not ok:
                    err = ctypes.get_last_error()
                    if err == ERROR_MORE_DATA:
                        pass  # keep the partial read below
                    else:
                        break  # ERROR_BROKEN_PIPE etc -- client (traced proc) gone
                if nread.value == 0:
                    break
                pending += buf.raw[:nread.value]
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    self._handle_line(line)
        finally:
            _k32.DisconnectNamedPipe(h)
            _k32.CloseHandle(h)
            # Quiet-disconnect logging: a client that delivered zero events
            # (or died with an unexpected error) is exactly the silent-loss
            # case that used to make an empty trace unexplainable.
            delivered = self.event_count - events_before
            if not self.quiet and delivered == 0 and not self._stop.is_set():
                print(f"[collector] client disconnected with 0 events (err={err})", file=sys.stderr)

    def _handle_line(self, raw: bytes):
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return
        try:
            event = json.loads(text)
        except json.JSONDecodeError:
            event = {"api": "__malformed__", "raw": text[:512]}
        # Stamp a receive time so the telemetry merge-sort can order these
        # against Sysmon/AMSI events (the DLL does not carry a wall clock).
        event.setdefault("ts", time.time())
        event.setdefault("source", "apitrace")
        with self._out_lock:
            pid = event.get("pid")
            if isinstance(pid, int) and pid not in self.pids:
                self.pids.add(pid)
                self._pids_dirty = True
            self._out.write(json.dumps(event, ensure_ascii=False) + "\n")
            self.event_count += 1
            if self.max_events and self.event_count >= self.max_events:
                self._stop.set()

    def stop(self):
        self._stop.set()
        # Unblock a pending ConnectNamedPipe by connecting a throwaway client.
        h = _k32.CreateFileW(self.pipe_path, GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if h != INVALID_HANDLE_VALUE and h is not None:
            _k32.CloseHandle(h)
        if getattr(self, "_accept_thread", None):
            self._accept_thread.join(timeout=3)
        for t in self._threads:
            t.join(timeout=1)
        if self._out:
            with self._out_lock:
                self._out.flush()
                self._out.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pipe", default="sandbox_apitrace", help="pipe name (default sandbox_apitrace)")
    parser.add_argument("--out", default="apitrace.jsonl", help="output JSONL path")
    parser.add_argument("--max-seconds", type=float, default=0.0, help="auto-stop after N seconds (0 = until stop-file/Ctrl-C)")
    parser.add_argument("--max-events", type=int, default=0, help="auto-stop after N events (0 = unlimited)")
    parser.add_argument("--stop-file", default=None, help="stop as soon as this file appears")
    parser.add_argument("--pids-file", default=None,
                        help="mirror attached pids here (one per line) for the guest wait-loop")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    col = ApiTraceCollector(args.pipe, args.out, max_events=args.max_events, quiet=args.quiet,
                            pids_path=args.pids_file)
    col.start()
    if not args.quiet:
        print(f"[collector] listening on {col.pipe_path} -> {args.out}", file=sys.stderr)

    deadline = time.time() + args.max_seconds if args.max_seconds else None
    last_pids_flush = time.time()
    try:
        while not col._stop.is_set():
            if deadline and time.time() >= deadline:
                break
            if args.stop_file and os.path.exists(args.stop_file):
                break
            if col.pids_path and col._pids_dirty and time.time() - last_pids_flush >= 1.0:
                col._write_pids()
                last_pids_flush = time.time()
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        col.stop()
        if col.pids_path and col._pids_dirty:
            col._write_pids()

    if not args.quiet:
        print(f"[collector] stopped: {col.connections} connection(s), {col.event_count} event(s) -> {args.out}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
