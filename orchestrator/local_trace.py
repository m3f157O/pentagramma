"""Local (host-side) live API tracing.

Launches a user-selected program under the MinHook behavioral monitor
(agent/windows/monitor_src) ON THE ORCHESTRATOR HOST -- no VM involved -- and
streams the hooked calls over the usual named pipe into a local
apitrace.jsonl that the UI polls (the "Live Trace" page).

Reuses the exact sandbox components, host-side:
  monitor_loader(+_x86).exe  -- suspended-launch + inject + handshake
  monitor_x64/x86.dll        -- 37-hook MinHook engine, child-following
  apitrace_collector.py      -- named-pipe server (pure stdlib ctypes)

One session at a time (mirrors the one-VM constraint).
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


def _log_error(base_dir: Path, what: str) -> None:
    """Local-trace failures must be debuggable without the uvicorn console
    (its shutdown noise buries real tracebacks)."""
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
        with (base_dir / "server.log").open("a", encoding="utf-8") as fh:
            fh.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} {what} ===\n")
            fh.write(traceback.format_exc())
    except OSError:
        pass

# Machine field of the PE COFF header -> loader/DLL pair to use.
_PE_MACHINE_X64 = 0x8664
_PE_MACHINE_X86 = 0x014C


def _pe_bitness(path: Path) -> str:
    with path.open("rb") as fh:
        head = fh.read(0x400)
    if len(head) < 0x40 or head[:2] != b"MZ":
        raise ValueError("not a PE file (no MZ header)")
    pe_off = int.from_bytes(head[0x3C:0x40], "little")
    machine = int.from_bytes(head[pe_off + 4:pe_off + 6], "little")
    if machine == _PE_MACHINE_X64:
        return "x64"
    if machine == _PE_MACHINE_X86:
        return "x86"
    raise ValueError(f"unsupported PE machine type 0x{machine:04x}")


class LocalTraceManager:
    def __init__(self, cfg: Any):
        paths = cfg.paths
        self.agent_dir = Path(paths["agent_dir"])
        self.base_dir = Path(paths["logs_dir"]) / "local-trace"
        # RLock, not Lock: start()/stop() call self.status() while holding the
        # lock -- a plain Lock self-deadlocks there (that was the live-trace
        # hang: every request queued behind the first deadlocked start()).
        self._lock = threading.RLock()
        self._session: Optional[Dict[str, Any]] = None
        # Clean up orphans from previous orchestrator lifetimes up front
        # (they squat the shared pipe name and steal new sessions' events).
        self._sweep_orphans()

    # -- orphan sweep -------------------------------------------------------

    def _sweep_orphans(self) -> None:
        """Kill collector/loader processes from PREVIOUS sessions.

        Orphaned collectors keep a server instance on the SAME pipe name and
        win the accept race against a new session's collector -- the monitor
        then streams events into the dead session's file and the new session
        shows zero events (observed in bring-up: a two-hours-old session file
        was still growing while new sessions captured nothing). The
        orchestrator runs elevated, so a WMI command-line match sees (and can
        kill) elevated orphans -- unlike PID-file tracking, this also covers
        sessions that predate session.json.

        Only ever called when NO session is running (start() raises first), so
        the current session's own collector never matches itself. Guest-VM
        collectors are remote processes and unaffected.
        """
        ps = (
            "Get-CimInstance Win32_Process | Where-Object { "
            "$_.CommandLine -match 'apitrace_collector\\.py' -or "
            "$_.CommandLine -match 'monitor_loader' } | "
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
        )
        try:
            subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _write_session_meta(self, s: Dict[str, Any]) -> None:
        try:
            (s["dir"] / "session.json").write_text(json.dumps({
                "collector_pid": s["collector"].pid,
                "loader_pid": s["loader"].pid,
            }), encoding="utf-8")
        except OSError:
            pass

    def _finalize_meta(self, s: Dict[str, Any]) -> None:
        """Archive the session metadata when it ends (stop or natural target
        exit) -- this is what the Traces history page lists."""
        try:
            (s["dir"] / "session.json").write_text(json.dumps({
                "id": s["id"],
                "target": s["target"],
                "arguments": s["arguments"],
                "bitness": s["bitness"],
                "started_at": s["started_at"],
                "ended_at": time.time(),
                "status": s["status"],
                "exit_code": s["exit_code"],
                "total_events": self._count_events(s["out_file"]),
                "collector_pid": s["collector"].pid,
                "loader_pid": s["loader"].pid,
            }), encoding="utf-8")
        except OSError:
            pass

    # -- lifecycle ---------------------------------------------------------

    def start(self, target: str, arguments: str = "") -> Dict[str, Any]:
        target_path = Path(target)
        if not target_path.is_file():
            raise FileNotFoundError(f"target not found: {target}")
        if target_path.suffix.lower() != ".exe":
            raise ValueError("only .exe targets are supported (scripts need the sandbox's launchers)")
        bitness = _pe_bitness(target_path)
        loader = self.agent_dir / ("monitor_loader.exe" if bitness == "x64" else "monitor_loader_x86.exe")
        dll = self.agent_dir / ("monitor_x64.dll" if bitness == "x64" else "monitor_x86.dll")
        for artifact in (loader, dll):
            if not artifact.is_file():
                raise FileNotFoundError(f"monitor artifact missing: {artifact} (run scripts/build_monitor.ps1)")

        with self._lock:
            if self._session and self._session["status"] == "running":
                raise RuntimeError("a local trace is already running -- stop it first")

            self._sweep_orphans()

            session_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
            sdir = self.base_dir / session_id
            sdir.mkdir(parents=True, exist_ok=True)
            out_file = sdir / "apitrace.jsonl"
            stop_file = sdir / "stop.flag"
            collector_log = (sdir / "collector.log").open("w", encoding="utf-8")
            loader_log = (sdir / "loader.log").open("w", encoding="utf-8")

            # 1. pipe server first (the monitor connects on DLL load)
            collector = subprocess.Popen(
                [sys.executable, str(self.agent_dir / "apitrace_collector.py"),
                 "--out", str(out_file), "--stop-file", str(stop_file), "--quiet"],
                stdout=collector_log, stderr=collector_log,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            time.sleep(0.8)  # let the pipe exist before the monitor connects

            # 2. suspended-launch the target + inject (pre-first-instruction)
            env = os.environ.copy()
            env["MONITOR_PID_FILE"] = str(sdir / "target.pid")  # loader writes the real target pid here
            cmd = [str(loader), str(dll), str(target_path)] + ([arguments] if arguments.strip() else [])
            try:
                loader_proc = subprocess.Popen(
                    cmd, stdout=loader_log, stderr=loader_log, env=env,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception:
                # don't leak the collector if the loader never starts
                stop_file.touch()
                try:
                    collector.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    collector.terminate()
                raise

            self._session = {
                "id": session_id,
                "target": str(target_path),
                "arguments": arguments,
                "bitness": bitness,
                "started_at": time.time(),
                "status": "running",
                "loader": loader_proc,
                "collector": collector,
                "out_file": out_file,
                "stop_file": stop_file,
                "dir": sdir,
                "exit_code": None,
            }
            self._write_session_meta(self._session)
            return self.status()

    @staticmethod
    def _target_pid(s: Dict[str, Any]) -> Optional[int]:
        """The loader drops the real target's pid here (MONITOR_PID_FILE) --
        needed to force-kill a target whose injected monitor wedged its exit
        path (observed: traced notepad survives WM_CLOSE) after the loader is
        already gone."""
        try:
            return int((s["dir"] / "target.pid").read_text().strip())
        except (OSError, ValueError):
            return None

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            s = self._session
            if not s:
                raise RuntimeError("no local trace session")
            if s["status"] == "running":
                # stop.flag tells the collector to wrap up; killing the loader
                # kills the target (kill-on-close job, see monitor_loader.cpp).
                s["stop_file"].touch()
                if s["loader"].poll() is None:
                    s["loader"].terminate()
                    try:
                        s["loader"].wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        s["loader"].kill()
                # Belt and braces: if the target outlived its loader (monitor
                # wedged its exit path), kill it explicitly by recorded pid.
                tpid = self._target_pid(s)
                if tpid:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(tpid)],
                                   capture_output=True)
                try:
                    s["collector"].wait(timeout=5)
                except subprocess.TimeoutExpired:
                    s["collector"].terminate()
                s["status"] = "stopped"
            self._finalize_meta(s)
            return self.status()

    def _refresh(self, s: Dict[str, Any]) -> None:
        if s["status"] == "running":
            rc = s["loader"].poll()
            if rc is not None:
                # target exited (loader forwards its exit code); let the
                # collector flush, then close it out.
                s["exit_code"] = rc
                s["status"] = "finished"
                s["stop_file"].touch()
                try:
                    s["collector"].wait(timeout=5)
                except subprocess.TimeoutExpired:
                    s["collector"].terminate()
                self._finalize_meta(s)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            s = self._session
            if not s:
                return {"active": False}
            self._refresh(s)
            return {
                "active": True,
                "id": s["id"],
                "target": s["target"],
                "arguments": s["arguments"],
                "bitness": s["bitness"],
                "status": s["status"],
                "exit_code": s["exit_code"],
                "started_at": s["started_at"],
                "elapsed_seconds": round(time.time() - s["started_at"], 1),
                "total_events": self._count_events(s["out_file"]),
            }

    # -- history (Traces page) ----------------------------------------------

    _SESSION_ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")

    def history(self) -> Dict[str, Any]:
        """Past sessions, newest first (the Traces page). The active session
        is excluded -- it lives on the Live Trace page."""
        out: List[Dict[str, Any]] = []
        if not self.base_dir.exists():
            return {"sessions": []}
        for sdir in sorted(self.base_dir.iterdir(), reverse=True):
            if not sdir.is_dir() or not self._SESSION_ID_RE.match(sdir.name):
                continue
            if self._session and sdir.name == self._session["id"] and self._session["status"] == "running":
                continue
            meta_file = sdir / "session.json"
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    meta = {}
            else:
                meta = {}
            meta.setdefault("id", sdir.name)
            meta.setdefault("target", "(legacy session)")
            out_file = sdir / "apitrace.jsonl"
            meta["size_bytes"] = out_file.stat().st_size if out_file.exists() else 0
            out.append(meta)
        return {"sessions": out}

    def history_events(self, session_id: str, offset: int = 0, limit: int = 500, q: str = "") -> Dict[str, Any]:
        """Read an ARCHIVED session's trace (same cursor semantics as the live
        events endpoint). session_id is regex-validated -- it's a directory
        name, never a path."""
        if not self._SESSION_ID_RE.match(session_id):
            raise ValueError("invalid session id")
        out_file = self.base_dir / session_id / "apitrace.jsonl"
        events: List[Dict[str, Any]] = []
        total = 0
        next_offset = offset
        if out_file.exists():
            needle = q.lower()
            with out_file.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    total = i + 1
                    if i < offset:
                        continue
                    next_offset = i + 1
                    if needle and needle not in line.lower():
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                    if len(events) >= limit:
                        break
        return {"id": session_id, "total": total, "offset": offset,
                "next_offset": next_offset, "events": events}

    @staticmethod
    def _count_events(out_file: Path) -> int:
        if not out_file.exists():
            return 0
        with out_file.open("rb") as fh:
            return sum(1 for _ in fh)

    def events(self, offset: int = 0, limit: int = 500, q: str = "") -> Dict[str, Any]:
        with self._lock:
            s = self._session
            if not s:
                return {"active": False, "total": 0, "offset": offset, "events": []}
            self._refresh(s)
            out_file = s["out_file"]

        events: List[Dict[str, Any]] = []
        total = 0
        next_offset = offset
        if out_file.exists():
            needle = q.lower()
            with out_file.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    total = i + 1
                    if i < offset:
                        continue
                    next_offset = i + 1  # raw lines consumed (q-filter skips still advance the cursor)
                    if needle and needle not in line.lower():
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                    if len(events) >= limit:
                        break
        return {
            "active": True,
            "session_status": s["status"],
            "total": total,
            "offset": offset,
            "next_offset": next_offset,
            "events": events,
        }
