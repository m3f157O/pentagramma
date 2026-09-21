"""Interactive browser console for the analysis VM (on-demand, opt-in).

Design (docs/interactive-console-streaming.md):
- Video OUT: host-side Hyper-V WMI thumbnail API (HyperVManager.capture_screenshot)
  at console resolution, ~1 fps. Zero guest footprint.
- Input IN: the guest-side console_input_server.ps1 runs in the INTERACTIVE
  session (scheduled task as the logged-on user) and listens on the named
  pipe \\.\pipe\sandbox_console_in. This module spawns a persistent helper
  process (scripts/console_session.ps1) that holds one PowerShell Direct
  session and relays browser input events onto that pipe. PSDirect sessions
  are non-interactive (verified 2026-09-03), so direct SendInput from them
  cannot reach the visible desktop -- the pipe bridge is the point.

Nothing is baked into the golden image: the server is deployed and started
on open, stopped and unregistered on close. Opening the console during a
run tags the report (interactive_console: true) -- interaction changes the
detonation, so such reports are not comparable to corpus baselines.
"""

import json
import queue
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from orchestrator.config import SandboxConfig
from orchestrator.hyperv import HyperVManager

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HELPER_SCRIPT = PROJECT_ROOT / "scripts" / "console_session.ps1"
GUEST_SERVER_SOURCE = PROJECT_ROOT / "agent" / "windows" / "console_input_server.ps1"

ALLOWED_ACTIONS = {"click", "rightclick", "dblclick", "move", "wheel", "key", "text", "screeninfo"}

# Module-level registry: main.py and executor.py must see the SAME manager
# per VM (the executor consults it for report tagging). Keyed by VM name;
# vm_name=None maps to the configured analysis VM (backward compatible).
_console_managers: Dict[str, "ConsoleManager"] = {}
_console_manager_lock = threading.Lock()


def get_console_manager(
    config: Optional[SandboxConfig] = None,
    create: bool = True,
    vm_name: Optional[str] = None,
) -> Optional["ConsoleManager"]:
    with _console_manager_lock:
        key = vm_name or (config.hyperv.get("analysis_vm") if config else None)
        if key is None:
            if not create:
                return None
            raise ValueError("vm_name required (no config to derive the analysis VM from)")
        mgr = _console_managers.get(key)
        if mgr is None and create:
            if config is None:
                raise ValueError("config required to create the console manager")
            mgr = ConsoleManager(config, vm_name=key)
            _console_managers[key] = mgr
        return mgr


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ConsoleManager:
    def __init__(self, config: SandboxConfig, vm_name: Optional[str] = None):
        self.config = config
        self.console_cfg = config.console
        self.hv = HyperVManager(config, vm_name=vm_name)
        self._lock = threading.Lock()

        self._open = False
        self._opened_at: Optional[datetime] = None
        self._last_activity: Optional[datetime] = None
        self._guest_resolution: Optional[Tuple[int, int]] = None

        self._helper: Optional[subprocess.Popen] = None
        self._helper_write_lock = threading.Lock()
        self._acks: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._helper_reader: Optional[threading.Thread] = None
        self._last_error: Optional[str] = None

        self._frame_bytes: Optional[bytes] = None
        self._frame_id = 0
        self._frame_at: Optional[datetime] = None
        self._frame_thread: Optional[threading.Thread] = None
        self._frame_stop = threading.Event()

        self._frame_dir = Path(config.paths.get("logs_dir", "logs")) / "console"

        # Usage windows for report tagging: (opened_at, closed_at or None)
        self._usage: List[Tuple[datetime, Optional[datetime]]] = []

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def open(self) -> Dict[str, Any]:
        with self._lock:
            if self._open:
                return self.status()
            if not self.console_cfg.get("enabled", True):
                raise RuntimeError("console is disabled in config (console.enabled)")

            status = self.hv.get_status()
            if status.get("State") != "Running":
                raise RuntimeError(f"VM is not running (state: {status.get('State', 'unknown')})")

            # Deploy the guest server (idempotent; also covers idle-VM opens
            # where no per-run agent copy has happened). Retry once: opening
            # right after a VM restore/boot can hit a transient broken
            # PSDirect session (PSSessionStateBroken).
            agent_dir = self.config.telemetry.get("guest_agent_dir", "C:\\SandboxAgent")
            start = None
            last_exc: Optional[Exception] = None
            for attempt in range(3):
                try:
                    self.hv.copy_sample(
                        str(GUEST_SERVER_SOURCE),
                        destination_folder=agent_dir,
                        destination_filename="console_input_server.ps1",
                    )
                    start = self.hv.console_input_server_start(agent_dir=agent_dir)
                    last_exc = None
                    break
                except Exception as exc:  # transient VM-boot race
                    last_exc = exc
                    time.sleep(3)
            if last_exc is not None:
                raise last_exc
            if start.get("Status") != "ready":
                raise RuntimeError(f"console input server failed to start: {start}")

            self._spawn_helper()
            try:
                self._guest_resolution = self._query_screeninfo()
            except Exception:
                self._stop_helper()
                raise

            self._frame_stop.clear()
            self._frame_thread = threading.Thread(target=self._frame_loop, daemon=True)
            self._frame_thread.start()

            self._open = True
            self._opened_at = _utcnow()
            self._last_activity = self._opened_at
            self._usage.append((self._opened_at, None))
            return self.status()

    def close(self) -> Dict[str, Any]:
        with self._lock:
            if not self._open:
                return self.status()
            self._frame_stop.set()
            try:
                self.hv.console_input_server_stop()
            except Exception as exc:
                self._last_error = f"input server stop failed: {exc}"
            self._stop_helper()
            self._open = False
            if self._usage and self._usage[-1][1] is None:
                self._usage[-1] = (self._usage[-1][0], _utcnow())
            return self.status()

    # ------------------------------------------------------------------
    # status / frames / input
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        frame_age = None
        if self._frame_at is not None:
            frame_age = round((_utcnow() - self._frame_at).total_seconds(), 1)
        return {
            "open": self._open,
            "enabled": self.console_cfg.get("enabled", True),
            "width": self.console_cfg.get("width", 1024),
            "height": self.console_cfg.get("height", 768),
            "fps": self.console_cfg.get("fps", 0.7),
            "guest_resolution": self._guest_resolution,
            "frame_id": self._frame_id,
            "frame_age_seconds": frame_age,
            "last_error": self._last_error,
        }

    def frame(self) -> Tuple[bytes, int]:
        """Latest console frame (PNG bytes, frame id). Raises if none yet."""
        self._last_activity = _utcnow()
        if self._frame_bytes is None:
            raise FileNotFoundError("no frame captured yet")
        return self._frame_bytes, self._frame_id

    def input(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Validate + forward one browser input event to the guest."""
        if not self._open:
            raise RuntimeError("console is not open")
        self._last_activity = _utcnow()

        action = event.get("action")
        if action not in ALLOWED_ACTIONS - {"screeninfo"}:
            raise ValueError(f"invalid action: {action}")

        cmd: Dict[str, Any] = {"action": action}
        if action in ("click", "rightclick", "dblclick", "move"):
            cmd["x"], cmd["y"] = self._scale_to_guest(event.get("x"), event.get("y"))
        elif action == "wheel":
            cmd["delta"] = int(event.get("delta", 0))
        elif action == "key":
            key = str(event.get("key", "")).strip()
            if not key or len(key) > 40:
                raise ValueError("invalid key")
            cmd["key"] = key
        elif action == "text":
            text = str(event.get("text", ""))
            if not text or len(text) > 2000:
                raise ValueError("invalid text")
            cmd["text"] = text

        self._send_helper(cmd)
        return {"ok": True}

    # ------------------------------------------------------------------
    # report tagging
    # ------------------------------------------------------------------

    def used_between(self, start: datetime, end: datetime) -> bool:
        """True if the console was open at any point inside [start, end]."""
        for opened, closed in self._usage:
            window_end = closed or _utcnow()
            if opened <= end and window_end >= start:
                return True
        return False

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _scale_to_guest(self, x: Any, y: Any) -> Tuple[int, int]:
        """Browser sends coordinates RELATIVE to the displayed image (0..1);
        scale to the guest's actual screen resolution."""
        xf, yf = float(x), float(y)
        if not (0.0 <= xf <= 1.0 and 0.0 <= yf <= 1.0):
            raise ValueError("coordinates must be relative (0..1)")
        if self._guest_resolution:
            gw, gh = self._guest_resolution
        else:
            gw = int(self.console_cfg.get("width", 1024))
            gh = int(self.console_cfg.get("height", 768))
        return int(round(xf * (gw - 1))), int(round(yf * (gh - 1)))

    def _spawn_helper(self) -> None:
        self._acks = queue.Queue()
        self._helper = subprocess.Popen(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", str(HELPER_SCRIPT),
                "-VMName", self.hv.vm_name,
                "-CredentialUsername", self.config.vm_creds(self.hv.vm_name)[0] or "",
                "-CredentialPassword", self.config.vm_creds(self.hv.vm_name)[1] or "",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            bufsize=1,
        )
        self._helper_reader = threading.Thread(target=self._read_acks, daemon=True)
        self._helper_reader.start()

    def _stop_helper(self) -> None:
        helper = self._helper
        self._helper = None
        if helper is not None:
            try:
                helper.kill()
            except Exception:
                pass

    def _read_acks(self) -> None:
        helper = self._helper
        if helper is None or helper.stdout is None:
            return
        for line in helper.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._acks.put(json.loads(line))
            except json.JSONDecodeError:
                continue

    def _send_helper(self, cmd: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Write one command to the helper and consume its ack. Returns the
        ack; raises RuntimeError when the guest reports failure."""
        helper = self._helper
        if helper is None or helper.stdin is None or helper.poll() is not None:
            raise RuntimeError("console input helper is not running")
        with self._helper_write_lock:
            helper.stdin.write(json.dumps(cmd) + "\n")
            helper.stdin.flush()
        try:
            ack = self._acks.get(timeout=float(self.console_cfg.get("input_timeout_seconds", 5)))
        except queue.Empty:
            # The guest round-trip can legitimately outlast the timeout under
            # load; don't fail the click, just note it.
            self._last_error = "input ack timeout (command may still have landed)"
            return None
        if not ack.get("ok"):
            self._last_error = ack.get("error")
            raise RuntimeError(f"guest input failed: {ack.get('error')}")
        self._last_error = None
        return ack

    def _query_screeninfo(self) -> Optional[Tuple[int, int]]:
        ack = self._send_helper({"action": "screeninfo"})
        if not ack or not ack.get("output"):
            return None
        try:
            info = json.loads(ack["output"])
            w, h = int(info["Width"]), int(info["Height"])
            if w > 0 and h > 0:
                return (w, h)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass
        return None

    def _frame_loop(self) -> None:
        cfg = self.console_cfg
        # Prefer the guest's real resolution (queried at open): the WMI
        # thumbnail API rejects aspect ratios that don't match the console
        # framebuffer (ReturnValue 32775).
        if self._guest_resolution:
            width, height = self._guest_resolution
        else:
            width = int(cfg.get("width", 1024))
            height = int(cfg.get("height", 768))
        interval = 1.0 / max(float(cfg.get("fps", 0.7)), 0.1)
        auto_close = float(cfg.get("auto_close_minutes", 30)) * 60
        self._frame_dir.mkdir(parents=True, exist_ok=True)
        scratch = self._frame_dir / "frame.png"
        failures = 0

        while not self._frame_stop.is_set():
            try:
                result = self.hv.capture_screenshot(str(scratch), width_pixels=width, height_pixels=height)
                if result.get("Status") == "captured":
                    self._frame_bytes = scratch.read_bytes()
                    self._frame_id += 1
                    self._frame_at = _utcnow()
                    failures = 0
                else:
                    failures += 1
                    self._last_error = f"frame capture: {result.get('Status', 'unknown')}"
            except Exception as exc:
                failures += 1
                self._last_error = f"frame capture: {exc}"

            # VM went away / repeated failure -> close the session.
            if failures >= 5:
                break
            # Idle auto-close (no frame fetches and no input for N minutes).
            if self._last_activity and (_utcnow() - self._last_activity).total_seconds() > auto_close:
                break
            self._frame_stop.wait(interval)

        if self._open:
            try:
                self.close()
            except Exception:
                pass

