"""Offline unit tests for the interactive console (orchestrator/console.py).

No VM, no PowerShell: HyperVManager and the helper subprocess are mocked.
Run standalone (python tests\\test_console.py) or under pytest.
"""

import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.console import ConsoleManager  # noqa: E402


def make_config():
    class Cfg:
        console = {
            "enabled": True,
            "width": 1280,
            "height": 800,
            "fps": 10.0,  # fast frames so tests don't wait
            "input_timeout_seconds": 2,
            "auto_close_minutes": 30,
        }
        paths = {
            "logs_dir": tempfile.mkdtemp(prefix="console_test_"),
            "scripts_dir": str(Path(__file__).resolve().parent.parent / "scripts"),
        }
        telemetry = {"guest_agent_dir": "C:\\SandboxAgent"}
        hyperv = {"analysis_vm": "test-vm", "vm_username": "u", "vm_password": "p"}

    return Cfg()


def make_mgr():
    mgr = ConsoleManager(make_config())
    mgr.hv = mock.Mock()  # never touch Hyper-V in tests
    return mgr


# --- coordinate scaling ------------------------------------------------------

def test_scale_with_guest_resolution():
    mgr = make_mgr()
    mgr._guest_resolution = (1920, 1080)
    assert mgr._scale_to_guest(0.5, 0.5) == (960, 540)   # round(959.5)=960 (banker's), round(539.5)=540
    assert mgr._scale_to_guest(0.0, 0.0) == (0, 0)
    assert mgr._scale_to_guest(1.0, 1.0) == (1919, 1079)


def test_scale_falls_back_to_config_resolution():
    mgr = make_mgr()
    assert mgr._guest_resolution is None
    assert mgr._scale_to_guest(1.0, 1.0) == (1279, 799)


def test_scale_rejects_out_of_range():
    mgr = make_mgr()
    for bad in ((1.5, 0.5), (-0.1, 0.5), (0.5, 2.0)):
        try:
            mgr._scale_to_guest(*bad)
            raise AssertionError(f"expected ValueError for {bad}")
        except ValueError:
            pass


# --- input validation ---------------------------------------------------------

def test_input_requires_open_console():
    mgr = make_mgr()
    try:
        mgr.input({"action": "click", "x": 0.5, "y": 0.5})
        raise AssertionError("expected RuntimeError")
    except RuntimeError:
        pass


def test_input_rejects_bad_actions_and_payloads():
    mgr = make_mgr()
    mgr._open = True
    mgr._send_helper = mock.Mock()
    for bad in (
        {"action": "format_c"},
        {"action": "screeninfo"},            # internal-only action
        {"action": "key", "key": ""},
        {"action": "text", "text": ""},
        {"action": "text", "text": "x" * 5000},
    ):
        try:
            mgr.input(bad)
            raise AssertionError(f"expected rejection of {bad}")
        except (ValueError, RuntimeError):
            pass
    mgr._send_helper.assert_not_called()


def test_input_scales_clicks_into_guest_pixels():
    mgr = make_mgr()
    mgr._open = True
    mgr._guest_resolution = (1024, 768)
    sent = []
    mgr._send_helper = lambda cmd: sent.append(cmd)
    mgr.input({"action": "click", "x": 0.25, "y": 0.5})
    assert sent == [{"action": "click", "x": 256, "y": 384}]


# --- report tagging window ----------------------------------------------------

def test_used_between():
    mgr = make_mgr()
    t0 = datetime.now(timezone.utc) - timedelta(minutes=5)
    # closed window
    mgr._usage.append((t0 + timedelta(seconds=10), t0 + timedelta(seconds=20)))
    assert mgr.used_between(t0, t0 + timedelta(seconds=15)) is True       # overlap at end
    assert mgr.used_between(t0 + timedelta(seconds=15), t0 + timedelta(seconds=60)) is True
    assert mgr.used_between(t0 + timedelta(seconds=30), t0 + timedelta(seconds=60)) is False
    # still-open window (closed=None) matches everything after opened
    mgr._usage.append((t0 + timedelta(seconds=40), None))
    assert mgr.used_between(t0 + timedelta(seconds=50), t0 + timedelta(seconds=999)) is True


# --- lifecycle (fully mocked) ---------------------------------------------------

def test_open_requires_running_vm():
    mgr = make_mgr()
    mgr.hv.get_status.return_value = {"State": "Off"}
    try:
        mgr.open()
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "not running" in str(exc)


def test_open_close_happy_path():
    mgr = make_mgr()
    mgr.hv.get_status.return_value = {"State": "Running"}
    mgr.hv.console_input_server_start.return_value = {"Status": "ready"}
    mgr._spawn_helper = mock.Mock()
    mgr._query_screeninfo = mock.Mock(return_value=(1024, 768))
    # frame capture writes the scratch file like the real Get-Thumbnail does
    def fake_capture(path, width_pixels, height_pixels):
        Path(path).write_bytes(b"\x89PNG-fake")
        return {"Status": "captured"}
    mgr.hv.capture_screenshot.side_effect = fake_capture

    status = mgr.open()
    assert status["open"] is True
    assert status["guest_resolution"] == (1024, 768)
    mgr.hv.copy_sample.assert_called_once()
    mgr.hv.console_input_server_start.assert_called_once()

    # a frame lands quickly at fps=10
    deadline = time.time() + 5
    while mgr._frame_bytes is None and time.time() < deadline:
        time.sleep(0.05)
    data, frame_id = mgr.frame()
    assert data == b"\x89PNG-fake" and frame_id >= 1

    status = mgr.close()
    assert status["open"] is False
    mgr.hv.console_input_server_stop.assert_called_once()
    # usage window was recorded and closed -> tagging works
    assert mgr._usage and mgr._usage[-1][1] is not None


def test_open_fails_when_input_server_not_ready():
    mgr = make_mgr()
    mgr.hv.get_status.return_value = {"State": "Running"}
    mgr.hv.console_input_server_start.return_value = {"Status": "not_ready", "LastTaskResult": 1}
    try:
        mgr.open()
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "input server" in str(exc)


def main():
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print(f"PASS {name}")
    print("ALL CONSOLE TESTS PASSED")


if __name__ == "__main__":
    main()
