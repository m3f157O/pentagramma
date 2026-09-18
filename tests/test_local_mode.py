"""Offline unit tests for local mode (sandbox.mode=local).

No VM, no elevated rights, no detonation: LocalTransport's ps1 calls are
monkeypatched/captured; clean_local_state runs against temp dirs.
Run standalone (python tests\\test_local_mode.py) or under pytest.
"""

import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.backends import make_backend  # noqa: E402
from orchestrator.config import SandboxConfig, set_mode  # noqa: E402
from orchestrator.hyperv import HyperVManager, LocalTransport  # noqa: E402

SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent / "scripts")


class FakeCfg:
    """Attribute-section config stand-in (same idiom as test_console.py)."""

    def __init__(self, tmp: Path):
        self.hyperv = {}  # deliberately absent analysis_vm: local deployments may not have one
        self.paths = {"scripts_dir": SCRIPTS_DIR}
        agent = tmp / "SandboxAgent"
        dest = tmp / "Sandbox"
        dumps = agent / "dumps"
        for d in (agent, dest, dumps):
            d.mkdir(parents=True, exist_ok=True)
        self.telemetry = {
            "guest_agent_dir": str(agent),
            "guest_output_file": str(agent / "telemetry.jsonl"),
        }
        self.sample_execution = {"guest_destination_folder": str(dest)}
        self.process_dumps = {"guest_output_dir": str(dumps)}
        self.network_capture = {"guest_output_dir": str(agent)}
        self.behavioral_tracing = {
            "guest_apitrace_file": str(agent / "apitrace.jsonl"),
            "guest_stop_file": str(agent / "apitrace_stop.flag"),
            "guest_pid_file": str(agent / "sample_pid.txt"),
        }
        self.guardian = {
            "guest_output_file": str(agent / "guardian.jsonl"),
            "guest_stop_file": str(agent / "guardian_stop.flag"),
        }
        self.mode = "local"
        self.is_local_mode = True


def _write_config(tmp: Path, extra: str = "") -> Path:
    p = tmp / "config.yaml"
    p.write_text(
        "paths:\n  scripts_dir: \"%s\"\nhyperv:\n  analysis_vm: \"vm\"\n%s" % (SCRIPTS_DIR.replace("\\", "\\\\"), extra),
        encoding="utf-8",
    )
    return p


# --- config parsing -----------------------------------------------------------

def test_config_default_mode_is_hyperv():
    with tempfile.TemporaryDirectory() as td:
        cfg = SandboxConfig(_write_config(Path(td)))
        assert cfg.mode == "hyperv"
        assert cfg.is_local_mode is False


# --- set_mode (GUI mode switch) -------------------------------------------------

def test_set_mode_roundtrip_preserves_comments_and_backs_up():
    with tempfile.TemporaryDirectory() as td:
        p = _write_config(Path(td), "sandbox:\n  mode: hyperv            # hyperv | local\n")
        prev = set_mode("local", p)
        assert prev == "hyperv"
        assert SandboxConfig(p).mode == "local"
        text = p.read_text(encoding="utf-8")
        assert "# hyperv | local" in text  # inline comment preserved
        assert p.with_suffix(".yaml.bak").exists()  # one-time backup written
        prev = set_mode("HYPERV", p)  # case-insensitive
        assert prev == "local"
        assert SandboxConfig(p).mode == "hyperv"
        prev = set_mode("hyperv", p)  # no-op: no rewrite, no error
        assert prev == "hyperv"


def test_set_mode_rejects_garbage():
    import pytest

    with tempfile.TemporaryDirectory() as td:
        p = _write_config(Path(td), "sandbox:\n  mode: hyperv\n")
        with pytest.raises(ValueError):
            set_mode("bogus", p)
        with pytest.raises(ValueError):
            set_mode("", p)
        assert SandboxConfig(p).mode == "hyperv"  # untouched


def test_set_mode_requires_sandbox_section_and_mode_key():
    import pytest

    with tempfile.TemporaryDirectory() as td:
        p = _write_config(Path(td))  # no sandbox: section at all
        with pytest.raises(ValueError):
            set_mode("local", p)
        # sandbox: section exists but the NEXT top-level section comes first
        p2 = _write_config(Path(td), "sandbox:\ntelemetry:\n  sysmon_service_name: x\n")
        with pytest.raises(ValueError):
            set_mode("local", p2)


# --- vm_creds (per-VM credential list) ------------------------------------------

def test_vm_creds_list_hit():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "config.yaml"
        p.write_text(
            "hyperv:\n"
            "  analysis_vm: a\n"
            "  vms:\n"
            "    - name: a\n"
            "      username: gigi\n"
            "      password: pw-a\n"
            "    - name: b\n"
            "      username: lab\n"
            "      password: pw-b\n",
            encoding="utf-8",
        )
        cfg = SandboxConfig(p)
        assert cfg.vm_creds("a") == ("gigi", "pw-a")
        assert cfg.vm_creds("b") == ("lab", "pw-b")
        assert cfg.vm_creds("nonexistent") == (None, None)  # no hidden defaults


def test_vm_creds_legacy_fallback():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "config.yaml"
        p.write_text(
            "hyperv:\n"
            "  analysis_vm: vm\n"
            "  vm_username: gigi\n"
            "  vm_password: gigi\n",
            encoding="utf-8",
        )
        cfg = SandboxConfig(p)
        assert cfg.vm_creds("vm") == ("gigi", "gigi")  # legacy top-level keys still work


def test_vm_creds_empty_when_unconfigured():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "config.yaml"
        p.write_text("hyperv:\n  analysis_vm: vm\n", encoding="utf-8")
        assert SandboxConfig(p).vm_creds("vm") == (None, None)


def test_vm_creds_vms_file_roundtrip_and_precedence():
    """config/vms.yaml (GUI-managed) is written by set_vm_credentials and
    takes precedence over the config.yaml hyperv.vms list."""
    import orchestrator.config as config_mod

    with tempfile.TemporaryDirectory() as td:
        cfg_path = Path(td) / "config.yaml"
        cfg_path.write_text(
            "hyperv:\n"
            "  analysis_vm: a\n"
            "  vms:\n"
            "    - name: a\n"
            "      username: old\n"
            "      password: oldpw\n",
            encoding="utf-8",
        )
        vms_path = Path(td) / "vms.yaml"
        with mock.patch.object(config_mod, "_vms_file_path", lambda: vms_path):
            # vms.yaml wins once written
            config_mod.set_vm_credentials("a", "gigi", "newpw")
            assert SandboxConfig(cfg_path).vm_creds("a") == ("gigi", "newpw")
            # update in place (same VM, no duplicate entry)
            config_mod.set_vm_credentials("a", "gigi", "newpw2")
            assert SandboxConfig(cfg_path).vm_creds("a") == ("gigi", "newpw2")
            data = config_mod._read_vms_file()
            assert len([e for e in data["vms"] if e["name"] == "a"]) == 1
            # delete falls back to config.yaml list entry
            assert config_mod.delete_vm_credentials("a") is True
            assert SandboxConfig(cfg_path).vm_creds("a") == ("old", "oldpw")
            assert config_mod.delete_vm_credentials("a") is False  # already gone


def test_set_vm_credentials_validates_input():
    import orchestrator.config as config_mod
    import pytest

    with tempfile.TemporaryDirectory() as td:
        with mock.patch.object(config_mod, "_vms_file_path", lambda: Path(td) / "vms.yaml"):
            with pytest.raises(ValueError):
                config_mod.set_vm_credentials("", "u", "p")
            with pytest.raises(ValueError):
                config_mod.set_vm_credentials("vm", "", "p")
        assert not (Path(td) / "vms.yaml").exists()


def test_config_local_mode():
    with tempfile.TemporaryDirectory() as td:
        cfg = SandboxConfig(_write_config(Path(td), "sandbox:\n  mode: local\n"))
        assert cfg.mode == "local"
        assert cfg.is_local_mode is True


# --- backend factory ------------------------------------------------------------

def test_make_backend_hyperv():
    with tempfile.TemporaryDirectory() as td:
        cfg = SandboxConfig(_write_config(Path(td)))
        assert type(make_backend(cfg)) is HyperVManager


def test_make_backend_local():
    with tempfile.TemporaryDirectory() as td:
        cfg = SandboxConfig(_write_config(Path(td), "sandbox:\n  mode: local\n"))
        backend = make_backend(cfg)
        assert type(backend) is LocalTransport
        assert backend.vm_name == "local"  # never leaks hyperv.analysis_vm into local-mode reports


def test_local_transport_tolerates_missing_hyperv_section():
    with tempfile.TemporaryDirectory() as td:
        backend = LocalTransport(FakeCfg(Path(td)))
        assert backend.vm_name == "local"


# --- LocalTransport verb surface -------------------------------------------------

def test_local_transport_lifecycle_noops():
    with tempfile.TemporaryDirectory() as td:
        lt = LocalTransport(FakeCfg(Path(td)))
        for name, args in (("ensure_snapshot", ()), ("restore_snapshot", ()), ("recapture_snapshot", ()),
                           ("stop_vm", ()), ("restart_guest", ()), ("copy_agent", ("src",))):
            res = getattr(lt, name)(*args)
            assert res["Status"] == "skipped" and res["Reason"] == "local-mode", res
        start = lt.start_vm()
        assert start["State"] == "Running" and start["IPAddress"] == "127.0.0.1"


def test_local_transport_injects_localmode_flag():
    with tempfile.TemporaryDirectory() as td:
        lt = LocalTransport(FakeCfg(Path(td)))
        captured = {}

        def fake_run_ps(self, command, **params):
            captured["command"] = command
            captured["params"] = params
            return {"ok": True}

        with mock.patch.object(HyperVManager, "_run_ps", fake_run_ps):
            lt.telemetry_init()
        assert captured["command"] == "Telemetry-Init"
        assert captured["params"].get("LocalMode") is True


def test_local_transport_get_status_marks_mode():
    import orchestrator.hyperv as hv_mod

    hv_mod._LOCAL_STATUS_CACHE["data"] = None  # bypass the 30s TTL cache
    with tempfile.TemporaryDirectory() as td:
        lt = LocalTransport(FakeCfg(Path(td)))
        with mock.patch.object(HyperVManager, "_run_ps", lambda self, cmd, **p: {"VMName": "local", "Checks": {}}):
            status = lt.get_status()
        assert status["Mode"] == "local"


def test_local_transport_get_status_ttl_cache():
    import orchestrator.hyperv as hv_mod

    hv_mod._LOCAL_STATUS_CACHE["data"] = None
    hv_mod._LOCAL_STATUS_CACHE["ts"] = 0.0
    with tempfile.TemporaryDirectory() as td:
        lt = LocalTransport(FakeCfg(Path(td)))
        calls = []

        def fake(self, cmd, **p):
            calls.append(cmd)
            return {"VMName": "local", "Checks": {}}

        with mock.patch.object(HyperVManager, "_run_ps", fake):
            lt.get_status()
            lt.get_status()
            lt.get_status()
        assert calls == ["Get-LocalStatus"]  # 3 polls, 1 probe
        hv_mod._LOCAL_STATUS_CACHE["data"] = None  # leave clean for other tests


def test_local_transport_hyperv_only_features_raise():
    with tempfile.TemporaryDirectory() as td:
        lt = LocalTransport(FakeCfg(Path(td)))
        for fn in (lt.capture_screenshot, lt.console_input_server_start):
            try:
                fn()
                raise AssertionError("expected RuntimeError")
            except RuntimeError:
                pass
        assert lt.console_input_server_stop()["Status"] == "skipped"


# --- clean_local_state -------------------------------------------------------------

def _populate(tmp: Path, cfg: FakeCfg):
    agent = Path(cfg.telemetry["guest_agent_dir"])
    dest = Path(cfg.sample_execution["guest_destination_folder"])
    dumps = Path(cfg.process_dumps["guest_output_dir"])
    artifacts = [
        agent / "telemetry.jsonl", agent / "telemetry_baseline.json",
        agent / "apitrace.jsonl", agent / "apitrace.jsonl.pids",
        agent / "apitrace_stop.flag", agent / "sample_pid.txt",
        agent / "guardian.jsonl", agent / "guardian_stop.flag",
        agent / "network.etl", agent / "network.pcapng",
        dest / "evil.exe", dumps / "sample_0000.dmp",
    ]
    for f in artifacts:
        f.write_text("x")
    keep = agent / "monitor_x64.dll"  # instrumentation, NOT a run artifact
    keep.write_text("keep")
    return artifacts, keep


def test_clean_local_state_removes_run_artifacts_only():
    with tempfile.TemporaryDirectory() as td:
        cfg = FakeCfg(Path(td))
        lt = LocalTransport(cfg)
        lt.clear_sandbox_archive = lambda: {"Status": "cleared"}  # no ps1 in tests
        artifacts, keep = _populate(Path(td), cfg)
        res = lt.clean_local_state()
        assert res["Status"] == "cleaned" and not res["Errors"], res
        for f in artifacts:
            assert not f.exists(), f"should be gone: {f}"
        assert keep.exists(), "instrumentation must survive cleanup"


def test_clean_local_state_refuses_paths_outside_sandbox_dirs():
    with tempfile.TemporaryDirectory() as td:
        cfg = FakeCfg(Path(td))
        outside = Path(td) / "outside.txt"
        outside.write_text("do not touch")
        cfg.telemetry["guest_output_file"] = str(outside)  # misconfiguration
        lt = LocalTransport(cfg)
        lt.clear_sandbox_archive = lambda: {"Status": "cleared"}
        res = lt.clean_local_state()
        assert outside.exists(), "must never delete outside the sandbox dirs"
        assert any("refused" in e for e in res["Errors"]), res


# --- API gating -----------------------------------------------------------------

def test_require_hyperv_gates_local_mode():
    from fastapi import HTTPException
    from orchestrator import main

    class Cfg:
        is_local_mode = True

    with mock.patch.object(main, "_cfg", lambda: Cfg()):
        try:
            main._require_hyperv()
            raise AssertionError("expected HTTPException")
        except HTTPException as exc:
            assert exc.status_code == 409

    class Cfg2:
        is_local_mode = False

    with mock.patch.object(main, "_cfg", lambda: Cfg2()):
        main._require_hyperv()  # must not raise


def main():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    for name, fn in tests:
        fn()
        print(f"PASS  {name}")
    print(f"{len(tests)} tests passed")


if __name__ == "__main__":
    main()
