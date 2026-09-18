"""Offline unit tests for the /api/fleet merge logic (main.fleet).

HyperVManager/LocalTransport are monkeypatched with fakes -- no Hyper-V, no
PowerShell, no elevation.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import orchestrator.main as main_mod  # noqa: E402


class FakeCfg:
    is_local_mode = False
    mode = "hyperv"
    hyperv = {
        "analysis_vm": "pentagramma",
        "vms": [
            {"name": "pentagramma", "username": "gigi", "password": "gigi"},
            {"name": "ghost-vm", "username": "gigi", "password": "gigi"},  # registered, not on host
            {"name": "nocreds-vm", "username": "", "password": ""},        # registered, no creds
        ],
    }
    paths = {"agent_dir": "C:/agent"}
    telemetry = {"guest_agent_dir": "C:\\SandboxAgent", "sources": ["sysmon", "amsi"]}

    def vm_creds(self, name):
        for vm in self.hyperv["vms"]:
            if vm["name"] == name:
                return vm["username"] or None, vm["password"] or None
        return None, None


class FakeLocalTransport:
    def __init__(self, cfg):
        pass

    def get_status(self):
        return {"State": "Running", "Checks": {"sysmon": True}, "LocalSystem": {"Hostname": "HOST"}}


class FakeHyperVManager:
    def __init__(self, cfg):
        pass

    def list_vms(self):
        return [
            {"Name": "pentagramma", "State": "Running", "Uptime": "1.00:00:00", "IPAddress": "10.0.0.5"},
            {"Name": "stray-vm", "State": "Off", "Uptime": "00:00:00", "IPAddress": None},  # on host, not registered
            {"Name": "nocreds-vm", "State": "Running", "Uptime": "2.00:00:00", "IPAddress": None},
        ]

    def get_status(self, vm_name=None):
        assert vm_name == "pentagramma"  # only managed+creds+running VMs are probed
        return {
            "State": "Running",
            "Checks": {"sysmon": True, "defender_rtp": False},
            "GuestSystem": {"Hostname": "PENTAGRAMMA"},
        }


class FleetTests(unittest.TestCase):
    def _fleet(self):
        with mock.patch.object(main_mod, "_cfg", lambda: FakeCfg()), \
             mock.patch.object(main_mod, "LocalTransport", FakeLocalTransport), \
             mock.patch.object(main_mod, "HyperVManager", FakeHyperVManager):
            return main_mod.fleet()

    def test_fleet_shape(self):
        data = self._fleet()
        self.assertEqual(data["mode"], "hyperv")
        by_name = {e["name"]: e for e in data["entries"]}
        self.assertEqual(set(by_name), {"local", "pentagramma", "stray-vm", "ghost-vm", "nocreds-vm"})

        local = by_name["local"]
        self.assertEqual(local["type"], "local")
        self.assertFalse(local["active"])
        self.assertEqual(local["checks"], {"sysmon": True})

        penta = by_name["pentagramma"]
        self.assertTrue(penta["active"])
        self.assertTrue(penta["managed"])
        self.assertTrue(penta["credentials_configured"])
        self.assertEqual(penta["checks"]["defender_rtp"], False)
        self.assertEqual(penta["system"]["Hostname"], "PENTAGRAMMA")

    def test_unregistered_vm_is_inventory_only(self):
        by_name = {e["name"]: e for e in self._fleet()["entries"]}
        stray = by_name["stray-vm"]
        self.assertFalse(stray["managed"])
        self.assertFalse(stray["credentials_configured"])
        self.assertNotIn("checks", stray)  # no creds -> never probed

    def test_registered_but_no_creds_not_probed(self):
        by_name = {e["name"]: e for e in self._fleet()["entries"]}
        nc = by_name["nocreds-vm"]
        self.assertTrue(nc["managed"])
        self.assertFalse(nc["credentials_configured"])
        self.assertNotIn("checks", nc)  # Running but no creds -> no probe

    def test_registered_missing_from_host(self):
        by_name = {e["name"]: e for e in self._fleet()["entries"]}
        ghost = by_name["ghost-vm"]
        self.assertEqual(ghost["state"], "missing")
        self.assertIn("not found", ghost["error"])

    def test_detail_shows_credentials_presence_never_password(self):
        import json as _json
        with mock.patch.object(main_mod, "_cfg", lambda: FakeCfg()):
            d = main_mod.fleet_detail("pentagramma")
        self.assertTrue(d["managed"])
        self.assertTrue(d["credentials"]["configured"])
        self.assertEqual(d["credentials"]["username"], "gigi")
        self.assertNotIn("gigi", _json.dumps(d.get("last_health") or {}))  # health only
        blob = _json.dumps(d)
        self.assertNotIn('"password"', blob)  # never serialized

    def test_detail_local_and_unknown(self):
        with mock.patch.object(main_mod, "_cfg", lambda: FakeCfg()):
            loc = main_mod.fleet_detail("local")
            unk = main_mod.fleet_detail("never-heard-of-it")
        self.assertFalse(loc["credentials"]["required"])
        self.assertFalse(unk["managed"])
        self.assertFalse(unk["credentials"]["configured"])
        self.assertIsNone(unk["last_health"])


class FleetProvisionTests(unittest.TestCase):
    class FakeBackend:
        def __init__(self, cfg, vm_name=None):
            self.calls = []
            self.vm_name = vm_name

        def get_status(self, name=None):
            return {"State": "Running", "Checks": {"sysmon": True}}

        def copy_agent(self, **kw):
            self.calls.append(("copy_agent", kw))
            return {"Status": "copied"}

        def telemetry_init(self, **kw):
            self.calls.append(("telemetry_init", kw))
            return {"Status": "ok"}

        def invoke_guest_python(self, script, args, agent_dir=None):
            self.calls.append(("invoke_guest_python", script, args))
            return {"ExitCode": 0}

        def restart_guest(self):
            self.calls.append(("restart_guest",))
            return {"Status": "restarted"}

    def _provision(self, name, step, cfg=None):
        backend = self.FakeBackend
        with mock.patch.object(main_mod, "_cfg", lambda: cfg or FakeCfg()), \
             mock.patch.object(main_mod, "LocalTransport", backend), \
             mock.patch.object(main_mod, "HyperVManager", backend):
            return main_mod.fleet_provision(name, step)

    def test_unknown_step_404(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self._provision("pentagramma", "nuke-it")
        self.assertEqual(cm.exception.status_code, 404)

    def test_vm_without_creds_409(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self._provision("never-registered", "agent")
        self.assertEqual(cm.exception.status_code, 409)
        self.assertIn("no credentials", cm.exception.detail)

    def test_agent_step_dispatches_per_vm(self):
        r = self._provision("pentagramma", "agent")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["result"]["Status"], "copied")

    def test_defender_off_reboots_vm_never_local(self):
        # VM: disable -> reboot (GPO applies at service start) -> verify
        r = self._provision("pentagramma", "defender-off")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["result"]["reboot"]["Status"], "restarted")
        self.assertIn("verify", r["result"])
        # local host: never rebooted from a web button
        r2 = self._provision("local", "defender-off")
        self.assertNotIn("reboot", r2["result"])
        self.assertIn("reboot manually", r2["result"]["note"])

    def test_local_target_uses_local_backend(self):
        r = self._provision("local", "sysmon")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["target"], "local")


if __name__ == "__main__":
    unittest.main()
