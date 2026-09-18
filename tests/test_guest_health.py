"""Offline unit tests for guest instrumentation health (hyperv mode).

HyperVManager.get_status merges the Get-GuestHealth probe (PSDirect) into the
dashboard status payload with a module-level 30s TTL cache. All ps1 calls are
mocked -- no VM, no elevation, no PowerShell.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import orchestrator.hyperv as hyperv_mod  # noqa: E402
from orchestrator.hyperv import HyperVManager  # noqa: E402

SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent / "scripts")


class FakeCfg:
    hyperv = {"analysis_vm": "pentagramma", "snapshot_name": "SANDBOX_READY"}
    paths = {"scripts_dir": SCRIPTS_DIR}


HEALTH_OK = {
    "Checks": {"sysmon": True, "agent_dir": True, "monitor_dlls": True,
               "guardian_driver": True, "secure_boot": False, "defender_rtp": False},
    "GuestSystem": {"Hostname": "PENTAGRAMMA", "OS": "Windows 11", "Build": "22631"},
    "ChecksError": None,
}


def _manager(responses):
    """HyperVManager with _run_ps mocked: responses = {verb: payload-or-exception}."""
    mgr = HyperVManager(FakeCfg())

    def fake_run_ps(command, **params):
        resp = responses[command]
        if isinstance(resp, Exception):
            raise resp
        return dict(resp)

    mgr._run_ps = mock.Mock(side_effect=fake_run_ps)
    return mgr


def _reset_cache():
    hyperv_mod._GUEST_HEALTH_CACHE.clear()


class GuestHealthTests(unittest.TestCase):
    def setUp(self):
        _reset_cache()

    def test_vm_off_skips_probe(self):
        mgr = _manager({"Get-Status": {"VMName": "pentagramma", "State": "Off", "Uptime": "00:00:00"}})
        status = mgr.get_status()
        self.assertIsNone(status["Checks"])
        self.assertNotIn("GuestSystem", status)
        called = [c.args[0] for c in mgr._run_ps.call_args_list]
        self.assertEqual(called, ["Get-Status"])  # Get-GuestHealth never called

    def test_running_merges_health(self):
        mgr = _manager({
            "Get-Status": {"VMName": "pentagramma", "State": "Running", "Uptime": "1.00:00:00"},
            "Get-GuestHealth": HEALTH_OK,
        })
        status = mgr.get_status()
        self.assertEqual(status["Checks"]["sysmon"], True)
        self.assertEqual(status["Checks"]["defender_rtp"], False)
        self.assertEqual(status["GuestSystem"]["Hostname"], "PENTAGRAMMA")
        self.assertNotIn("ChecksError", status)  # None error is not surfaced

    def test_ttl_cache_single_probe(self):
        mgr = _manager({
            "Get-Status": {"VMName": "pentagramma", "State": "Running"},
            "Get-GuestHealth": HEALTH_OK,
        })
        mgr.get_status()
        mgr.get_status()
        mgr.get_status()
        probes = [c for c in mgr._run_ps.call_args_list if c.args[0] == "Get-GuestHealth"]
        self.assertEqual(len(probes), 1)  # 3 polls, 1 PSDirect probe

    def test_probe_exception_tolerated(self):
        mgr = _manager({
            "Get-Status": {"VMName": "pentagramma", "State": "Running"},
            "Get-GuestHealth": RuntimeError("PSDirect timeout"),
        })
        status = mgr.get_status()  # must not raise
        self.assertIsNone(status["Checks"])
        self.assertIn("PSDirect timeout", status["ChecksError"])

    def test_cache_invalidated_on_off_running_transition(self):
        mgr = _manager({
            "Get-Status": {"VMName": "pentagramma", "State": "Running"},
            "Get-GuestHealth": HEALTH_OK,
        })
        mgr.get_status()
        # VM goes off -> next status must not serve stale guest checks
        mgr._run_ps.side_effect = lambda command, **p: {"VMName": "pentagramma", "State": "Off"}
        status = mgr.get_status()
        self.assertIsNone(status["Checks"])
        # VM back on -> probe runs again (cache was invalidated)
        mgr._run_ps.side_effect = lambda command, **p: (
            {"VMName": "pentagramma", "State": "Running"} if command == "Get-Status" else dict(HEALTH_OK)
        )
        status = mgr.get_status()
        self.assertEqual(status["Checks"]["sysmon"], True)

    def test_per_vm_cache_keying(self):
        """Fleet path: explicit vm_name overrides the default VM and each
        VM gets its own health cache slot."""
        mgr = _manager({
            "Get-Status": {"VMName": "x", "State": "Running"},
            "Get-GuestHealth": HEALTH_OK,
        })
        mgr.get_status("vm-a")
        mgr.get_status("vm-b")
        mgr.get_status("vm-a")  # cached, no third probe
        self.assertEqual(set(hyperv_mod._GUEST_HEALTH_CACHE.keys()), {"vm-a", "vm-b"})
        probes = [c for c in mgr._run_ps.call_args_list if c.args[0] == "Get-GuestHealth"]
        self.assertEqual(len(probes), 2)
        self.assertEqual({c.kwargs["VMName"] for c in probes}, {"vm-a", "vm-b"})

    def test_last_known_health_retained_when_vm_off(self):
        """Fleet 'Manage' view shows the LAST recorded instrumentation
        snapshot even after the VM goes off."""
        mgr = _manager({
            "Get-Status": {"VMName": "pentagramma", "State": "Running"},
            "Get-GuestHealth": HEALTH_OK,
        })
        mgr.get_status()
        mgr._run_ps.side_effect = lambda command, **p: {"VMName": "pentagramma", "State": "Off"}
        status = mgr.get_status()
        self.assertIsNone(status["Checks"])  # live status: no stale checks
        last = HyperVManager.last_guest_health("pentagramma")
        self.assertIsNotNone(last)
        self.assertEqual(last["data"]["Checks"]["sysmon"], True)
        self.assertEqual(last["state_at_probe"], "Off")


if __name__ == "__main__":
    unittest.main()
