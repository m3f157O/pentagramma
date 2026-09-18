"""Offline unit tests for the live telemetry tail (/api/jobs/active/events).

No VM, no job: jobs.get_active_job_id and the backend are monkeypatched.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import orchestrator.main as main_mod  # noqa: E402


class FakeBackend:
    def __init__(self, tail):
        self.tail = tail
        self.calls = []

    def tail_telemetry(self, path, offset):
        self.calls.append((path, offset))
        return dict(self.tail)


class LiveTailTests(unittest.TestCase):
    def _call(self, offset=0, active="job-1", tail=None):
        backend = FakeBackend(tail or {"Offset": 0, "Text": ""})
        with mock.patch.object(main_mod.jobs, "get_active_job_id", lambda: active), \
             mock.patch.object(main_mod, "_backend", lambda: backend):
            return main_mod.active_job_events(offset=offset), backend

    def test_409_when_no_active_job(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self._call(active=None)
        self.assertEqual(cm.exception.status_code, 409)

    def test_happy_path_full_lines(self):
        resp, backend = self._call(tail={"Offset": 14, "Text": '{"a":1}\n{"b":2}\n'})
        self.assertEqual(resp["events"], ['{"a":1}', '{"b":2}'])
        self.assertEqual(resp["offset"], 14)

    def test_trailing_partial_line_rewinds_offset(self):
        # collector mid-write: "par" is incomplete -- must not be emitted and
        # the offset must rewind so the next poll re-reads it.
        resp, _ = self._call(tail={"Offset": 10, "Text": '{"a":1}\npar'})
        self.assertEqual(resp["events"], ['{"a":1}'])
        self.assertEqual(resp["offset"], 7)  # 10 - len("par")

    def test_empty_file(self):
        resp, _ = self._call(tail={"Offset": 0, "Text": ""})
        self.assertEqual(resp["events"], [])


if __name__ == "__main__":
    unittest.main()
