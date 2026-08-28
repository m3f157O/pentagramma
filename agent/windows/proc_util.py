"""Subprocess helpers for the guest agent.

Every telemetry source shells out to a Windows CLI tool (wevtutil, logman,
auditpol, sc, pktmon, ...) and captures its output. Python's default
text-mode capture (``text=True``) decodes that output with the guest's
strict *locale* codec. On this analysis VM (Italian Windows) that's a code
page which can't map every byte a real event-log stream carries -- localized
service descriptions, accented account names / file paths, etc. The first
unmappable byte raises ``UnicodeDecodeError`` *inside subprocess's background
pipe-reader thread* ("Thread-1 (_readerthread)"), which kills the capture and
surfaces as the opaque, run-ending failure at the telemetry_collect step
(the reader thread dies before filling the output buffer, so the main thread
then blows up reading an empty result).

The severity scales with how much localized text is in the captured stream,
which is why it was only intermittent with Sysmon's terse operational log but
became near-constant once verbose logs (Security/System) were queried and as
more content accumulated per run.

``run_text`` routes every capture through ``errors="replace"``: an unmappable
byte becomes U+FFFD instead of crashing the reader thread. This only changes
behaviour for bytes that previously crashed -- everything that already decoded
cleanly is byte-for-byte unchanged, so there's no regression risk to the
captures that were already working.
"""

import subprocess
from typing import Any


def run_text(cmd: Any, **kwargs: Any) -> "subprocess.CompletedProcess":
    """subprocess.run for capturing a Windows tool's text output safely.

    Defaults to capture_output=True, text=True, errors="replace"; any of
    these (plus timeout, check, cwd, ...) can still be overridden per call.
    """
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("errors", "replace")
    return subprocess.run(cmd, **kwargs)
