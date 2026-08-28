"""Shared ETW session helpers for sandbox telemetry collectors needing
offline ETL-file decoding (AMSI; also the intended target for a future
ETW-TI fix, if its PPL/code-signing restriction is ever worked around --
see docs/detection-gap-tracker.md).

Session start/stop goes through logman -ets, matching the pattern already
used elsewhere in this project (agent/windows/network_capture.py's pktmon
sessions, the pre-existing agent/windows/etw_ti_collector.py). Decoding a
completed .etl file uses pywintrace (FireEye/Mandiant's ctypes ETW wrapper)
directly against its lower-level EventConsumer, not the higher-level ETW
wrapper class -- offline-file processing needs to synchronously wait for
ProcessTrace() to finish (via Thread.join()), which the higher-level
wrapper doesn't expose.
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import proc_util
from etw import evntcons as ec
from etw import evntrace as et
from etw.etw import EventConsumer

# Windows FILETIME epoch (1601-01-01) to Unix epoch (1970-01-01), in 100ns ticks.
_FILETIME_EPOCH_OFFSET = 116444736000000000


def start_logman_session(session_name: str, provider_name: str, etl_path: str) -> bool:
    """Start a logman ETW trace session writing to an ETL file. Stops any
    stale session with the same name first (best-effort). Returns True if
    the session started successfully.
    """
    proc_util.run_text(["logman", "stop", session_name, "-ets"], timeout=10)
    proc = proc_util.run_text(
        ["logman", "start", session_name, "-p", provider_name, "-o", etl_path, "-ets"],
        timeout=10,
    )
    return proc.returncode == 0


def stop_logman_session(session_name: str) -> bool:
    proc = proc_util.run_text(["logman", "stop", session_name, "-ets"], timeout=10)
    return proc.returncode == 0


def filetime_to_iso(filetime: int) -> str:
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to ISO 8601 UTC."""
    unix_ts = (filetime - _FILETIME_EPOCH_OFFSET) / 10_000_000
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()


def parse_etl_file(
    etl_path: str,
    event_id_filter: List[int],
    field_decoder: Callable[[int, Dict[str, Any]], Optional[Dict[str, Any]]],
    max_events: int = 5000,
    timeout_seconds: float = 60.0,
) -> Dict[str, Any]:
    """Offline-decode a completed ETL file, filtered to the given event IDs.

    field_decoder receives (event_id, raw_event_dict) -- raw_event_dict is
    the second element of pywintrace's (event_id, event_dict) callback tuple
    -- and returns a normalized dict, or None to skip the event.

    Capped at max_events: some ETW providers (confirmed empirically for
    AMSI) are system-wide, not scoped to one process, so even a few seconds
    of capture on a busy host can produce tens of thousands of events. The
    cap is enforced by stopping the trace consumer early from inside the
    callback once reached, not by processing everything and truncating
    after the fact, since per-event TDH decoding is too expensive at that
    volume to just let it run to completion and discard the excess.
    """
    results: List[Dict[str, Any]] = []
    truncated = {"value": False}
    consumer_holder: Dict[str, Optional[EventConsumer]] = {"consumer": None}

    trace_logfile = et.EVENT_TRACE_LOGFILE()
    trace_logfile.LogFileName = etl_path
    trace_logfile.ProcessTraceMode = ec.PROCESS_TRACE_MODE_EVENT_RECORD

    def _callback(event: Any) -> None:
        if not isinstance(event, tuple) or len(event) != 2:
            return
        event_id, event_dict = event
        if event_id_filter and event_id not in event_id_filter:
            return
        normalized = field_decoder(event_id, event_dict)
        if normalized is not None:
            results.append(normalized)
        if len(results) >= max_events:
            truncated["value"] = True
            consumer = consumer_holder["consumer"]
            # This callback runs ON consumer.process_thread -- calling the
            # full consumer.stop() here would make the thread try to join
            # itself (RuntimeError). Only signal + close the trace handle
            # (the two thread-safe parts of stop()); the actual join happens
            # from the caller's thread below once this thread exits on its
            # own as a result of CloseTrace unblocking ProcessTrace().
            if consumer is not None and not consumer.end_capture.is_set():
                consumer.end_capture.set()
                try:
                    et.CloseTrace(consumer.trace_handle)
                except Exception:
                    pass

    consumer = EventConsumer(logger_name=None, event_callback=_callback, trace_logfile=trace_logfile)
    consumer_holder["consumer"] = consumer
    consumer.start()
    consumer.process_thread.join(timeout=timeout_seconds)
    if consumer.process_thread.is_alive():
        # Still running after the timeout (large file / slow decode) -- stop
        # rather than block collect() indefinitely.
        truncated["value"] = True

    try:
        consumer.stop()
    except Exception:
        pass  # already stopped (e.g. the callback's early-stop already ran)

    return {"events": results, "truncated": truncated["value"]}
