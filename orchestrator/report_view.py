"""Pure transforms over already-loaded report dicts.

Shared by the REST API (orchestrator/main.py) and the MCP server
(mcp_server/server.py) so both present identical trimmed/paginated views of a
report without duplicating the logic. No file I/O here — callers load the
report dict (e.g. via ReportGenerator.load_report) and pass it in.
"""

import json
from typing import Any, Dict, List, Optional


def trim_static_analysis(static: Dict[str, Any]) -> Dict[str, Any]:
    """Collapse the PE string dumps (up to 1000 entries each) to counts."""
    if not static:
        return static
    trimmed = dict(static)
    strings = trimmed.get("strings")
    if isinstance(strings, dict):
        trimmed["strings"] = {
            "interesting": strings.get("interesting", []),
            "ascii_count": len(strings.get("ascii", [])),
            "unicode_count": len(strings.get("unicode", [])),
        }
    return trimmed


def trim_report(
    report: Dict[str, Any],
    include_raw_events: bool = False,
    max_events: int = 200,
) -> Dict[str, Any]:
    """Drop the raw telemetry event stream (can be tens of thousands of
    entries), drop environment-scoped alerts (Sigma can put per-report
    alert counts in the tens of thousands -- confirmed one real report's
    /summary payload was 21.3MB before this, almost entirely from alerts,
    since events were already dropped here but alerts never were), and
    collapse PE string dumps.

    Sample-scoped alerts (in_sample_scope != False -- same "treat missing
    as sample-scoped" rule as report_detail.js, so reports predating alert-
    scope classification keep all their alerts inline exactly as before)
    stay inline in full: they're the ones worth seeing immediately, and
    post-classification they're a small fraction of the total (976 of
    17,776 in the report that motivated this). Environment-scoped alerts
    are dropped to a count only, fetched on demand via paginate_alerts().
    """
    trimmed = dict(report)
    events = trimmed.pop("events", [])
    trimmed["static_analysis"] = trim_static_analysis(trimmed.get("static_analysis", {}))
    trimmed["events_total"] = len(events)
    if include_raw_events:
        trimmed["events"] = events[:max_events]
        trimmed["events_truncated"] = len(events) > max_events
    else:
        trimmed["events_omitted"] = True

    all_alerts = trimmed.get("alerts") or []
    sample_alerts = [a for a in all_alerts if a.get("in_sample_scope") is not False]
    environment_alert_count = len(all_alerts) - len(sample_alerts)
    trimmed["alerts"] = sample_alerts
    trimmed["environment_alerts_total"] = environment_alert_count
    trimmed["environment_alerts_omitted"] = environment_alert_count > 0

    return trimmed


def paginate_alerts(
    report: Dict[str, Any],
    offset: int = 0,
    limit: int = 200,
    scope: Optional[str] = None,
    event_type: Optional[str] = None,
    q: Optional[str] = None,
) -> Dict[str, Any]:
    """Slice/filter the alert list for on-demand browsing -- same shape as
    paginate_events(), used for the "Environment / baseline noise" section
    that trim_report() drops from the initial summary payload.
    """
    alerts: List[Dict[str, Any]] = report.get("alerts") or []
    total = len(alerts)

    filtered = alerts
    if scope == "sample":
        filtered = [a for a in filtered if a.get("in_sample_scope") is not False]
    elif scope == "environment":
        filtered = [a for a in filtered if a.get("in_sample_scope") is False]
    if event_type:
        filtered = [a for a in filtered if (a.get("event_type") or a.get("EventType")) == event_type]
    if q:
        needle = q.lower()
        filtered = [a for a in filtered if needle in json.dumps(a, default=str).lower()]

    filtered_total = len(filtered)
    page = filtered[offset : offset + limit]

    return {
        "analysis_id": report.get("analysis_id"),
        "total": total,
        "filtered_total": filtered_total,
        "offset": offset,
        "limit": limit,
        "alerts": page,
    }


def summarize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """One-line-per-report projection for a history table."""
    sample = report.get("sample") or {}
    environment = report.get("environment") or {}
    summary = report.get("summary") or {}
    alerts = report.get("alerts") or []
    sha256 = (sample.get("hashes") or {}).get("sha256", "")
    filename = sample.get("filename", "")
    eid25_count = sum(1 for a in alerts if a.get("event_id") == 25)
    verdict = report.get("verdict") or {}

    return {
        "analysis_id": report.get("analysis_id"),
        "timestamp": report.get("timestamp"),
        "filename": filename,
        "sample_type": sample.get("sample_type"),
        "sha256_short": sha256[:12] if sha256 else "",
        "status": report.get("status"),
        "alert_count": summary.get("alert_count", len(alerts)),
        "total_events": summary.get("total_events", 0),
        "runtime_seconds": environment.get("runtime_seconds"),
        "eid25_count": eid25_count,
        # Verdict at a glance for the history/dashboard tables. None for
        # reports that predate the verdict feature.
        "verdict_level": verdict.get("level"),
        "verdict_score": verdict.get("score"),
        # run_injection_harness.ps1 always publishes/copies this exact filename.
        "is_injection_harness": filename == "InjectionHarness.exe",
    }


def paginate_events(
    report: Dict[str, Any],
    offset: int = 0,
    limit: int = 200,
    event_type: Optional[str] = None,
    q: Optional[str] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """Slice/filter the raw event stream for on-demand browsing."""
    events: List[Dict[str, Any]] = report.get("events") or []
    total = len(events)

    # Sources present in this report, so the browser can offer a filter
    # dropdown without a separate schema field (sysmon, amsi, apitrace, ...).
    sources = sorted({e.get("source") for e in events if e.get("source")})

    filtered = events
    if source:
        # Comma-separated list accepted (same convention as event_type) so
        # e.g. the Event-logs tab covers security+system+windefend as ONE
        # server-paginated stream.
        wanted_src = {s.strip() for s in source.split(",") if s.strip()}
        filtered = [e for e in filtered if e.get("source") in wanted_src]
    if event_type:
        # Comma-separated list accepted so the UI's per-EID-family tabs
        # (e.g. injection = ImageLoad,CreateRemoteThread,ProcessAccess,
        # ProcessTampering) stay one server-paginated stream instead of N
        # client-merged ones.
        wanted = {t.strip() for t in event_type.split(",") if t.strip()}
        filtered = [e for e in filtered if (e.get("event_type") or e.get("EventType")) in wanted]
    if q:
        needle = q.lower()
        filtered = [e for e in filtered if needle in json.dumps(e, default=str).lower()]

    filtered_total = len(filtered)
    page = filtered[offset : offset + limit]

    return {
        "analysis_id": report.get("analysis_id"),
        "total": total,
        "filtered_total": filtered_total,
        "offset": offset,
        "limit": limit,
        "sources": sources,
        "events": page,
    }
