"""PID-lineage computation rooted at the sample's own launched process.

Used to scope both dropped-file retrieval (executor.py) and alert-scope
classification (reporting.py) to what the sample itself did, as opposed to
the sandbox's own infrastructure (Sysmon reconfiguration, pktmon.exe, the
Python-based telemetry collector) or unrelated background Windows
activity -- both of which otherwise dilute every single report's signal
regardless of what the sample did. Confirmed empirically against a real
report: of 20 alerts on one run, only the 4 sharing the sample's own PID
were genuinely sample-attributed; the rest belonged to unrelated PIDs.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple


def _basename(path: Optional[str]) -> str:
    """Lowercased final path component. Manual split (not os.path) because
    these are always Windows guest paths regardless of the host OS the
    orchestrator runs on."""
    if not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _parse_sysmon_time(raw: Any) -> Optional[datetime]:
    """Parse a Sysmon event timestamp ("2026-09-03 18:26:16.714" or ISO-8601).
    Returns a naive datetime; all inputs share the same guest clock."""
    if not raw:
        return None
    s = str(raw).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=None)
    except ValueError:
        pass
    try:
        return datetime.strptime(s[:26], "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


# Slack for the pid-reuse time-window check: same clock source (Sysmon
# UtcTime), but creation/termination events are written by different kernel
# callbacks and can arrive marginally out of order.
_REUSE_WINDOW_SLACK = timedelta(seconds=1)


class PidLineage:
    """A sample's process lineage, tracked two ways: by ProcessId (the OS
    PID, which Windows recycles -- fast under a busy analysis, confirmed
    live 2026-07-03: a `timeout /t 3` child (PID 9832) exited and Windows
    handed that same PID to an unrelated wermgr.exe within milliseconds,
    and PID-only lineage kept scoring wermgr.exe's own bulk file writes as
    the sample's own "mass file modification" activity, since 9832 had
    ever been in-lineage) and by ProcessGuid (Sysmon's own globally-unique-
    per-instance identifier, immune to PID reuse by design). Guid lineage
    is preferred wherever available; PID lineage is the fallback for
    events/alert types that don't carry a ProcessGuid (e.g. the Sigma
    event_count correlation alert only ever had ProcessId to work with
    before this fix -- see sigma_engine.py::_build_correlation_alert).
    """

    __slots__ = ("pids", "guids")

    def __init__(self, pids: Set[int], guids: Set[str]):
        self.pids = pids
        self.guids = guids

    def __bool__(self) -> bool:
        return bool(self.pids)

    def contains_event(self, data: Dict[str, Any]) -> bool:
        """Whether the process that produced an event with these Sysmon
        `data` fields belongs to the sample's lineage. Prefers ProcessGuid
        (immune to PID reuse) when the event carries one and guid lineage is
        available; falls back to ProcessId otherwise. An event with no
        resolvable identifier is out of scope.

        Single source of truth for the guid-preferred-then-pid precedence,
        shared by classify_alert_scope (alert tagging) and
        ioc_summary._extract_network_connections -- duplicating this decision
        is exactly how a caller (ioc_summary) got left doing a raw ``pid in
        lineage`` membership test that broke the moment build_pid_lineage
        started returning a PidLineage instead of a bare set.
        """
        guid = data.get("ProcessGuid") or data.get("SourceProcessGuid")
        if guid and self.guids:
            return guid in self.guids
        pid_raw = data.get("ProcessId") or data.get("SourceProcessId")
        try:
            pid = int(pid_raw)
        except (TypeError, ValueError):
            return False
        return pid in self.pids


def build_pid_lineage(
    events: List[Dict[str, Any]],
    root_pid: Optional[int],
    root_image: Optional[str] = None,
) -> PidLineage:
    """BFS over ProcessCreate events, rooted at root_pid. Originally the
    inline scoping logic in executor.py::_select_dropped_files (confirmed
    necessary there via a real historical event: logman.exe, the AMSI
    collector, creating C:\\SandboxAgent\\amsi.etl -- unrelated to anything
    the sample did); extracted here as the second consumer needing the
    same computation.

    root_image (execution_info.LauncherPath) is the image the executor
    actually launched the sample as. It disambiguates root_pid when Windows
    recycled that PID within the analysis: root_pid can name several process
    incarnations, and only the one whose Image matches the launcher is the
    sample -- a PID-reuse predecessor or successor is some other binary.
    """
    if root_pid is None:
        return PidLineage(set(), set())

    pid_child_map: Dict[int, List[int]] = {}
    guid_child_map: Dict[str, List[str]] = {}
    # Every ProcessGuid ever seen for a given PID. A PID can have several
    # incarnations within a single analysis (Windows recycles PIDs fast), so
    # this is a set, not a single "first seen" value -- picking first-seen is
    # exactly what mis-resolved root_pid to an earlier throwaway process's
    # guid (confirmed live 2026-07-04: a conhost.exe transiently held the
    # sample's eventual PID ~4s before the sample's own powershell.exe was
    # assigned it, so the guid lineage started from the conhost and never
    # included the real root, silently dropping every genuine root event).
    pid_own_guids: Dict[int, Set[str]] = {}
    # For a given PARENT pid, the ParentProcessGuids its children declared --
    # i.e. the guids of the specific incarnation(s) of that pid that actually
    # spawned children. This is what lets us recover the *correct* root guid:
    # a PID-reuse predecessor (e.g. a conhost) never parents the sample's
    # children, so its guid is naturally absent here.
    parent_guids_by_ppid: Dict[int, Set[str]] = {}
    # (guid, image_basename) for every ProcessCreate incarnation of root_pid,
    # so root_image can select the incarnation that actually IS the sample.
    root_incarnations: List[Tuple[str, str]] = []

    # Incarnation time windows: pid -> creation time (ProcessCreate UtcTime)
    # and termination time (ProcessTerminate UtcTime). Windows recycles PIDs
    # within milliseconds; without a time check, a reused pid's children get
    # adopted into the sample's lineage and every guid-less event from that
    # pid number (apitrace, guardian, correlation alerts) is mis-scoped into
    # the sample (confirmed live 2026-09-03: benign_control.bat's cmd.exe pid
    # was reused by a SYSTEM process spawning EdgeUpdate children, one of
    # which reused the monitor_loader's pid -- pulling the loader's own
    # NtResumeThread-of-the-sample alert in-scope, +15 verdict weight).
    pid_ctime: Dict[int, datetime] = {}
    pid_etime: Dict[int, datetime] = {}

    for event in events:
        event_type = event.get("event_type") or event.get("EventType")
        data = event.get("data") or {}
        if event_type == "ProcessTerminate":
            try:
                tpid = int(data.get("ProcessId"))
            except (TypeError, ValueError):
                continue
            # Earliest terminate wins for a recycled pid: the sample
            # incarnation's death is the window boundary that matters.
            ts = _parse_sysmon_time(data.get("UtcTime") or event.get("timestamp"))
            if ts and (tpid not in pid_etime or ts < pid_etime[tpid]):
                pid_etime[tpid] = ts
            continue
        if event_type != "ProcessCreate":
            continue
        try:
            pid = int(data.get("ProcessId"))
            ppid = int(data.get("ParentProcessId"))
        except (TypeError, ValueError):
            continue
        pid_child_map.setdefault(ppid, []).append(pid)
        ctime = _parse_sysmon_time(data.get("UtcTime") or event.get("timestamp"))
        if ctime:
            pid_ctime.setdefault(pid, ctime)

        guid = data.get("ProcessGuid")
        parent_guid = data.get("ParentProcessGuid")
        if guid:
            pid_own_guids.setdefault(pid, set()).add(guid)
            if pid == root_pid:
                root_incarnations.append((guid, _basename(data.get("Image"))))
            if parent_guid:
                guid_child_map.setdefault(parent_guid, []).append(guid)
                parent_guids_by_ppid.setdefault(ppid, set()).add(parent_guid)

    # Resolve the sample's root ProcessGuid, most-authoritative signal first:
    #   1. Image == launcher: the sample runs AS root_image; a PID-reuse
    #      predecessor/successor is a different binary. Handles both the
    #      childless-sample case (an unrelated wuauclt.exe reused root_pid and
    #      spawned Defender-update children) and the child-ful one.
    #   2. Else the guid root's own children point at as their parent (works
    #      when root_image is unavailable and the sample actually spawned
    #      children; a reuse predecessor never parents the sample's children).
    #   3. Else every guid ever seen for root_pid (last resort; can't broaden
    #      scope past the PID lineage, since those events carry root_pid anyway).
    want_image = _basename(root_image)
    root_guids: Set[str] = set()
    if want_image:
        root_guids = {g for (g, img) in root_incarnations if img == want_image}
    if not root_guids:
        root_guids = set(parent_guids_by_ppid.get(root_pid) or ())
    if not root_guids:
        root_guids = set(pid_own_guids.get(root_pid) or ())
    guids: Set[str] = set(root_guids)
    gqueue = list(root_guids)
    while gqueue:
        current = gqueue.pop()
        for child in guid_child_map.get(current, []):
            if child not in guids:
                guids.add(child)
                gqueue.append(child)

    pids: Set[int] = set()
    if guids:
        # Preferred: derive the pid set from the GUID tree -- each in-tree
        # guid incarnation contributes its pid. Precise under PID reuse in
        # BOTH directions (confirmed live 2026-09-03, two opposite failures):
        #  - children of a RECYCLED incarnation are never adopted (their
        #    ParentProcessGuid names the recycled incarnation, which is not
        #    in the guid tree): the benign/70 run's EdgeUpdate children.
        #  - children of the REAL sample are still adopted even when the
        #    sample's pid number was itself recycled from an earlier short-
        #    lived process: the benign/27 run's taskkill (parent powershell
        #    pid 5168 had a prior incarnation whose termination would have
        #    failed a pid-only time-window check).
        guid_to_pid: Dict[str, int] = {}
        for pid, gset in pid_own_guids.items():
            for g in gset:
                guid_to_pid[g] = pid
        pids = {guid_to_pid[g] for g in guids if g in guid_to_pid}
        pids.add(root_pid)
    if not pids:
        # Fallback (guid-less telemetry): time-windowed pid BFS. A child born
        # after the parent's (earliest) termination belongs to a recycled
        # incarnation -- reject; fail-open when timestamps are missing.
        pids = {root_pid}
        queue = [root_pid]
        while queue:
            current = queue.pop()
            parent_died = pid_etime.get(current)
            for child in pid_child_map.get(current, []):
                if child in pids:
                    continue
                child_born = pid_ctime.get(child)
                if parent_died and child_born and child_born > parent_died + _REUSE_WINDOW_SLACK:
                    continue
                pids.add(child)
                queue.append(child)

    return PidLineage(pids, guids)


def classify_alert_scope(alerts: List[Dict[str, Any]], lineage: PidLineage) -> List[Dict[str, Any]]:
    """Tags each alert with in_sample_scope: True/False.

    Alerts that already carry an explicit "in_sample_scope" key are left
    untouched -- detect_dump_yara_matches/detect_dropped_file_yara_matches
    (orchestrator/heuristics.py) set it directly at emission time, since
    their inputs (process dumps and dropped files) are already scoped to
    the sample's own lineage upstream and have no natural per-alert PID of
    their own to infer from.

    Prefers ProcessGuid (immune to PID reuse) when the alert carries one;
    falls back to ProcessId otherwise. An alert with no resolvable PID and
    no explicit marker defaults to False (environment) -- confirmed via one
    real case (a Sysmon EventID-16 config-change alert with no ProcessId in
    its schema): it's Sysmon's own self-management, not sample activity. A
    deliberate default, not an accident of missing data.
    """
    classified = []
    for alert in alerts:
        if "in_sample_scope" in alert:
            classified.append(alert)
            continue
        tagged = dict(alert)
        tagged["in_sample_scope"] = lineage.contains_event(alert.get("data") or {})
        classified.append(tagged)
    return classified
