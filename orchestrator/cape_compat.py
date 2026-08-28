"""Compatibility layer for running CAPE community signatures offline.

Vendored CAPE community signatures (cape_signatures/) are written against
CAPEv2's `lib.cuckoo.common.abstracts.Signature` base class and a Cuckoo-style
`results` model. This module provides a faithful, dependency-free subset of
that base class plus stub modules for the few other `lib.cuckoo.common.*`
imports the community set makes (constants / utils / fraunhofer_helper).

Method semantics (get_argument caching, _check_value matching rules,
mark_call/add_match payloads) are extracted 1:1 from CAPEv2's abstracts.py
(kevoreilly/CAPEv2 @ master, fetched 2026-07-27) so signatures behave exactly
as upstream -- only CAPE-environment features (yara_detected over result
blocks, threat intel lookups, disk paths) are stubbed out.

The `results` model expected by signatures:
    results["behavior"]["processes"] = [
        {"process_id": int, "process_name": str, "calls": [call, ...]}, ...]
    results["behavior"]["summary"] = {"files": [], "keys": [], "mutexes": [],
        "read_files": [], "write_files": [], "delete_files": [],
        "read_keys": [], "write_keys": [], "delete_keys": [],
        "started_services": [], "created_services": [], "executed_commands": []}
    results["network"] = {"hosts": [], "domains": [], "http": []}
    results["signatures"] = []   # filled as signatures match (ordered sigs)

Each call:
    {"timestamp": str, "thread_id": str, "category": str, "api": str,
     "status": bool, "return": str, "repeated": int,
     "arguments": [{"name": str, "value": str}, ...]}
"""

import logging
import re
import sys
import types
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


class Signature:
    """Base class for Cuckoo/CAPE signatures (dependency-free subset)."""

    name = ""
    description = ""
    severity = 1
    confidence = 100
    weight = 1
    categories = []
    families = []
    authors = []
    references = []
    alert = False
    enabled = True
    minimum = None
    maximum = None
    ttps = []
    mbcs = []

    # Higher order runs later (meta-signatures keying off other matches).
    order = 0

    evented = False
    filter_processnames = set()
    filter_apinames = set()
    filter_categories = set()
    filter_analysistypes = set()
    banned_suricata_sids = ()

    def __init__(self, results=None):
        self.data = []
        self.new_data = []
        self.results = results
        self._current_call_cache = None
        self._current_call_dict = None
        self._current_call_raw_cache = None
        self._current_call_raw_dict = None
        self.hostname2ips = {}
        self.matched = False

        # Set by the evented dispatcher before each on_call().
        self.pid = None
        self.cid = None
        self.call = None

    # ------------------------------------------------------------------
    # matching primitive
    # ------------------------------------------------------------------

    def _check_value(self, pattern, subject, regex=False, all=False, ignorecase=True):
        """Checks a pattern against a given subject (exact CAPE semantics)."""
        if regex:
            if all:
                retset = set()
            exp = re.compile(pattern, re.IGNORECASE)
            if isinstance(subject, list):
                for item in subject:
                    if exp.match(item):
                        if all:
                            retset.add(item)
                        else:
                            return item
            elif exp.match(subject):
                if all:
                    retset.add(subject)
                else:
                    return subject
            if all and len(retset) > 0:
                return retset
        elif ignorecase:
            lowerpattern = pattern.lower()
            if isinstance(subject, list):
                for item in subject:
                    if item.lower() == lowerpattern:
                        return item
            elif subject.lower() == lowerpattern:
                return subject
        elif isinstance(subject, list):
            for item in subject:
                if item == pattern:
                    return item
        elif subject == pattern:
            return subject

        return None

    # ------------------------------------------------------------------
    # summary checks (results["behavior"]["summary"])
    # ------------------------------------------------------------------

    def check_process_name(self, pattern, all=False):
        if "behavior" in self.results and "processes" in self.results["behavior"]:
            for process in self.results["behavior"]["processes"]:
                if re.findall(pattern, process["process_name"], re.I):
                    return process if all else True
        return False

    def check_file(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("files", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_read_file(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("read_files", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_write_file(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("write_files", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_delete_file(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("delete_files", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_key(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("keys", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_read_key(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("read_keys", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_write_key(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("write_keys", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_delete_key(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("delete_keys", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_mutex(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("mutexes", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all, ignorecase=False)

    def check_started_service(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("started_services", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_created_service(self, pattern, regex=False, all=False):
        subject = self.results.get("behavior", {}).get("summary", {}).get("created_services", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_executed_command(self, pattern, regex=False, all=False, ignorecase=True):
        subject = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all, ignorecase=ignorecase)

    # ------------------------------------------------------------------
    # call/argument checks
    # ------------------------------------------------------------------

    def check_api(self, pattern, process=None, regex=False, all=False):
        """Checks for an API being called."""
        if all:
            retset = set()
        for item in self.results["behavior"]["processes"]:
            if process and item["process_name"] != process:
                continue
            for call in item["calls"]:
                ret = self._check_value(pattern=pattern, subject=call["api"], regex=regex, all=all, ignorecase=False)
                if ret:
                    if all:
                        retset.update(ret)
                    else:
                        return call["api"]

        return retset if all and len(retset) > 0 else None

    def check_argument_call(self, call, pattern, name=None, api=None, category=None, regex=False, all=False, ignorecase=False):
        """Checks for a specific argument of an invoked API."""
        if all:
            retset = set()

        if api and call["api"] != api:
            return False

        if category and call["category"] != category:
            return False

        for argument in call["arguments"]:
            if name and argument["name"] != name:
                continue

            ret = self._check_value(pattern=pattern, subject=argument["value"], regex=regex, all=all, ignorecase=ignorecase)
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return argument["value"]

        if all and len(retset) > 0:
            return retset

        return False

    def check_argument(self, pattern, name=None, api=None, category=None, process=None, regex=False, all=False, ignorecase=False):
        """Checks for a specific argument of an invoked API."""
        if all:
            retset = set()

        for item in self.results["behavior"]["processes"]:
            if process and item["process_name"] != process:
                continue

            for call in item["calls"]:
                r = self.check_argument_call(call, pattern, name, api, category, regex, all, ignorecase)
                if r:
                    if all:
                        retset.update(r)
                    else:
                        return r

        if all and len(retset) > 0:
            return retset

        return None

    # ------------------------------------------------------------------
    # network checks (results["network"]) -- empty in our model: safe no-match
    # ------------------------------------------------------------------

    def check_ip(self, pattern, regex=False, all=False):
        if all:
            retset = set()

        if "network" not in self.results:
            return None

        hosts = self.results["network"].get("hosts")
        if not hosts:
            return None

        for item in hosts:
            ret = self._check_value(pattern=pattern, subject=item["ip"], regex=regex, all=all, ignorecase=False)
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["ip"]

        if all and len(retset) > 0:
            return retset

        return None

    def check_domain(self, pattern, regex=False, all=False):
        if all:
            retset = set()

        if "network" not in self.results:
            return None

        domains = self.results["network"].get("domains")
        if not domains:
            return None

        for item in domains:
            ret = self._check_value(pattern=pattern, subject=item["domain"], regex=regex, all=all)
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["domain"]

        if all and len(retset) > 0:
            return retset

        return None

    def check_url(self, pattern, regex=False, all=False):
        if all:
            retset = set()

        if "network" not in self.results:
            return None

        httpitems = self.results["network"].get("http")
        if not httpitems:
            return None
        for item in httpitems:
            ret = self._check_value(pattern=pattern, subject=item["uri"], regex=regex, all=all, ignorecase=False)
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["uri"]

        if all and len(retset) > 0:
            return retset

        return None

    def check_suricata_alerts(self, pattern, blacklist=None):
        """No Suricata in our pipeline -- never matches."""
        return False

    def check_dnsbbl(self, domain: str):
        """DNS blocklist lookups need live DNS -- disabled offline."""
        return False, None

    def check_threatfox(self, searchterm: str):
        """Threat intel lookups are disabled offline."""
        return None

    # ------------------------------------------------------------------
    # process / argument accessors
    # ------------------------------------------------------------------

    def get_initial_process(self):
        """Obtains the initial process information."""
        if (
            "behavior" not in self.results
            or "processes" not in self.results["behavior"]
            or not len(self.results["behavior"]["processes"])
        ):
            return None

        return self.results["behavior"]["processes"][0]

    def get_environ_entry(self, proc, env_name):
        """Obtains environment entry from process."""
        if not proc or env_name not in proc.get("environ", {}):
            return None

        return proc["environ"][env_name]

    def get_argument(self, call, name):
        """Retrieves the value of a specific argument from an API call."""
        if call is not self._current_call_cache:
            self._current_call_cache = call
            self._current_call_dict = {argument["name"]: argument["value"] for argument in call["arguments"]}

        if name in self._current_call_dict:
            return self._current_call_dict[name]

        return None

    def get_raw_argument(self, call, name):
        """Retrieves the raw value of a specific argument from an API call."""
        if call is not self._current_call_raw_cache:
            self._current_call_raw_cache = call
            self._current_call_raw_dict = {
                argument["name"]: argument["raw_value"] for argument in call["arguments"] if "raw_value" in argument
            }

        if name in self._current_call_raw_dict:
            return self._current_call_raw_dict[name]

        return None

    def get_name_from_pid(self, pid):
        """Retrieve a process name from a supplied pid."""
        if pid:
            if isinstance(pid, str) and pid.isdigit():
                pid = int(pid)
            if self.results.get("behavior", {}).get("processes", []):
                for proc in self.results["behavior"]["processes"]:
                    if proc["process_id"] == pid:
                        return proc["process_name"]

        return None

    # ------------------------------------------------------------------
    # ordered/meta-signature helpers
    # ------------------------------------------------------------------

    def signature_matched(self, signame: str) -> bool:
        matched_signatures = [sig["name"] for sig in self.results.get("signatures", [])]
        return signame in matched_signatures

    def get_signature_data(self, signame: str) -> List[Dict[str, str]]:
        if self.signature_matched(signame):
            signature = next((m for m in self.results.get("signatures", []) if m.get("name") == signame), None)
            if signature:
                return signature.get("data", []) + signature.get("new_data", [])
        return []

    # ------------------------------------------------------------------
    # match recording
    # ------------------------------------------------------------------

    def mark_call(self, *args, **kwargs):
        """Mark the current call as explanation as to why this signature matched."""
        mark = {
            "type": "call",
            "pid": self.pid,
            "cid": self.cid,
        }

        if args or kwargs:
            log.warning("You have provided extra arguments to the mark_call() method which does not support doing so.")

        self.data.append(mark)

    def add_match(self, process, type, match):
        """Adds a match to the signature data."""
        signs = []
        if isinstance(match, list):
            signs.extend({"type": type, "value": item} for item in match)
        else:
            signs.append({"type": type, "value": match})

        process_summary = None
        if process:
            process_summary = {"process_name": process["process_name"], "process_id": process["process_id"]}

        self.new_data.append({"process": process_summary, "signs": signs})

    def has_matches(self) -> bool:
        """Returns true if there is matches (data is not empty)."""
        return len(self.new_data) > 0 or len(self.data) > 0

    def set_path(self, analysis_path):
        """CAPE calls this before run()/on_complete(); several signatures
        touch the path attributes even when they never read from disk."""
        self.analysis_path = analysis_path
        self.conf_path = ""
        self.file_path = ""
        self.dropped_path = ""
        self.procdump_path = ""
        self.CAPE_path = ""
        self.reports_path = ""
        self.shots_path = ""
        self.pcap_path = ""
        self.pmemory_path = ""
        self.memory_path = ""
        self.self_extracted = ""
        self.files_metadata = ""

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def on_call(self, call, process):
        """Notify signature about API call."""
        raise NotImplementedError

    def on_complete(self):
        """Evented signature is notified when all API calls are done."""
        raise NotImplementedError

    def run(self):
        """Start non-evented signature processing."""
        raise NotImplementedError

    def as_result(self):
        """Properties as a dict (for results)."""
        return dict(
            name=self.name,
            description=self.description,
            categories=self.categories,
            severity=self.severity,
            weight=self.weight,
            confidence=self.confidence,
            references=self.references,
            data=self.data,
            new_data=self.new_data,
            alert=self.alert,
            families=self.families,
        )


# ----------------------------------------------------------------------
# stub lib.cuckoo.common.* modules so vendored signatures import cleanly
# ----------------------------------------------------------------------

def _make_stub_modules() -> Dict[str, types.ModuleType]:
    """Build the lib.cuckoo.common.* modules the community set imports."""

    lib = types.ModuleType("lib")
    lib.__path__ = []
    cuckoo = types.ModuleType("lib.cuckoo")
    cuckoo.__path__ = []
    common = types.ModuleType("lib.cuckoo.common")
    common.__path__ = []

    abstracts = types.ModuleType("lib.cuckoo.common.abstracts")
    abstracts.Signature = Signature

    constants = types.ModuleType("lib.cuckoo.common.constants")
    constants.CUCKOO_ROOT = "."

    utils = types.ModuleType("lib.cuckoo.common.utils")

    def convert_to_printable(s, cache=None):
        return s

    def add_family_detection(results, family, detected_by, data=None):
        # Offline: family detections are recorded on the results model so
        # ordered signatures can still see them.
        detections = results.setdefault("_family_detections", [])
        detections.append({"family": family, "detected_by": detected_by, "data": data})

    utils.convert_to_printable = convert_to_printable
    utils.add_family_detection = add_family_detection

    fraunhofer = types.ModuleType("lib.cuckoo.common.fraunhofer_helper")

    def get_dga_lookup_dict():
        # The DGA lookup table ships with CAPE, not the community repo.
        return {}

    fraunhofer.get_dga_lookup_dict = get_dga_lookup_dict

    return {
        "lib": lib,
        "lib.cuckoo": cuckoo,
        "lib.cuckoo.common": common,
        "lib.cuckoo.common.abstracts": abstracts,
        "lib.cuckoo.common.constants": constants,
        "lib.cuckoo.common.utils": utils,
        "lib.cuckoo.common.fraunhofer_helper": fraunhofer,
    }


_installed = False


def install_compat_modules() -> None:
    """Register the stub lib.cuckoo.common.* modules in sys.modules (once)."""
    global _installed
    if _installed:
        return
    sys.modules.update(_make_stub_modules())
    _installed = True
