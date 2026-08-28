"""
Batch-mode ETW collector for local telemetry testing.

Uses built-in Windows tools:
  - logman   : start/stop ETW trace sessions
  - tracerpt : convert ETL files to XML

This is intentionally simple. A real-time streaming version will come later.
"""

import ctypes
import json
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

# Kernel ETW provider and keyword flags.
# Verified with: logman query providers "Windows Kernel Trace"
# Keywords: process, thread, file, registry, net, img, disk, fileio, ...
KERNEL_TRACE_PROVIDER = "Windows Kernel Trace"
KERNEL_TRACE_FLAGS = ["process", "thread", "file", "registry", "net"]

# Kernel trace sessions must use the special name "NT Kernel Logger".
# Only one kernel trace session can run on the system at a time.
DEFAULT_SESSION_NAME = "NT Kernel Logger"

# Namespace used by tracerpt output.
TRACERPT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class EtwCollector:
    def __init__(
        self,
        flags: Optional[List[str]] = None,
        session_name: str = DEFAULT_SESSION_NAME,
    ):
        self.flags = flags or KERNEL_TRACE_FLAGS
        self.session_name = session_name
        self._etl_path: Optional[Path] = None

    # ------------------------------------------------------------------
    # Session control
    # ------------------------------------------------------------------

    def start(self, etl_path: Optional[Path] = None) -> Path:
        """Start a new ETW trace session.

        If etl_path is not provided, a temp file is used.
        Any existing session with the same name is deleted first.
        """
        if etl_path is None:
            etl_path = Path(tempfile.gettempdir()) / f"{self.session_name}.etl"
        self._etl_path = Path(etl_path)

        # Clean up any stale session with the same name.
        subprocess.run(
            ["logman", "stop", self.session_name, "-ets"],
            capture_output=True,
        )
        subprocess.run(
            ["logman", "delete", self.session_name, "-ets"],
            capture_output=True,
        )

        flags_str = ",".join(self.flags)
        # logman kernel trace syntax (verified):
        #   logman start "NT Kernel Logger" -p "Windows Kernel Trace" (process,thread,file,registry,net) -o file.etl -ets
        # The flags must be enclosed in parentheses.
        cmd = [
            "logman",
            "start",
            self.session_name,
            "-ets",
            "-ow",
            "-max",
            "500",
            "-bs",
            "1024",
            "-nb",
            "24",
            "48",
            "-f",
            "bincirc",
            "-o",
            str(self._etl_path),
            "-p",
            KERNEL_TRACE_PROVIDER,
            f"({flags_str})",
        ]

        print(f"[etw] starting session '{self.session_name}' with flags ({flags_str})")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip()
            # 0x80070005 = access denied; 0x80070427 = cannot perform this operation on a built-in account
            if "access is denied" in err.lower():
                raise RuntimeError(
                    "Kernel ETW providers require Administrator privileges. "
                    "Please restart your terminal as Administrator and try again."
                )
            raise RuntimeError(f"logman failed (exit {proc.returncode}): {err}")
        return self._etl_path

    def stop(self) -> Path:
        """Stop the ETW trace session and return the ETL file path."""
        if self._etl_path is None:
            raise RuntimeError("ETW session was not started")
        print(f"[etw] stopping session '{self.session_name}'")
        stop_proc = subprocess.run(
            ["logman", "stop", self.session_name, "-ets"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if stop_proc.returncode != 0:
            err = stop_proc.stderr.strip() or stop_proc.stdout.strip()
            raise RuntimeError(f"logman stop failed ({stop_proc.returncode}): {err}")
        print(f"[etw] trace file: {self._etl_path} ({self._etl_path.stat().st_size} bytes)")
        return self._etl_path

    def delete_session(self) -> None:
        """Delete the session definition (does not delete the ETL file)."""
        subprocess.run(
            ["logman", "delete", self.session_name, "-ets"],
            capture_output=True,
        )

    # ------------------------------------------------------------------
    # Conversion to JSONL
    # ------------------------------------------------------------------

    def convert_to_jsonl(self, etl_path: Path, jsonl_path: Path) -> int:
        """Convert an ETL file to normalized JSONL.

        Returns the number of events written.
        """
        etl_path = Path(etl_path)
        jsonl_path = Path(jsonl_path)

        xml_path = jsonl_path.with_suffix(".xml")
        summary_path = jsonl_path.with_suffix(".txt")

        print(f"[etw] converting {etl_path} to XML with tracerpt")
        # tracerpt writes XML + summary. We ignore the summary.
        tr_proc = subprocess.run(
            [
                "tracerpt",
                str(etl_path),
                "-o",
                str(xml_path),
                "-summary",
                str(summary_path),
                "-y",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if tr_proc.returncode != 0:
            err = tr_proc.stderr.strip() or tr_proc.stdout.strip()
            raise RuntimeError(f"tracerpt failed ({tr_proc.returncode}): {err}")
        print(f"[etw] XML size: {xml_path.stat().st_size} bytes")

        events = self._parse_tracerpt_xml(xml_path)
        print(f"[etw] parsed {len(events)} events from XML")

        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with jsonl_path.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")

        # Clean up intermediate files.
        xml_path.unlink(missing_ok=True)
        summary_path.unlink(missing_ok=True)

        print(f"[etw] wrote {len(events)} events to {jsonl_path}")
        return len(events)

    def _parse_tracerpt_xml(self, xml_path: Path) -> List[Dict]:
        """Parse tracerpt XML into normalized event dicts."""
        ns = TRACERPT_NS
        events: List[Dict] = []

        try:
            tree = ET.parse(str(xml_path))
        except ET.ParseError:
            return events

        root = tree.getroot()
        for ev in root.findall(f"{ns}Event"):
            system = ev.find(f"{ns}System")
            if system is None:
                continue

            provider = system.find(f"{ns}Provider")
            event_id = system.find(f"{ns}EventID")
            time_created = system.find(f"{ns}TimeCreated")
            computer = system.find(f"{ns}Computer")

            provider_name = provider.get("Name") if provider is not None else None
            provider_guid = provider.get("Guid") if provider is not None else None

            # RenderingInfo may contain Opcode and Task which help classify.
            rendering = ev.find(f"{ns}RenderingInfo")
            opcode = None
            task = None
            if rendering is not None:
                opcode_el = rendering.find(f"{ns}Opcode")
                if opcode_el is not None:
                    opcode = opcode_el.text
                task_el = rendering.find(f"{ns}Task")
                if task_el is not None:
                    task = task_el.text

            event: Dict = {
                "source": "etw",
                "provider_name": provider_name,
                "provider_guid": provider_guid,
                "event_id": int(event_id.text) if event_id is not None and event_id.text else None,
                "event_name": task,
                "opcode": opcode,
                "timestamp": time_created.get("SystemTime") if time_created is not None else None,
                "computer": computer.text if computer is not None else None,
                "data": {},
            }

            data = ev.find(f"{ns}EventData")
            if data is not None:
                for field in data:
                    key = field.get("Name")
                    if key:
                        event["data"][key] = field.text

            # Add a friendly event_type based on provider + event_id.
            event["event_type"] = self._classify(event)
            events.append(event)

        return events

    def _classify(self, event: Dict) -> str:
        """Map classic kernel trace opcode to a sandbox-friendly event type."""
        opcode = (event.get("opcode") or "").lower()

        # Process lifecycle
        if opcode == "start":
            return "ProcessStart"
        if opcode in ("stop", "end", "terminate"):
            return "ProcessStop"
        if opcode == "dcstart":
            return "ProcessDcStart"
        if opcode in ("dcstop", "dcend"):
            return "ProcessDcStop"

        # Thread lifecycle
        if opcode == "thread_start":
            return "ThreadStart"
        if opcode == "thread_stop":
            return "ThreadStop"

        # File I/O (coarse grouping)
        file_opcodes = {
            "create", "cleanup", "close", "read", "write", "flush",
            "setinformation", "setinfo", "delete", "rename", "createnewfile",
            "filecreate", "filedelete", "filecleanup", "fileclose",
            "fileread", "filewrite", "filerundown", "queryinformation",
            "querysecurity", "setsecurity", "dirnotify",
        }
        if opcode in file_opcodes:
            return "FileIo"

        # Registry (coarse grouping)
        registry_opcodes = {
            "createkey", "open", "openkey", "deletekey", "querykey",
            "setvalue", "deletevalue", "queryvalue",
            "enumeratekey", "enumeratevaluekey",
            "kcbcreate", "kcbdelete", "kcb rundown", "kcbrundownend",
            "query", "querysecurity", "setinformation", "setname",
        }
        if opcode in registry_opcodes:
            return "Registry"

        # Network (coarse grouping)
        network_opcodes = {
            "send", "recv", "connect", "disconnect", "accept",
            "retransmit", "tcpsendipv4", "tcpreceiveipv4",
            "udpsendipv4", "udpreceiveipv4",
            "sendipv4", "recvipv4", "connectipv4", "disconnectipv4", "acceptipv4",
            "sendipv6", "recvipv6", "connectipv6", "disconnectipv6", "acceptipv6",
            "tcpcopyipv4", "tcpcopyipv6",
        }
        if opcode in network_opcodes:
            return "Network"

        # Services enumeration (useful for sandbox baseline)
        if opcode == "services":
            return "Services"

        # Metadata / noise — system configuration events
        meta_opcodes = {
            "header", "extension", "endextension", "partitioninfoextensionv2",
            "cpu", "platform", "video", "power", "irq", "processors",
            "nic", "phydisk", "logdisk", "defragmentation",
            "boot config info", "codeintegrity", "config", "counters",
            "devicefamily", "dpi", "flightids", "telemetryconfiguration",
            "virtualization config info", "pnp", "rdcomplete",
        }
        if opcode in meta_opcodes:
            return "Meta"

        return opcode.title() if opcode else "Unknown"

    # ------------------------------------------------------------------
    # Convenience helper
    # ------------------------------------------------------------------

    def collect_during(
        self,
        command: List[str],
        jsonl_path: Path,
        pre_delay: float = 1.0,
        post_delay: float = 1.0,
    ) -> int:
        """Start ETW, run a command, stop ETW, and write normalized JSONL."""
        self.start()
        try:
            time.sleep(pre_delay)
            subprocess.run(command, check=False)
            time.sleep(post_delay)
            self.stop()
        finally:
            self.delete_session()

        return self.convert_to_jsonl(self._etl_path, jsonl_path)


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


if __name__ == "__main__":
    if not is_admin():
        print("[warn] ETW kernel providers usually require Administrator privileges.")
        print("[warn] If logman fails, restart this terminal as Administrator.\n")

    if len(sys.argv) < 2:
        print("Usage: etw_collector.py <command> [args...]")
        print("Example: python etw_collector.py tests/local/test-dropper.bat")
        sys.exit(1)

    target = sys.argv[1:]
    out = Path("logs/etw_test.jsonl").resolve()

    collector = EtwCollector()
    count = collector.collect_during(target, out)
    print(f"Captured {count} ETW events -> {out}")
