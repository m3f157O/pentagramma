"""Guest-side network capture using Windows built-in pktmon.exe.

This module wraps pktmon so the orchestrator can start a PCAPNG-compatible
capture before a sample runs, stop it after the analysis timeout, and copy the
resulting capture off the VM before the snapshot is restored.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import proc_util


class PktmonCaptureError(Exception):
    """Raised when a pktmon operation fails."""


class NetworkCapture:
    """Manage a pktmon-based network capture inside the sandbox VM."""

    def __init__(
        self,
        output_dir: str | Path = r"C:\SandboxAgent",
        etl_filename: str = "network.etl",
        pcapng_filename: str = "network.pcapng",
        max_file_size_mb: int = 256,
        snaplen_bytes: int = 0,
        components: str = "all",
    ):
        self.output_dir = Path(output_dir)
        self.etl_path = self.output_dir / etl_filename
        self.pcapng_path = self.output_dir / pcapng_filename
        self.max_file_size_mb = max_file_size_mb
        self.snaplen_bytes = snaplen_bytes
        self.components = components
        self.pktmon = self._find_pktmon()

    @staticmethod
    def _find_pktmon() -> str:
        """Return the path to pktmon.exe or raise if not found."""
        pktmon = shutil.which("pktmon")
        if pktmon:
            return pktmon
        # Common System32 location on modern Windows
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "pktmon.exe"
        if system32.exists():
            return str(system32)
        raise PktmonCaptureError("pktmon.exe not found; requires Windows 10 2004+ / Server 2019+")

    @staticmethod
    def _is_admin() -> bool:
        """Check whether the current process is elevated."""
        try:
            return os.getuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]

    def _run(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        """Run pktmon with the given arguments."""
        cmd = [self.pktmon] + args
        result = proc_util.run_text(cmd, check=False)
        if check and result.returncode != 0:
            raise PktmonCaptureError(
                f"pktmon {' '.join(args)} failed (exit {result.returncode}): {result.stderr or result.stdout}"
            )
        return result

    def list_components(self) -> List[Dict[str, Any]]:
        """List pktmon capture components (NICs, etc.) as JSON."""
        result = self._run(["list", "--json"])
        try:
            data = json.loads(result.stdout)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []

    def start(self) -> Dict[str, Any]:
        """Start a circular pktmon capture to an ETL file."""
        if not self._is_admin():
            raise PktmonCaptureError("Network capture requires Administrator privileges")

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # pktmon only supports one active session; stop any stale session first.
        try:
            self._run(["stop"], check=False)
        except PktmonCaptureError:
            pass

        # Remove any previous ETL so the capture starts clean.
        if self.etl_path.exists():
            self.etl_path.unlink()

        self._run(
            [
                "start",
                "--capture",
                "--comp",
                self.components,
                "--pkt-size",
                str(self.snaplen_bytes),
                "--file-name",
                str(self.etl_path),
                "--file-size",
                str(self.max_file_size_mb),
                "--log-mode",
                "circular",
            ]
        )

        return {
            "status": "started",
            "etl_path": str(self.etl_path),
            "max_file_size_mb": self.max_file_size_mb,
            "snaplen_bytes": self.snaplen_bytes,
            "components": self.components,
        }

    def stop(self) -> Dict[str, Any]:
        """Stop the active pktmon capture."""
        result = self._run(["stop"])
        return {
            "status": "stopped",
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }

    def convert_to_pcapng(self) -> Dict[str, Any]:
        """Convert the ETL log to PCAPNG format."""
        if not self.etl_path.exists():
            raise PktmonCaptureError(f"ETL file not found: {self.etl_path}")
        if self.pcapng_path.exists():
            self.pcapng_path.unlink()
        self._run(["etl2pcap", str(self.etl_path), "--out", str(self.pcapng_path)])
        return {
            "status": "converted",
            "etl_path": str(self.etl_path),
            "pcapng_path": str(self.pcapng_path),
            "pcapng_size_bytes": self.pcapng_path.stat().st_size if self.pcapng_path.exists() else 0,
        }

    def status(self) -> Dict[str, Any]:
        """Return pktmon status."""
        result = self._run(["status"], check=False)
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }


def _json_out(data: Dict[str, Any]) -> None:
    # Single-line JSON so PowerShell Direct returns it as one parseable string.
    print(json.dumps(data, separators=(",", ":"), default=str))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Guest-side pktmon network capture helper")

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--output-dir",
        default=r"C:\SandboxAgent",
        help="Directory for ETL and PCAPNG files (default: C:\SandboxAgent)",
    )
    parent_parser.add_argument("--etl-filename", default="network.etl")
    parent_parser.add_argument("--pcapng-filename", default="network.pcapng")
    parent_parser.add_argument("--max-file-size-mb", type=int, default=256)
    parent_parser.add_argument("--snaplen-bytes", type=int, default=0)
    parent_parser.add_argument("--components", default="all")

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("start", parents=[parent_parser], help="Start capture")
    subparsers.add_parser("stop", parents=[parent_parser], help="Stop capture")
    subparsers.add_parser("convert", parents=[parent_parser], help="Convert ETL to PCAPNG")
    subparsers.add_parser("status", parents=[parent_parser], help="Show pktmon status")
    subparsers.add_parser("list", parents=[parent_parser], help="List pktmon components")

    args = parser.parse_args(argv)

    capture = NetworkCapture(
        output_dir=args.output_dir,
        etl_filename=args.etl_filename,
        pcapng_filename=args.pcapng_filename,
        max_file_size_mb=args.max_file_size_mb,
        snaplen_bytes=args.snaplen_bytes,
        components=args.components,
    )

    try:
        if args.command == "start":
            _json_out(capture.start())
        elif args.command == "stop":
            _json_out(capture.stop())
        elif args.command == "convert":
            _json_out(capture.convert_to_pcapng())
        elif args.command == "status":
            _json_out(capture.status())
        elif args.command == "list":
            _json_out({"components": capture.list_components()})
    except PktmonCaptureError as exc:
        _json_out({"status": "error", "message": str(exc)})
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
