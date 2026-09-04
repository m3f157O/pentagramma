"""Sample-format resolution and guest launch-command planning.

Resolves what kind of sample was submitted (exe/dll/script/zip/url) and
builds the concrete (launcher_path, launcher_arguments) pair the guest
should execute -- replacing the old "always launch the sample file
directly" assumption with a per-format dispatch table. See
scripts/hyperv-vm.ps1::Invoke-SampleExecution for where LaunchPlan output
is consumed.
"""

import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import filetype
import pefile

VALID_SAMPLE_TYPES = {"exe", "dll", "js", "vbs", "ps1", "bat", "zip", "url", "unknown"}

# Text-based script types have no distinguishing magic bytes, so extension
# is their only detection signal. .cmd is folded into "bat" -- cmd.exe /c
# treats both extensions identically, so there's no behavioral difference
# to preserve by keeping them as separate sample types.
EXTENSION_TO_TYPE = {
    "exe": "exe",
    "dll": "dll",
    "js": "js",
    "jse": "js",
    "vbs": "vbs",
    "vbe": "vbs",
    "ps1": "ps1",
    "bat": "bat",
    "cmd": "bat",
    "zip": "zip",
}

SAMPLE_TYPE_TO_EXTENSION = {
    "exe": "exe",
    "dll": "dll",
    "js": "js",
    "vbs": "vbs",
    "ps1": "ps1",
    "bat": "bat",
}

DEFAULT_LAUNCHER_PATHS = {
    "wscript": r"C:\Windows\System32\wscript.exe",
    "cscript": r"C:\Windows\System32\cscript.exe",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "cmd": r"C:\Windows\System32\cmd.exe",
    "rundll32": r"C:\Windows\System32\rundll32.exe",
    "regsvr32": r"C:\Windows\System32\regsvr32.exe",
    "explorer": r"C:\Windows\explorer.exe",
    "curl": r"C:\Windows\System32\curl.exe",
}


@dataclass
class LaunchPlan:
    sample_type: str
    launcher_path: Optional[str] = None
    launcher_arguments: Optional[str] = None
    destination_filename: Optional[str] = None
    working_directory: Optional[str] = None
    dll_exports: Optional[List[str]] = field(default=None)
    execution_error: Optional[str] = None
    execution_error_detail: Optional[Any] = None


class ArchiveResolutionError(Exception):
    def __init__(self, code: str, message: str, entries: Optional[List[str]] = None):
        super().__init__(message)
        self.code = code
        self.entries = entries or []


# ---------------------------------------------------------------------------
# Type resolution
# ---------------------------------------------------------------------------

def _sniff_pe_type(data: bytes) -> Optional[str]:
    """Authoritative exe-vs-dll check via the PE header's IMAGE_FILE_DLL
    flag. Takes priority over extension for this pair specifically, since
    extension alone is often wrong (malware routinely ships DLLs renamed
    to .exe and vice versa) and pefile can settle it definitively.
    """
    if data[:2] != b"MZ":
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return None
    try:
        return "dll" if pe.is_dll() else "exe"
    finally:
        pe.close()


def resolve_sample_type(filename: str, data: bytes, override: Optional[str] = None) -> str:
    if override:
        normalized = override.strip().lower()
        if normalized not in VALID_SAMPLE_TYPES:
            raise ValueError(f"Unknown sample_type override: {override!r}")
        return normalized

    pe_type = _sniff_pe_type(data)
    if pe_type:
        return pe_type

    ext = Path(filename).suffix.lower().lstrip(".")
    if ext in EXTENSION_TO_TYPE:
        return EXTENSION_TO_TYPE[ext]

    kind = filetype.guess(data)
    if kind and kind.extension == "zip":
        return "zip"

    return "unknown"


# ---------------------------------------------------------------------------
# DLL export inspection
# ---------------------------------------------------------------------------

def _list_pe_exports(data: bytes) -> List[str]:
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    except Exception:
        return []
    exports: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(exp.name.decode("utf-8", errors="ignore") if exp.name else f"#{exp.ordinal}")
    pe.close()
    return exports


def _resolve_dll_launch(
    guest_path: str,
    dest_filename: str,
    working_directory: str,
    sample_data: Optional[bytes],
    override: Optional[str],
    launcher_paths: Dict[str, str],
) -> LaunchPlan:
    exports = _list_pe_exports(sample_data) if sample_data is not None else []
    base = dict(sample_type="dll", destination_filename=dest_filename, working_directory=working_directory, dll_exports=exports)

    if override:
        return LaunchPlan(
            **base,
            launcher_path=launcher_paths.get("rundll32", DEFAULT_LAUNCHER_PATHS["rundll32"]),
            launcher_arguments=f'"{guest_path}",{override}',
        )
    if "DllRegisterServer" in exports:
        return LaunchPlan(
            **base,
            launcher_path=launcher_paths.get("regsvr32", DEFAULT_LAUNCHER_PATHS["regsvr32"]),
            launcher_arguments=f'/s "{guest_path}"',
        )
    if len(exports) == 1:
        return LaunchPlan(
            **base,
            launcher_path=launcher_paths.get("rundll32", DEFAULT_LAUNCHER_PATHS["rundll32"]),
            launcher_arguments=f'"{guest_path}",{exports[0]}',
        )
    if not exports:
        return LaunchPlan(
            **base,
            execution_error="no_exports_found",
            execution_error_detail="The DLL exports no functions; pass dll_entry_point to force a rundll32 invocation.",
        )
    return LaunchPlan(
        **base,
        execution_error="ambiguous_entry_point",
        execution_error_detail=exports,
    )


# ---------------------------------------------------------------------------
# Launch plan construction
# ---------------------------------------------------------------------------

def build_launch_plan(
    sample_type: str,
    guest_destination_folder: str,
    sample_data: Optional[bytes] = None,
    dll_entry_point_override: Optional[str] = None,
    launcher_paths: Optional[Dict[str, str]] = None,
    script_engine: str = "wscript",
    powershell_args: str = "-NoProfile -ExecutionPolicy Bypass",
) -> LaunchPlan:
    launcher_paths = launcher_paths or DEFAULT_LAUNCHER_PATHS
    folder = guest_destination_folder.rstrip("\\")

    if sample_type in ("exe", "unknown"):
        # Reproduces today's exact behavior: no launcher override, no
        # synthetic destination filename -- direct launch of the copied
        # sample file exactly as before this feature existed.
        return LaunchPlan(sample_type=sample_type)

    if sample_type not in SAMPLE_TYPE_TO_EXTENSION:
        raise ValueError(f"Unsupported sample_type for launch plan: {sample_type!r}")

    ext = SAMPLE_TYPE_TO_EXTENSION[sample_type]
    dest_filename = f"sample.{ext}"
    guest_path = f"{folder}\\{dest_filename}"

    if sample_type in ("js", "vbs"):
        engine = script_engine if script_engine in ("wscript", "cscript") else "wscript"
        return LaunchPlan(
            sample_type=sample_type,
            launcher_path=launcher_paths.get(engine, DEFAULT_LAUNCHER_PATHS[engine]),
            launcher_arguments=f'"{guest_path}"',
            destination_filename=dest_filename,
            working_directory=folder,
        )

    if sample_type == "ps1":
        return LaunchPlan(
            sample_type=sample_type,
            launcher_path=launcher_paths.get("powershell", DEFAULT_LAUNCHER_PATHS["powershell"]),
            launcher_arguments=f'{powershell_args} -File "{guest_path}"',
            destination_filename=dest_filename,
            working_directory=folder,
        )

    if sample_type == "bat":
        return LaunchPlan(
            sample_type=sample_type,
            launcher_path=launcher_paths.get("cmd", DEFAULT_LAUNCHER_PATHS["cmd"]),
            launcher_arguments=f'/c "{guest_path}"',
            destination_filename=dest_filename,
            working_directory=folder,
        )

    return _resolve_dll_launch(guest_path, dest_filename, folder, sample_data, dll_entry_point_override, launcher_paths)


def validate_url(url: str) -> str:
    if not url or not isinstance(url, str):
        raise ValueError("url must be a non-empty string")
    cleaned = url.strip()
    for bad_char in ('"', "\n", "\r", "\x00"):
        if bad_char in cleaned:
            raise ValueError("URL contains a disallowed character")
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme {parsed.scheme!r} (only http/https are allowed)")
    if not parsed.netloc:
        raise ValueError("URL is missing a host")
    return cleaned


def derive_fetch_filename(url: str, default: str = "download.bin") -> str:
    parsed = urlparse(url)
    name = Path(parsed.path).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._") if name else ""
    return name[:120] if name else default


def build_url_launch_plan(
    url: str,
    url_mode: str,
    guest_destination_folder: str,
    launcher_paths: Optional[Dict[str, str]] = None,
    fetch_curl_args: str = "-s -k -L",
    fetch_default_filename: str = "download.bin",
) -> LaunchPlan:
    launcher_paths = launcher_paths or DEFAULT_LAUNCHER_PATHS
    folder = guest_destination_folder.rstrip("\\")
    clean_url = validate_url(url)
    mode = url_mode if url_mode in ("browse", "fetch") else "browse"

    if mode == "browse":
        # explorer.exe takes a single argv with no shell metacharacter
        # interpretation -- unlike `cmd.exe /c start`, an adversarial URL
        # containing '&'/'|' cannot break out into a second command.
        return LaunchPlan(
            sample_type="url",
            launcher_path=launcher_paths.get("explorer", DEFAULT_LAUNCHER_PATHS["explorer"]),
            launcher_arguments=f'"{clean_url}"',
            working_directory=folder,
        )

    dest_filename = derive_fetch_filename(clean_url, fetch_default_filename)
    guest_path = f"{folder}\\{dest_filename}"
    return LaunchPlan(
        sample_type="url",
        launcher_path=launcher_paths.get("curl", DEFAULT_LAUNCHER_PATHS["curl"]),
        launcher_arguments=f'{fetch_curl_args} -o "{guest_path}" "{clean_url}"',
        working_directory=folder,
    )


# ---------------------------------------------------------------------------
# ZIP archive resolution
# ---------------------------------------------------------------------------

def list_archive_file_entries(data: bytes) -> List[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return [info.filename for info in zf.infolist() if not info.is_dir()]


def resolve_archive_entry(
    data: bytes,
    archive_entry: Optional[str] = None,
    archive_password: Optional[str] = None,
    extra_passwords: Optional[List[str]] = None,
    max_entry_size_bytes: int = 104857600,
    max_total_entries: int = 2000,
) -> Tuple[str, bytes]:
    """Reads the resolved entry's bytes directly via ZipFile.read() -- never
    extractall() -- so there's no attacker-controlled path ever written to
    host disk (eliminates zip-slip by construction, not by validation).
    """
    extra_passwords = extra_passwords or []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ArchiveResolutionError("invalid_archive", f"Not a valid ZIP archive: {exc}") from exc

    with zf:
        entries = [info for info in zf.infolist() if not info.is_dir()]
        if len(entries) > max_total_entries:
            raise ArchiveResolutionError(
                "too_many_entries", f"Archive contains {len(entries)} entries, exceeding the {max_total_entries} cap"
            )
        if not entries:
            raise ArchiveResolutionError("empty_archive", "Archive contains no files")

        if archive_entry:
            matches = [info for info in entries if info.filename == archive_entry]
            if not matches:
                raise ArchiveResolutionError(
                    "entry_not_found",
                    f"{archive_entry!r} not found in archive",
                    entries=[info.filename for info in entries],
                )
            chosen = matches[0]
        elif len(entries) == 1:
            chosen = entries[0]
        else:
            raise ArchiveResolutionError(
                "multiple_entries",
                f"Archive contains {len(entries)} files; specify archive_entry to choose one",
                entries=[info.filename for info in entries],
            )

        if chosen.file_size > max_entry_size_bytes:
            raise ArchiveResolutionError(
                "entry_too_large",
                f"{chosen.filename!r} is {chosen.file_size} bytes, exceeding the {max_entry_size_bytes} cap",
            )

        candidates: List[Optional[str]] = [None]
        if archive_password:
            candidates.append(archive_password)
        for extra in extra_passwords:
            if extra not in candidates:
                candidates.append(extra)

        last_error: Optional[Exception] = None
        for candidate in candidates:
            try:
                pwd = candidate.encode("utf-8") if candidate else None
                content = zf.read(chosen.filename, pwd=pwd)
                return chosen.filename, content
            except NotImplementedError:
                # AES-encrypted zip (MalwareBazaar switched to AES): stdlib
                # zipfile only speaks legacy ZipCrypto -- fall back to
                # pyzipper, still fully in-memory (no host-disk extraction).
                return chosen.filename, _read_aes_zip_entry(
                    data, chosen.filename, candidates, max_entry_size_bytes
                )
            except RuntimeError as exc:
                last_error = exc
                continue

        raise ArchiveResolutionError(
            "wrong_password", f"Failed to decrypt {chosen.filename!r} with any known password"
        ) from last_error


def _read_aes_zip_entry(
    data: bytes,
    entry_name: str,
    password_candidates: List[Optional[str]],
    max_entry_size_bytes: int,
) -> bytes:
    """Read one entry from an AES-encrypted zip via pyzipper (lazy import).
    Same safety contract as resolve_archive_entry: read() into memory only,
    never extract to host disk."""
    try:
        import pyzipper
    except ImportError as exc:
        raise ArchiveResolutionError(
            "unsupported_encryption",
            "Archive uses AES encryption and pyzipper is not installed "
            "(pip install pyzipper into the orchestrator venv)",
        ) from exc
    last_error: Optional[Exception] = None
    for candidate in password_candidates:
        try:
            with pyzipper.AESZipFile(io.BytesIO(data)) as azf:
                info = azf.getinfo(entry_name)
                if info.file_size > max_entry_size_bytes:
                    raise ArchiveResolutionError(
                        "entry_too_large",
                        f"{entry_name!r} is {info.file_size} bytes, exceeding the {max_entry_size_bytes} cap",
                    )
                pwd = candidate.encode("utf-8") if candidate else None
                return azf.read(entry_name, pwd=pwd)
        except ArchiveResolutionError:
            raise
        except (RuntimeError, OSError, KeyError) as exc:
            last_error = exc
            continue
    raise ArchiveResolutionError(
        "wrong_password", f"Failed to decrypt {entry_name!r} (AES) with any known password"
    ) from last_error
