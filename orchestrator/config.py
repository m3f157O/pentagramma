"""Configuration loader for the sandbox orchestrator."""

import os
import re
import yaml
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"


class SandboxConfig:
    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self._config_path = config_path
        self._data: Dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        if not self._config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self._config_path}")
        with open(self._config_path, "r", encoding="utf-8") as f:
            self._data = yaml.safe_load(f) or {}

    def get(self, key: str, default: Any = None) -> Any:
        """Dot-notation getter, e.g. 'hyperv.vm_prefix'."""
        value = self._data
        for part in key.split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value

    @property
    def sandbox(self) -> Dict[str, Any]:
        return self._data.get("sandbox", {})

    @property
    def mode(self) -> str:
        """Execution backend: 'hyperv' (default) or 'local' (detonate on the
        orchestrator's own machine -- standalone/emergency package)."""
        return str(self._data.get("sandbox", {}).get("mode", "hyperv")).lower()

    @property
    def is_local_mode(self) -> bool:
        return self.mode == "local"

    @property
    def paths(self) -> Dict[str, str]:
        return self._data.get("paths", {})

    @property
    def hyperv(self) -> Dict[str, Any]:
        return self._data.get("hyperv", {})

    @property
    def edr(self) -> Dict[str, Any]:
        return self._data.get("edr", {})

    @property
    def telemetry(self) -> Dict[str, Any]:
        return self._data.get("telemetry", {})

    @property
    def analysis(self) -> Dict[str, Any]:
        return self._data.get("analysis", {})

    @property
    def network_capture(self) -> Dict[str, Any]:
        return self._data.get("network_capture", {})

    @property
    def cape_signatures(self) -> Dict[str, Any]:
        return self._data.get("cape_signatures", {})

    @property
    def screenshots(self) -> Dict[str, Any]:
        return self._data.get("screenshots", {})

    @property
    def process_dumps(self) -> Dict[str, Any]:
        return self._data.get("process_dumps", {})

    @property
    def dropped_files(self) -> Dict[str, Any]:
        return self._data.get("dropped_files", {})

    @property
    def sample_execution(self) -> Dict[str, Any]:
        return self._data.get("sample_execution", {})

    @property
    def sigma(self) -> Dict[str, Any]:
        return self._data.get("sigma", {})

    @property
    def api(self) -> Dict[str, Any]:
        return self._data.get("api", {})

    @property
    def static_analysis(self) -> Dict[str, Any]:
        return self._data.get("static_analysis", {})

    @property
    def behavioral_tracing(self) -> Dict[str, Any]:
        return self._data.get("behavioral_tracing", {})

    @property
    def guardian(self) -> Dict[str, Any]:
        return self._data.get("guardian", {})

    @property
    def console(self) -> Dict[str, Any]:
        return self._data.get("console", {})

    def vm_creds(self, vm_name: str) -> tuple:
        """Guest credentials (username, password) for a VM. Resolution order:
        1. config/vms.yaml (GUI-managed credential registry, Fleet page),
        2. the hyperv.vms list in config.yaml,
        3. legacy top-level hyperv.vm_username/vm_password keys.
        (None, None) when unknown -- no hidden defaults."""
        for entry in _read_vms_file().get("vms", []) or []:
            if isinstance(entry, dict) and entry.get("name") == vm_name:
                return entry.get("username"), entry.get("password")
        for entry in self.hyperv.get("vms", []) or []:
            if isinstance(entry, dict) and entry.get("name") == vm_name:
                return entry.get("username"), entry.get("password")
        legacy = (self.hyperv.get("vm_username"), self.hyperv.get("vm_password"))
        return legacy if legacy != (None, None) else (None, None)


def get_config() -> SandboxConfig:
    env_path = os.environ.get("SANDBOX_CONFIG")
    if env_path:
        return SandboxConfig(Path(env_path))
    return SandboxConfig()


VALID_MODES = ("hyperv", "local")

VMS_FILE_PATH = DEFAULT_CONFIG_PATH.parent / "vms.yaml"


def _vms_file_path() -> Path:
    """GUI-managed credential registry (Fleet page). Lives next to
    config.yaml; gitignored (contains guest passwords)."""
    env_path = os.environ.get("SANDBOX_CONFIG")
    if env_path:
        return Path(env_path).parent / "vms.yaml"
    return VMS_FILE_PATH


def _read_vms_file() -> Dict[str, Any]:
    path = _vms_file_path()
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _write_vms_file(data: Dict[str, Any]) -> None:
    path = _vms_file_path()
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def set_vm_credentials(vm_name: str, username: str, password: str) -> None:
    """Upsert a VM credential entry into config/vms.yaml (Fleet page)."""
    vm_name = (vm_name or "").strip()
    if not vm_name or not username:
        raise ValueError("vm name and username are required")
    data = _read_vms_file()
    vms = data.setdefault("vms", [])
    for entry in vms:
        if isinstance(entry, dict) and entry.get("name") == vm_name:
            entry["username"] = username
            entry["password"] = password
            break
    else:
        vms.append({"name": vm_name, "username": username, "password": password})
    _write_vms_file(data)


def delete_vm_credentials(vm_name: str) -> bool:
    """Remove a VM credential entry from config/vms.yaml. True if removed."""
    data = _read_vms_file()
    vms = data.get("vms", []) or []
    kept = [e for e in vms if not (isinstance(e, dict) and e.get("name") == vm_name)]
    if len(kept) == len(vms):
        return False
    data["vms"] = kept
    _write_vms_file(data)
    return True


def registered_vm_credentials(config_hyperv: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Merged credential registry for the Fleet page: name ->
    {"configured": bool, "username": str|None}. Presence + username only,
    never passwords. vms.yaml (GUI-managed) takes precedence over the
    hyperv.vms list in config.yaml."""
    registry: Dict[str, Dict[str, Any]] = {}
    for source in (config_hyperv.get("vms", []) or [], _read_vms_file().get("vms", []) or []):
        for entry in source:
            if isinstance(entry, dict) and entry.get("name"):
                registry[entry["name"]] = {
                    "configured": bool(entry.get("username") and entry.get("password")),
                    "username": entry.get("username"),
                }
    return registry


def set_mode(mode: str, config_path: Path = None) -> str:
    """Write ``sandbox.mode`` into config.yaml and return the previous value.

    Section-aware text surgery (preserves comments and layout; one-time
    backup at ``config.yaml.bak``) rather than a yaml round-trip, which would
    strip the heavily-commented file bare. Picked up by the next
    ``get_config()`` call, so new analyses use it immediately; an
    orchestrator restart is still recommended for cached subsystems.
    """
    mode = (mode or "").strip().lower()
    if mode not in VALID_MODES:
        raise ValueError(f"invalid sandbox mode {mode!r} (expected one of {VALID_MODES})")
    if config_path is None:
        env_path = os.environ.get("SANDBOX_CONFIG")
        config_path = Path(env_path) if env_path else DEFAULT_CONFIG_PATH
    path = Path(config_path)
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    # Locate the top-level "sandbox:" section, then its "mode:" key.
    start = next((i for i, ln in enumerate(lines) if ln.startswith("sandbox:")), None)
    if start is None:
        raise ValueError(f"{path} has no 'sandbox:' section")
    previous = None
    for j in range(start + 1, len(lines)):
        ln = lines[j]
        stripped = ln.strip()
        if stripped and not ln[0] in (" ", "#"):
            break  # next top-level section: sandbox: had no mode key
        m = re.match(r"^(\s*)mode:\s*(\S+)(.*)$", ln.rstrip("\n"))
        if m:
            previous = m.group(2).strip().lower()
            newline = "\n" if ln.endswith("\n") else ""
            lines[j] = f"{m.group(1)}mode: {mode}{m.group(3)}{newline}"
            break
    if previous is None:
        raise ValueError(f"{path} sandbox: section has no 'mode:' key")

    if previous != mode:
        bak = path.with_suffix(".yaml.bak")
        if not bak.exists():
            bak.write_text(text, encoding="utf-8")
        path.write_text("".join(lines), encoding="utf-8")
    return previous
