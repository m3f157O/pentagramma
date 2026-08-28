"""Configuration loader for the sandbox orchestrator."""

import os
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


def get_config() -> SandboxConfig:
    env_path = os.environ.get("SANDBOX_CONFIG")
    if env_path:
        return SandboxConfig(Path(env_path))
    return SandboxConfig()
