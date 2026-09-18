"""Execution-backend factory: where detonation happens.

``sandbox.mode`` in config.yaml selects the backend:

- ``hyperv`` (default) -- the dedicated Hyper-V analysis VM, driven through
  PowerShell Direct by :class:`orchestrator.hyperv.HyperVManager`.
- ``local`` -- the orchestrator's own machine (standalone/emergency package).
  :class:`orchestrator.hyperv.LocalTransport` reuses the same PowerShell
  helper with ``-LocalMode`` so all analysis logic (adaptive window, dumps,
  collectors) runs unmodified, locally; VM-lifecycle verbs become no-ops.
"""

from orchestrator.config import SandboxConfig
from orchestrator.hyperv import HyperVManager, LocalTransport


def make_backend(config: SandboxConfig) -> HyperVManager:
    """Return the execution backend for the configured sandbox.mode."""
    if config.is_local_mode:
        return LocalTransport(config)
    return HyperVManager(config)
