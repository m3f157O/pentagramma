"""Enable the Windows Security-log audit subcategories that
sigma_rules/builtin/security/'s vendored ruleset (140 rules, 43 distinct
EventIDs) actually needs. Unlike PowerShell script-block logging or
Sysmon, Security-log auditing is a mix: some subcategories are already on
by default on Windows 10/11 (Logon, User/Security Group Account
Management, Audit Policy Change -- confirmed via a live-VM
`auditpol /get /category:*` check), others are off (Security System
Extension -- needed for EID 4697 "service installed", the single most-
referenced EID in the vendored set at 21 rules; the Object Access cluster;
Privilege Use; Removable Storage).

Deliberately NOT enabling Account Logon / DS Access subcategories (Kerberos
ticket operations, Directory Service Access/Changes) -- those EIDs
(4768/4769/4776/4794/5136 etc.) are Active-Directory/domain-controller
concepts that cannot fire on this single-workstation, non-domain-joined
VM regardless of audit policy, so there's nothing to gain by turning them
on (same reasoning already applied to excluding the AD-specific builtin/
Sigma subdirectories at vendoring time).

Applied fresh at every telemetry_init() call (auditpol changes take effect
immediately, no reboot) rather than baked into the golden snapshot --
same precedent as PowerShellLoggingManager.ensure_enabled().
"""

import sys
from typing import List

import proc_util

# (subcategory name as auditpol expects it, feeds these EIDs from the
# vendored ruleset)
SUBCATEGORIES = [
    "Security System Extension",     # 4697 (service installed -- 21 rules, the single most-referenced EID)
    "File System",                   # object-access cluster: 4656/4663
    "Registry",                      # 4657 (registry value modified)
    "Handle Manipulation",           # 4656/4661
    "File Share",                    # 5140
    "Detailed File Share",           # 5145
    "Other Object Access Events",    # 4662/5156 and related
    "Sensitive Privilege Use",       # 4673/4674
    "Non Sensitive Privilege Use",   # 4673/4674
    "Removable Storage",             # 6416 (new external device recognized)
    "Other Logon/Logoff Events",     # 4649 (replay attack detected)
]


def _run_auditpol(args: List[str]) -> str:
    proc = proc_util.run_text(["auditpol"] + args, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"auditpol {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


class SecurityAuditManager:
    def _is_subcategory_enabled(self, subcategory: str) -> bool:
        """Parses auditpol's plain-text table output (no JSON interface
        exists) -- same "parse a Windows CLI tool's text output" pattern
        already used for wevtutil elsewhere in this agent.
        """
        try:
            output = _run_auditpol(["/get", f"/subcategory:{subcategory}"])
        except RuntimeError:
            return False
        for line in output.splitlines():
            if subcategory.lower() in line.lower():
                return "no auditing" not in line.lower()
        return False

    def is_enabled(self) -> bool:
        """True only if every needed subcategory is already auditing."""
        return all(self._is_subcategory_enabled(s) for s in SUBCATEGORIES)

    def enable(self) -> None:
        for subcategory in SUBCATEGORIES:
            print(f"[security_audit] enabling subcategory: {subcategory}")
            try:
                _run_auditpol(["/set", f"/subcategory:{subcategory}", "/success:enable", "/failure:enable"])
            except RuntimeError as exc:
                print(f"[security_audit] warning: could not enable '{subcategory}': {exc}")

    def ensure_enabled(self) -> None:
        missing = [s for s in SUBCATEGORIES if not self._is_subcategory_enabled(s)]
        if not missing:
            print("[security_audit] all required subcategories already enabled")
            return
        print(f"[security_audit] enabling {len(missing)} missing subcategories")
        for subcategory in missing:
            try:
                _run_auditpol(["/set", f"/subcategory:{subcategory}", "/success:enable", "/failure:enable"])
            except RuntimeError as exc:
                print(f"[security_audit] warning: could not enable '{subcategory}': {exc}")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: security_audit_manager.py <enable|status|ensure>")
        return 1

    action = sys.argv[1].lower()
    mgr = SecurityAuditManager()

    if action == "enable":
        mgr.enable()
    elif action == "status":
        print("enabled" if mgr.is_enabled() else "not enabled")
    elif action == "ensure":
        mgr.ensure_enabled()
    else:
        print(f"Unknown action: {action}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
