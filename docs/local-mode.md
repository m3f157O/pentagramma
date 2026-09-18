# Local mode — standalone detonation on the orchestrator's own machine

**For expert operators, inside their own disposable VM.** Local mode turns the
machine the orchestrator runs on into the analysis environment: same pipeline,
same report format, no Hyper-V dependency. Intended for emergency evaluation
and portable analysis kits, not for replacing the isolated VM workflow.

## What changes vs hyperv mode

| Area | hyperv mode | local mode |
|---|---|---|
| Sample execution | VM via PowerShell Direct | local processes (same `hyperv-vm.ps1` scriptblocks, invoked in-process via the `-LocalMode` seam) |
| Isolation | VM + snapshot revert per run | **operator-owned** (run inside your own throwaway VM) |
| Rollback | `Restore-VMSnapshot` per run | `clean_local_state()` per run (deletes prior run's artifacts under `C:\Sandbox`, `C:\SandboxAgent`, dumps; clears the Sysmon archive) |
| Screenshots | Hyper-V WMI thumbnails | **disabled** (no equivalent) |
| Interactive console | browser console + input | **disabled** (`/api/console/*` → 409; `interactive=true` submissions fall back to the standard launch path) |
| Guardian driver | in golden image | **optional**: installed by the installer when Secure Boot is off; skipped with reason `secure_boot` otherwise. Detection works without it (fail-open by design — see below) |
| Harness/guardian/provision API routes | available | 409 (`requires hyperv mode`) |
| Report fields | — | `environment.mode: "local"`, `environment.elevated: true` |

## Install

```powershell
# from the repo root (or an extracted package built by scripts\package_local.ps1)
powershell -ExecutionPolicy Bypass -File scripts\install_local.ps1
```

Flags: `-KeepDefender` (don't disable realtime monitoring — samples may be
killed mid-run), `-SkipGuardian`, `-NoAutostart`.

The installer: deploys `agent\windows` → `C:\SandboxAgent`, creates
`C:\Sandbox`, installs Python deps, disables Defender realtime, handles the
Secure Boot/Guardian decision, writes `sandbox.mode: local` into
`config\config.yaml` (backup at `config.yaml.bak`), optionally registers an
autostart task. Sysmon needs no explicit step — telemetry init installs and
reconfigures it per run.

Then start the orchestrator elevated as usual (`start.ps1`). The dashboard's
**Analysis Environment** card shows `mode: local`, the local system's
hostname/OS/build, and an instrumentation checklist (Sysmon service, agent
dir, monitor DLLs, Guardian driver, Secure Boot state).

**Running samples:** there is no separate "local sandbox" launcher in the GUI
— when `sandbox.mode: local` is active, the regular **Analyze** form (or
`POST /api/analyze`) detonates on the local machine. Mode is a process-level
config switch, not a per-run choice.

## Guardian without the driver — what you lose

The driver was always a fail-open plugin (the whole pipeline predates it):

- **place** → falls back to user-mode `monitor_loader.exe`. The known gap:
  children spawned via raw `NtCreateUserProcess` past user-mode hooks won't
  get kernel-placed hooks.
- **protect** → telemetry processes/registry are no longer kernel-protected;
  successful unhooking is still *detected* by the Sysmon↔apitrace blindspot
  correlator, just not prevented.
- **verify** → hook-integrity/module-remap driver events absent.

Secure Boot ON ⇒ test-signed driver cannot load ⇒ the installer disables
`guardian.enabled` and the dashboard check shows `off`. This is a supported,
explicitly-visible degraded mode — not a silent failure.

## Operator contract (read this)

1. **There is no rollback.** Run local mode inside your own disposable VM and
   revert that VM between sessions. Per-run cleanup deletes only the sandbox's
   own artifacts; a destructive sample can still damage the OS.
2. **The malware runs elevated** (the orchestrator runs elevated; parity with
   the guest's admin user). The report stamps `environment.elevated: true`.
3. **The orchestrator shares the box with the sample.** Orchestrator activity
   appears in telemetry (lineage scoping keeps it out of the sample's alert
   scope), and a destructive sample can kill the orchestrator mid-run — the
   report is written at the end, so such a run loses its report.
4. Reports from local mode are **not comparable** to VM-mode corpus baselines
   (`environment.mode` differs; noise profile differs).

## Switching modes

From the dashboard's **Analysis Environment** card: the *Switch to
local/Hyper-V* button writes `sandbox.mode` via `POST /api/config/mode`
(with a one-time `config.yaml.bak` backup). New analyses pick the change up
immediately (`get_config()` re-reads the file per call); an orchestrator
restart is still recommended so cached subsystems reinitialize. The topbar
badge always shows the active mode (`hyperv — isolated VM` green /
`LOCAL — malware runs on THIS machine` red). Manual path:
`config\config.yaml` → `sandbox.mode: hyperv` (or restore `config.yaml.bak`)
+ restart. The installer is idempotent; re-running it refreshes the agent.
