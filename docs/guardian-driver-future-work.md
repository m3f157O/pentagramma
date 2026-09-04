# SandboxGuard — future work

Status of record: `docs/guardian-driver.md` (A0/A1a/A2/A4 all validated,
driver provisioned into the golden image). This file tracks what is
deliberately NOT done yet, why, and what it would take.

## Planned (deferred from A1 to A1b)

### 1. Minifilter file protection (job 3) — the one proven gap

- **Evidence:** the A4 tamper canary (`tests/local/test-tamper.ps1`)
  successfully **deleted the telemetry file** — every other protected action
  (kill Sysmon64, stop service, Defender exclusion, Sysmon key write) was
  denied; this one wasn't. See guardian-driver.md §4.
- **Scope:** protect `telemetry.jsonl`, `guardian.jsonl`, `apitrace.jsonl`,
  `C:\SandboxAgent\dumps\`, and the driver/agent binaries themselves against
  delete/rename/overwrite while a run is active.
- **Cost:** driver-model change — `FltRegisterFilter`, minifilter altitude
  (needs a real allocated altitude, not a self-chosen one, if this ever
  leaves the lab), `.inf` install path, new provisioning flow. This is why
  it was split out of A1a (WDM-only).
- **Interim mitigation:** none in-driver; the tamper canary flags it.

### 2. Hook-integrity verifier (job 4)

- **Gap:** a sample can patch over the monitor DLL's MinHook hooks in its own
  process (or a child's) to blind the API trace. Today this is only
  *observable* (memory events on the hook region), never *actively verified*.
- **Shape:** periodic verification that each hooked stub still begins with
  the monitor's trampoline (or at least is not restored to the original
  bytes). Could live in the driver (read target VA via MmCopyVirtualMemory)
  or in the guardian agent (user-mode ReadProcessMemory) — agent-side is
  cheaper and needs no driver change; driver-side is tamper-harder.
  No design yet; decide placement when picked up.

## Small / nice-to-have

- **Dedicated module-remap test** (job 5): currently only exercised
  implicitly (no FP storms over ~180 events). Add a canary that remaps
  ntdll (e.g. via a second `LoadLibrary` on a copied DLL name / manual map)
  and asserts a `GuardianModuleRemap` alert.
- **Unload protection:** `sc stop SandboxGuard` / `FltUnload`-equivalent is
  not explicitly blocked today (service *key writes* are denied via Cm, but
  a stop control is a different path). Add a tamper-canary step and, if it
  succeeds, deny unload while a run is active (or fail-closed `DriverUnload`).

## Optional hardening (not missing functionality)

- **Detectability / camouflage:** `\\.\SandboxGuard`, the service name, and
  altitudes `300000`/`300001` are enumerable sandbox fingerprints. For a
  private analysis VM this is low priority — evasion attempts are signal,
  not noise — but renaming + randomized device/service names is possible if
  the VM is ever used against samples that gate on sandbox artifacts.
- **Production signing:** testsigning is baked into the golden image and is
  fine for a private VM. Only relevant if the driver ever ships outside the
  sandbox (attestation/EV signing, real minifilter altitude, HLK).

## Explicitly not planned

- No ETW/telemetry role for the driver (Sysmon + agent cover it).
- No network filtering (pktmon covers capture; blocking is out of scope).
- No self-defense against a fully kernel-competent sample (out of threat
  model: guest has no vulnerable-driver loader baked in, and a sample that
  goes kernel has already lost).
