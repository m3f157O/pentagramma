# SandboxGuard — guardian driver

Status: **WS-A2 VALIDATED** (2026-09-02) — driver baked into the golden
image (testsigning + auto-start via `action=provision`), guardian agent
wired into analysis runs, canaries green:
benign_control.bat suspicious/37 (baseline 12–37, **0 guardian alerts**),
InjectionHarness malicious/90 + 9/9 techniques (baseline exact).
A1a verified (§2). Deferred to A1b: minifilter file protection (job 3),
hook-integrity verifier (job 4). Plan of record:
`C:\Users\giammy\.kimi\plans\cyclops-beta-ray-bill-iron-fist.md`.

Scope (per the 2026-08-19 design decision): one driver, three roles —
**protect** the telemetry stack (Ob/Cm/minifilter), **verify** it
(hook-integrity, module-remap), and **place** it (process-notify callback +
user-mode APC → LoadLibraryW, for both sandbox lineage mode and the
standalone agent's `--process-name` mode).

Scope (per the 2026-08-19 design decision): one driver, three roles —
**protect** the telemetry stack (Ob/Cm/minifilter), **verify** it
(hook-integrity, module-remap), and **place** it (process-notify callback +
user-mode APC → LoadLibraryW, for both sandbox lineage mode and the
standalone agent's `--process-name` mode).

## 1. A0 spike

### Artifacts

| File | Role |
|---|---|
| `guardian\src\SandboxGuard.c` | A0 skeleton: device `\\.\SandboxGuard`, IOCTL PING/DRAIN, `PsSetCreateProcessNotifyRoutineEx` logging create/exit (image, pid, ppid, WoW64) into a 512-entry ring |
| `guardian\src\guardian_ioctl.h` | shared IOCTL ABI (ping signature `SBGUARD1`, event record layout) |
| `guardian\SandboxGuard.vcxproj` + `guardian\build_guardian.ps1` | WDM/x64 build via WDK CLI targets (no VS driver extension needed; Spectre off, auto-sign off) |
| `guardian\make_test_cert.ps1` | self-signed code-signing cert (LocalMachine\My, falls back to CurrentUser\My) + `signtool sign /fd sha256`; exports `out\SandboxGuardTest.cer` for guest import |
| `guardian\probe\guardian_probe.py` | guest-side ctypes probe: PING handshake + ring drain → JSONL |
| `guardian\guardian_spike.ps1` | host-side staged driver for the spike (below) |

### Runbook (elevated host PowerShell)

```
powershell -ExecutionPolicy Bypass -File guardian\build_guardian.ps1
powershell -ExecutionPolicy Bypass -File guardian\make_test_cert.ps1
powershell -ExecutionPolicy Bypass -File guardian\guardian_spike.ps1 -Stage inspect   # CI policy, read-only
powershell -ExecutionPolicy Bypass -File guardian\guardian_spike.ps1 -Stage enable    # testsigning + cert import + reboot
powershell -ExecutionPolicy Bypass -File guardian\guardian_spike.ps1 -Stage load      # sc create/start, PING, notepad test -> GO/NO-GO
powershell -ExecutionPolicy Bypass -File guardian\guardian_spike.ps1 -Stage cleanup   # then revert VM via orchestrator
```

### Results

Spike run 2026-09-01 against "bande nere" (inspect → enable → load → diag):

- CI policy enforcement status: **0 (off)**; Usermode CI **0 (off)**; VBS **0 (off)**. Only `driversipolicy.p7b` deployed, not enforced.
- testsigning accepted: **yes** (`bcdedit` shows `testsigning Yes` post-reboot; Secure Boot off, so no posture conflict).
- driver load (`sc start`): **SUCCESS** — service created, state RUNNING. SCM event 7045 logged; CodeIntegrity log shows only benign ID 3085 (WHQL enforcement disabled for boot session).
- PING handshake: **ok** — `SBGUARD1` signature returned, probe confirmed device is ours.
- process-create capture (notepad.exe): **yes** — seq 12 `{"kind": "create", "image": "\\??\\C:\\Windows\\system32\\notepad.exe", "pid": 968, "ppid": 6480}` drained via IOCTL; create/exit events for powershell/conhost/python also captured with correct pid/ppid/wow64.
- **Decision: GO** — the callback fires for every creation regardless of launcher, the IOCTL ring channel works, and no CI policy changes beyond testsigning were needed. All A1 assumptions (documented callbacks, ring-buffer event channel) are validated.

Notes from the run: the `enable` stage's final read-back `bcdedit` hit a
transient PSRemoting session break right after the guest reboot (state was
already applied; `diag` confirmed testsigning stuck). Harmless.

## 2. A1a increment (WDM: Ob + Cm + remap + injection placement)

A1 is split: **A1a** keeps the WDM skeleton and adds jobs 1, 2, 5, 6; **A1b**
defers job 3 (minifilter file protection — changes driver model + install
path) and job 4 (hook-integrity verifier thread).

### What the driver does now

| Job | Mechanism | Notes |
|---|---|---|
| 1 protect processes | `ObRegisterCallbacks` (process+thread, altitude `300000`) | strips `TERMINATE\|VM_WRITE\|VM_OPERATION\|CREATE_THREAD\|SET_INFORMATION` (process) and `TERMINATE\|SET_CONTEXT\|SUSPEND_RESUME` (thread) when target ∈ protected set; System + protected callers exempt → `access_denied` event |
| 2 protect registry | `CmRegisterCallbackEx` (altitude `300001`) | denies SetValue/DeleteKey/DeleteValue/Rename on paths containing `Services\Sysmon*`, `Services\SandboxGuard`, `AMSI\Providers`, `Windows Defender\Exclusions`, `Image File Execution Options\` → `reg_denied` event |
| 5 module-remap flag | `PsSetLoadImageNotifyRoutine` | second mapping of ntdll/kernel32/amsi into the same PID → `module_remap` event |
| 6 injection placement | `PsSetCreateProcessNotifyRoutineEx` (targeting) + `PsSetCreateThreadNotifyRoutine` (queue) → special kernel APC → in-target alloc/write → user APC `LoadLibraryW(dll)` | pre-entry-point placement; denylist (system/PPL) + `PsIsProtectedProcess` gate; failures → `inject_failed`, never fatal |

**Targeting ruleset** (`IOCTL_GUARDIAN_SET_TARGETING`): mode `sandbox` =
root PID + all descendants via driver-side lineage table (256 entries);
mode `standalone` = up to 8 image basenames + optional follow-children.
**Injection config** (`IOCTL_GUARDIAN_SET_INJECTION`): x86/x64 DLL paths +
`kernel32!LoadLibraryW` VAs supplied by the registering process (system DLL
bases are per-boot/per-bitness, so the agent's own address is valid for
same-bitness targets). **Inert by default**: all callbacks no-op until
registered; `IOCTL_GUARDIAN_CLEAR_ALL` resets.

### Header-machinery note

The 26100 WDK removed the APC routine typedefs, `KAPC_ENVIRONMENT`,
`KeInitializeApc`/`KeInsertQueueApc`, and `PsIsProtectedProcess` from its
headers (still exported by ntoskrnl, still MSDN-documented) — declared by
hand at the top of `SandboxGuard.c`. `KAPC` itself remains in `wdm.h`.

### Event ABI

Ring events are now a unified `GUARDIAN_EVENT` (360 bytes, `guardian_ioctl.h`)
with `Type` 1–7 (`proc_create`, `proc_exit`, `access_denied`, `reg_denied`,
`module_remap`, `inject_queued`, `inject_failed`) — the A0 `GUARDIAN_PROC_EVENT`
is gone; `guardian_probe.py` decodes the new record and can register
protection/targeting/injection from the CLI.

### Runbook (elevated host PowerShell)

```
powershell -ExecutionPolicy Bypass -File guardian\build_guardian.ps1
powershell -ExecutionPolicy Bypass -File guardian\make_test_cert.ps1 -SignOnly
powershell -ExecutionPolicy Bypass -File guardian\guardian_a1_test.ps1 -Stage load
powershell -ExecutionPolicy Bypass -File guardian\guardian_a1_test.ps1 -Stage test
powershell -ExecutionPolicy Bypass -File guardian\guardian_a1_test.ps1 -Stage cleanup   # then revert VM
```

Or via the orchestrator (must run **elevated** — Hyper-V PSDirect), which
shares the single-flight VM slot with analysis jobs:

```
curl -X POST "http://127.0.0.1:18000/api/guardian/run?action=build"   # compile + sign
curl -X POST "http://127.0.0.1:18000/api/guardian/run?action=load"    # returns {"job_id": ...}
curl "http://127.0.0.1:18000/api/jobs/<job_id>"                        # poll; 'output' has the script tail
curl -X POST "http://127.0.0.1:18000/api/guardian/run?action=test"    # report_status: all_pass | checks_failed
curl -X POST "http://127.0.0.1:18000/api/guardian/run?action=cleanup"
```

### Results

Test run 2026-09-01 via `POST /api/guardian/run?action=test` — **all 7 checks PASS**:

- A1 injection: benign `wkscli.dll` in notepad module list: **PASS** (pre-entry placement confirmed by module load)
- A2 `inject_queued` event: **PASS**
- B1 protected process survives `taskkill /F`: **PASS** (PROCESS_TERMINATE stripped, value=1 in event)
- B2 `access_denied` event: **PASS** (taskkill pid → protected notepad pid)
- C0 control write (`HKLM\SOFTWARE\SGControl`) succeeds: **PASS** (proves denial below is ours, not ACLs)
- C1 Sysmon service key write denied: **PASS** (`HKLM\SYSTEM\...\Services\Sysmon64` SetValue blocked)
- C2 `reg_denied` event: **PASS** (key path captured in event text)
- Informational: Defender\Exclusions writes are denied by **Defender Tamper Protection**, not our callback (different error message; altitude ordering means we may not see them — fine, goal achieved either way).
- **Decision: A1a DONE.** Note: job 5 (module-remap) has no dedicated check yet — exercised implicitly, no FP storms observed over ~180 events.

Bugs found and fixed during the A1a bring-up (kept for posterity):

1. **0x7E BSOD in DriverEntry** — `CmRegisterCallbackEx` parameter order is
   `(Function, Altitude, Driver, Context, Cookie, Reserved)`; Context and
   Cookie were swapped, so the kernel wrote the callback cookie through NULL.
   Compiles cleanly (PVOID), crashes at load. Diagnosed from minidump
   (`guardian\dumps\090126-9765-01.dmp`): AV in `nt!CmpRegisterCallbackInternal`
   writing the cookie out-param.
2. **probe: 64-bit pointer truncation** — ctypes defaults `restype=c_int`;
   `GetProcAddress("LoadLibraryW")` also auto-converted the name to a *wide*
   string (→ NULL). Fixed with explicit restype/argtypes + `b"LoadLibraryW"`.
3. **probe: drain paging** — one DRAIN IOCTL returns ≤64 events; the probe now
   pages until caught up (reg_denied events past seq 64 were silently dropped).
4. **guest DisableRegistryTools policy** blocks `reg.exe` — tests must use the
   PowerShell registry provider (bypasses the policy, hits the kernel).
5. **Copy-VMFile is host→guest only** on this build — guest→host pulls use
   `Copy-Item -FromSession` over PS Direct (used by the diag stage).

## 3. A2 integration (analysis-run wiring)

| Piece | File | What it does |
|---|---|---|
| Guest agent | `agent\windows\guardian_agent.py` | PING handshake (fail-open: emits `GuardianUnavailable` and exits 0 when the driver is absent) → CLEAR_ALL → register protections (self + Sysmon64) → register injection (monitor DLL paths + LoadLibraryW VA, x64 only for now) → register targeting (standalone image-name rule for the launched executable + follow-children) → drain ring ~1/s into `guardian.jsonl` (event types 3–7 only; proc create/exit stay Sysmon's) → CLEAR_ALL on stop |
| VM plumbing | `scripts\hyperv-vm.ps1` `Guardian-Start`/`Guardian-Stop` | Detached start (returns AgentPid) / stop-file + kill fallback, mirroring Apitrace-Start/Stop |
| Orchestrator | `orchestrator\hyperv.py`, `executor.py` | `guardian_start/stop`; run lifecycle: start before `execute_sample`, stop before `telemetry_collect`; sources string gains `guardian` only when actually started |
| Collector | `agent\windows\telemetry_collector.py` | `guardian` source: pass-through read of guardian.jsonl |
| Detection | `orchestrator\behavioral_signatures.py`, `detectors.py` | `_detect_guardian_events` 1:1 pass-through → alert types `GuardianProtectedAccess` (high), `GuardianProtectedRegistry` (high), `GuardianModuleRemap` (high), `GuardianInjectionFailed` (medium), all T1562.001; computed before the apitrace early-return so guardian alerts fire on untraced runs too |
| Config | `config.yaml` `guardian.enabled: true` | off = run proceeds exactly as today |
| Provisioning | `guardian\install_guardian.ps1` via `POST /api/guardian/run?action=provision` | restore → testsigning + cert → driver into `System32\drivers` + auto-start service → reboot → verify (service RUNNING + probe PING) → recapture golden snapshot **only on success** |

Design notes:

- **Targeting = image-name rule, not root-PID**: the root PID doesn't exist
  at registration time (pre-launch), and image-name + follow-children is
  race-free. For script samples the *launcher* image is targeted (e.g.
  `powershell.exe`) — every such process during the run gets the monitor;
  acceptable in a fresh VM.
- **Double placement is harmless**: driver APC and monitor_loader both call
  `LoadLibraryW(monitor)` — same path, refcounted, DllMain runs once. The
  loader stays the fallback when the driver is absent.
- **WoW64 gap**: x86 `LoadLibraryW` VA can't be read from an x64 agent;
  WoW64 targets produce `GuardianInjectionFailed` events (visible, never
  silent) until a 32-bit helper is added.

### A2 validation results (2026-09-02)

| Check | Result |
|---|---|
| `action=provision` | Driver baked into golden image: testsigning on, cert in Root+TrustedPublisher, `System32\drivers\SandboxGuard.sys` auto-start service, verified by boot-time load + PING, snapshot recaptured |
| benign_control.bat | suspicious/37 (baseline 12–37) — **0 guardian alerts**, 4 informational `GuardianInjectionPlaced` (cmd.exe tree pre-entry placement) |
| InjectionHarness | malicious/90 (**exact baseline**), 9/9 technique assertions PASS with guardian active |
| Env-noise scoping | Edge updater's routine IFEO self-write was denied (job working) → `GuardianProtectedRegistry` alert correctly scoped `in_sample_scope: false`, verdict unaffected |

Bugs found by the first canary run (fixed):

1. **Cm protection armed from boot** blocked our own `telemetry_init` Sysmon
   config write (`Services\SysmonDrv\Parameters`) → 20 false
   GuardianProtectedRegistry alerts, benign verdict flipped to malicious/45.
   Fix: registry protection is now INERT until the guardian agent registers
   its first protected PID (which happens right before the sample launches,
   after telemetry init); CLEAR_ALL disarms.
2. **Provision reboot race**: `Restart-Computer` returns before the guest
   goes down; readiness-wait caught the pre-reboot OS and verify read a
   stale "never started" service state. Fix: wait for a NEWER guest
   LastBootUpTime (also fixed in `guardian_spike.ps1`).
3. **Driver file locked by previous baked instance**: stop/delete the
   service BEFORE overwriting `System32\drivers\SandboxGuard.sys`.
4. **Checkpoint-VM visibility race**: snapshot not queryable immediately
   after Checkpoint-VM returns → `Recapture-SandboxSnapshot` now polls up
   to 120 s and surfaces real Checkpoint-VM errors.
5. **Provision fast-path** now requires the guest driver hash to match the
   host build (otherwise an updated build would never deploy).

Known noise: updaters (Edge/Chrome) routinely write IFEO keys for their own
images; job 2 denies them during runs and the events are env-noise-scoped.
If this ever proves too chatty, narrow the IFEO fragment to our own binary
names instead of `\Image File Execution Options\` globally.
