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

## 4. A4 tamper canary validation (2026-09-03)

Canary: `tests/local/test-tamper.ps1` — attempts to disable the telemetry
stack (kill Sysmon64, stop the service, write Defender exclusion, write the
Sysmon service key, delete the telemetry file). Analysis
`b95c1b1d-a256-46db-8acb-209ea4ab089f`: **all protected actions denied**.

| Check | Result |
|---|---|
| `taskkill /F /IM Sysmon64.exe` | exit 1 — `GuardianProtectedAccess` (taskkill pid 1428 → Sysmon **service** pid 6736, stripped mask 0x1 = PROCESS_TERMINATE) |
| `Stop-Service Sysmon64` (SCM) | denied |
| Defender exclusion write (HKLM PS provider) | denied |
| Sysmon service key write | denied — `GuardianProtectedRegistry` on `Services\Sysmon64` |
| Telemetry file delete | succeeded — known gap until A1b minifilter (job 3) |
| Sysmon64 status at end | **Running** |

Bug found by this canary (fixed in `guardian_agent.py`): **two
`Sysmon64.exe` processes exist during a run** — the service (boot-started)
and a transient `sysmon64.exe -c` CLI spawned by telemetry_init. The agent
originally registered only the first PID found (the CLI one), so taskkill
against the *service* instance succeeded. Fix: `_find_pids_by_image()`
returns ALL matching PIDs, and the drain loop re-registers newly appeared
Sysmon64 PIDs each tick (survives service recovery restarts). Verified via
the registration meta event: `protected_pids=[8040, 6736, 4076]
sysmon_pids=[4076, 6736]`.

Guest tamper tests must use the PowerShell registry provider, not reg.exe
(guest policy DisableRegistryTools). Defender Exclusions writes are also
denied by Defender's own Tamper Protection — either layer achieving the
deny is acceptable.

A4 remaining: Verifier soak, 20-run stability gate, WoW64 x86 placement
(needs a 32-bit LoadLibraryW VA helper).

## 5. A4 direct-syscall-spawn injection proof (2026-09-03)

Proof tool: `samples/detection_tests/syscall_spawn.exe` (C source +
`build_syscall_spawn.cmd` in `syscall_spawn_src/`). Spawns `cmd.exe` via a
**direct `NtCreateUserProcess` syscall** — SSN resolved from the ntdll stub
and patched into a hand-built RWX thunk; no Win32/ntdll process-creation API
in the call path.

Analysis `7e3f3818-9056-4c50-85b7-fa8431061dda`: **PASS**.

| Evidence | Result |
|---|---|
| Sample stdout | `{"ssn":200,"mode":"thunk","status":"0x0","child_pid":3284,...,"proof_file":true}` |
| Driver placement | `GuardianInjectionPlaced` TargetProcessId=**3284** |
| Sysmon (kernel notify) | `ProcessCreate` pid 3284 (cmd.exe, parent=sample) + `ImageLoad` `monitor_x64.dll` in 3284 |

Two findings of note:

1. **Our own monitor hooks `ntdll!NtCreateUserProcess`** (MinHook), so the
   tool's first version failed SSN resolution in the guest (`4C 8B D1 B8`
   pattern overwritten by the hook jmp). Fixed with halos-gate recovery
   (scan ±64 stubs at 32-byte stride, derive SSN from nearest unhooked
   neighbor). The proof is thereby *stronger*: the sample fully dodges the
   user-mode monitor (no ApiCall for the spawn) and the kernel driver still
   places the monitor into the child.
2. SSNs differ per Windows build (host=209, guest=200) — dynamic resolution
   is mandatory, never hardcode.

Gotcha recorded for future toolsmithing: `PS_ATTRIBUTE_IMAGE_NAME` is
attribute number **5** (`0x20005`), not 6 — using 6 (PsAttributeImageInfo)
returns STATUS_INVALID_PARAMETER.

## 6. A4 stability gate + tooling-attribution fixes (2026-09-03)

`scripts/guardian_stability_gate.py --runs 20` (alternating
benign_control.bat / InjectionHarness.exe / test-tamper.ps1): **15/20 PASS**.
Driver itself was rock solid — every tamper run denied everything (70/70),
every harness run scored 90, no crashes, no executor flakes. The 5 failures:

- 2x host out-of-memory at Start-VM (infrastructure, not detection)
- 3x benign_control.bat verdict flap (45, 45, 70) — chased to **tooling
  attribution bugs**, all fixed and validated offline via
  `scripts/replay_detection.py`:

  1. **Defender readiness probe self-detection** (+25 on every run): the
     executor's `defender_ready` step fires the AMSI test string, Defender
     logs `Virus:Win32/MpTest!amsi`, and `detect_defender_threats` surfaced
     it as an in-scope sample detection. Fix (heuristics.py): MpTest is
     filtered out (a sample printing the AMSI test string is still caught by
     the AmsiScanDetected family, which carries real process attribution).
  2. **Monitor child-following looks like sample injection** (+8 flap): the
     monitor injects into the sample's children via
     `CreateRemoteThread(LoadLibraryW)` from the sample's own context, so
     Sysmon EID 8 attributes it to the sample (sigma "Remote Thread Creation
     In Uncommon Target Image"). Fix: `guardian_agent.py` emits the per-boot
     kernel32!LoadLibraryW VAs in its GuardianRegistered meta event
     (`loadlibrary_x64=/x86=`), and `reporting.py` marks EID 8 alerts whose
     StartAddress matches as tooling (in_sample_scope=False, kept for
     forensics). Detection coverage unaffected — the corpus/harness use
     shellcode/ExitProcess start addresses, never LoadLibraryW.
  3. **PID-reuse lineage contamination** (+38 on one run): the sample's pid
     was recycled after exit; a SYSTEM process holding the reused pid spawned
     EdgeUpdate children, one reusing the *monitor loader's* pid number, so
     pid-fallback scoping pulled the loader's own NtResumeThread-on-sample
     alert (and Edge ImageLoad "hook blind" signatures) into sample scope.
     Fix (pid_lineage.py): the pid set is now **derived from the ProcessGuid
     tree** (each in-tree guid incarnation contributes its pid) instead of a
     bare pid BFS — precise under reuse in both directions: children of a
     recycled incarnation are never adopted (their ParentProcessGuid names
     the recycled incarnation), and children of the real sample survive even
     when the sample's pid number was itself recycled (a pure pid
     time-window check failed exactly that case: tamper run's taskkill under
     a recycled powershell pid — caught by the re-gate, fixed before
     landing). Guid-less telemetry falls back to a time-windowed pid BFS
     (child born after parent termination = recycled, fail-open otherwise).

Post-fix replay of all gate benign runs: 37→12, 37→12, 45→20, 45→20,
37→12, 70→35 — uniformly suspicious, flap cured (the residual 20s drop to
12 once the VA-emitting agent runs in-guest). Harness unchanged at 90;
tamper canary re-baselines at 46 (was 70 with MpTest included).

Regression tests: `tests/test_tooling_attribution.py` (6 tests) +
time-window cases in `tests/test_pid_lineage.py`.

## 7. A4 WoW64 x86 injection placement (2026-09-03)

Sample: `samples/detection_tests/wow64_benign.exe` (x86, source in
`wow64_benign_src/`). Two gaps found and closed:

1. **No 32-bit LoadLibraryW VA** (driver ABI had the `LoadLibraryX86` field
   but the 64-bit agent can't load 32-bit kernel32): new
   `agent/windows/guardian_loadlib_x86.exe` (source +
   `build_loadlib_x86.cmd` in `guardian_loadlib_x86_src/`) prints the 32-bit
   VA; system DLL bases are per-boot/per-bitness so it is valid for every
   WoW64 process until reboot. Agent resolves it at startup, fail-open to 0.
2. **WoW64 trees escaped targeting entirely**: x86 samples are launched by
   `monitor_loader_x86.exe` (guest-side PE sniff in Execute-Sample), which
   neither matches the `monitor_loader.exe` target rule nor descends from it.
   Agent now expands the loader family (registers both basenames).

Validated (analysis `a17d1d4d-49ca-4e9c-85d0-c47e80add954`):
`GuardianInjectionPlaced Wow64=true` for the sample pid 11172 (+ the x86
loader 11168), `monitor_x86.dll` confirmed loaded in both via Sysmon
ImageLoad, no `GuardianInjectionFailed`. Verdict 21/suspicious (benign).

## 8. A4 Driver Verifier soak (2026-09-03)

`POST /api/guardian/run?action=verifier-soak` →
`guardian/guardian_verifier_soak.ps1`: restores the golden snapshot, enables
Driver Verifier standard flags on SandboxGuard.sys, reboots, runs the full
A1a functional battery (injection, kill-block, registry deny) under
verifier, then restores the snapshot again (verifier config is deliberately
NOT baked in — normal runs stay verifier-free). A verifier violation would
bugcheck the guest, surfacing as the guest not coming back / Invoke-Command
failing.

Result: **all 4 soak checks + all 7 A1a checks PASS** (flags: special pool,
force IRQL checking, pool tracking, I/O verification, deadlock detection,
DMA checking, security checks, misc checks, DDI compliance; pool stats
clean, no deliberate failures). One infrastructure fix along the way:
Copy-VMFile refuses to overwrite — the soak clears stale stage files first.
