# Sandbox Injection / Evasion Coverage — Implementation Plan

**Date:** 2026-06-16  
**Goal:** Close the detection-surface gaps identified in `reports/detection_surface_report.md` and produce telemetry for every listed technique.

---

## Phase 0 — Foundations (1–2 days)

### 0.1 Reproducible test harness
- Create a single PowerShell script `scripts/run_injection_harness.ps1` that:
  - Restores the `SANDBOX_READY` snapshot.
  - Starts the VM and waits for the IP.
  - Re-builds `InjectionHarness.exe` from source.
  - Copies it into the guest and executes it.
  - Collects telemetry and prints EID counts.
- This removes manual `Copy-VMFile` / `Invoke-Command` steps and guarantees a clean VM for every test.

### 0.2 Telemetry comparison helper
- Add `scripts/compare_reports.py` that takes two report JSON files and prints:
  - New EIDs observed.
  - New event counts.
  - Missing expected events.
- This lets us validate each new technique quickly.

### 0.3 Baseline snapshot refresh
- After installing Sysmon 15.20 + the latest config, take a new `SANDBOX_READY` snapshot so every run starts from a known-good telemetry state.

---

## Phase 1 — EID 25 for Herpaderping / Ghosting / Doppelgänging (3–4 days)

### 1.1 Try a public EID 25 PoC first
- Download / build the canonical `herpaderping.exe` PoC (jxy-s / Johnny Shaw).
- Run it in the sandbox with the current config.
- Confirm it fires EID 25 and capture the exact event shape.
- **Acceptance:** at least one EID 25 with `Type: Image is replaced` from the PoC.

### 1.2 Fix our `NtCreateProcessEx` herpaderping path
Two hypotheses to test:
1. Sysmon needs an EID 1 `ProcessCreate` event to compare. Try calling `NtCreateUserProcess` instead of `NtCreateProcessEx` after the section overwrite.
2. The file must be overwritten **after** `CreateProcess` maps it but **before** `ResumeThread`, while the process is suspended.
   - This means using `CreateProcessW` on a decoy file with `CREATE_SUSPENDED`.
   - Then overwrite the decoy on disk.
   - Then resume the main thread.
   - This is the classic herpaderping flow; the earlier failure was a file-lock issue.
- **Acceptance:** our harness fires EID 25 for herpaderping.

### 1.3 Add process doppelgänging
- Use `NtCreateTransaction` + `CreateFileTransacted` to write payload into a transacted file.
- Create an image section from the transacted handle.
- Roll back the transaction.
- Create the process from the orphaned section.
- **Acceptance:** EID 25 fires with `Type: Image is replaced` or an equivalent tampering type.

### 1.4 Keep / improve ghosting
- The current ghosting test already deletes the file after section creation.
- If it still does not fire EID 25, move it to a "process creation primitives" demo rather than a detection target.

---

## Phase 2 — Additional Injection Techniques (4–5 days)

Add one test per technique to `InjectionHarness.exe`. Each must exit cleanly and produce some telemetry.

| # | Technique | Expected primary signal |
|---|-----------|-------------------------|
| 10 | AtomBombing (`GlobalAddAtom` + `NtQueueApcThread`) | EID 10 + EID 8 (if thread is created) |
| 11 | Module overloading / DLL hollowing | EID 7 (legitimate DLL loaded), then EID 25 if `.text` is replaced |
| 12 | `SetWindowsHookEx` global hook | EID 10 + EID 7 (hook DLL) |
| 13 | Thread pool injection (`TpAllocPool` worker factory) | EID 10 + EID 8 |
| 14 | `NtQueueApcThreadEx` user-mode APC | EID 10 |
| 15 | MapView injection (`NtMapViewOfSection` into remote process + `NtCreateThreadEx`) | EID 10 + EID 8 |

### 2.1 Cross-architecture tests
- Build a 32-bit version of `InjectedDll.dll` and add a WoW64 test.
- Test x64 → WoW64 and WoW64 → x64 injection paths.
- **Acceptance:** at least one new event per architecture path.

---

## Phase 3 — Evasion-of-Telemetry Techniques (3–4 days)

These widen EID 25 coverage by patching the *injecting* process itself.

| # | Technique | Expected signal |
|---|-----------|-----------------|
| 20 | ETW patch (`EtwEventWrite` / `NtTraceEvent` patch) | EID 25 on injector, `Type: Image is replaced` |
| 21 | AMSI patch (`AmsiScanBuffer` patch) | EID 25 on injector, possibly AMSI scan event |
| 22 | .NET ETW patching (`mscoreei.dll` / CLR ETW provider patch) | EID 25 on injector |

- Add `EtwPatching()`, `AmsiPatching()`, `ClrEtwPatching()` to the harness.
- Run them and verify EID 25 is emitted for the injector process.

---

## Phase 4 — Broader Sysmon Event Coverage (2 days)

### 4.1 Expand `agent/windows/sysmonconfig.xml`
Add rules for:
- EID 9 `RawAccessRead`
- EID 11 `FileCreate`
- EID 12/13/14 registry events
- EID 15 `FileCreateStreamHash`
- EID 17/18 named pipes
- EID 23 `FileDelete`
- EID 26 `FileDeleteDetected`

Use targeted include filters (e.g., `Image` under `C:\Sandbox`, `C:\Users`, `C:\Windows\Temp`) to avoid log floods.

### 4.2 Validate config schema
- Run `Sysmon64.exe -c agent/windows/sysmonconfig.xml` after every edit.
- Ensure the config reload step in `telemetry_collector.py` reports success.

---

## Phase 5 — Optional Telemetry Sources (3–4 days)

### 5.1 ETW Threat-Intelligence (ETW-TI)
- Implement `agent/windows/etw_ti_collector.py` using `pywin32` or `python-etw`.
- Subscribe to the `Microsoft-Windows-Threat-Intelligence` provider for:
  - `KERNEL_AUDIT_API_INLINEHOOK` (inline hooks)
  - `KERNEL_AUDIT_API_CALL` (direct syscalls)
  - `REMOTE_THREAD_CREATE` (additional remote-thread signal)
- Add `etw_ti` to `telemetry.sources` in `config/config.yaml`.
- Merge ETW-TI events into the same JSONL stream as Sysmon events.

### 5.2 AMSI
- Enable AMSI event collection via `Microsoft-Antimalware-Scan-Interface` ETW provider.
- Useful for catching script-based attacks later.

### 5.3 PowerShell script-block logging
- Enable PowerShell module / script-block logging in the guest via Group Policy registry keys.
- Collect event IDs 4103, 4104 from `Microsoft-Windows-PowerShell/Operational`.

---

## Phase 6 — Persistence & Post-Exploitation Behaviors (3 days)

Add a small "post-exploitation" test suite that runs after the injection tests:

| # | Behavior | Expected signal |
|---|----------|-----------------|
| 30 | Registry run-key write | Sysmon EID 13 |
| 31 | Scheduled task creation (`schtasks.exe` / COM) | EID 1 + EID 11 |
| 32 | Service creation (`sc.exe create`) | EID 1 + EID 13 |
| 33 | WMI event subscription (`wmic` / PowerShell) | EID 1 + WMI logs |
| 34 | File written to Startup folder | EID 11 |

These are not injection, but they exercise the full detection surface expected from a real sandbox sample.

---

## Phase 7 — Memory-Protection Telemetry (2–3 days)

### 7.1 ETW-TI `VIRTUAL_ALLOC` / `VIRTUAL_PROTECT`
- If available from the ETW-TI provider, capture `NtProtectVirtualMemory` / `NtAllocateVirtualMemory` calls.
- This shows the `PAGE_EXECUTE_READWRITE` transitions that precede shellcode injection.

### 7.2 Fallback: in-guest hook DLL
- If ETW-TI is insufficient, build a tiny C DLL that hooks `NtProtectVirtualMemory` via `minhook` or manual IAT hooking.
- Inject it into target processes? Better: load it into the harness itself and log `OldAccess -> NewAccess` transitions.
- Emit custom JSONL events for the orchestrator.

---

## Phase 8 — Reporting & Alerting Improvements (2 days)

### 8.1 Detection mapping
- Add a `mitre_mapping.json` file that maps each harness test name to MITRE technique IDs.
- Update `reporting.py` to tag alerts with MITRE IDs automatically.

### 8.2 Severity scoring
- Add a simple severity score per alert based on event type:
  - EID 25 → `critical`
  - EID 8, 10 with suspicious access → `high`
  - EID 7 from unusual paths → `medium`
  - EID 1, 11, 13 → `low`

### 8.3 Executive summary in report
- Extend the JSON report with a `findings` section:
  - `injection_techniques_detected`
  - `tampering_events`
  - `persistence_events`
  - `overall_risk_score`

---

## Phase 9 — Validation & Hardening (2 days)

### 9.1 Regression tests
- Run the harness against the clean snapshot 5 times.
- Confirm every expected EID appears in every run.
- Confirm no false-positive EID 25 from legitimate Windows startup noise.

### 9.2 Defender / AV exclusions
- Document all host and guest exclusions.
- Ensure the new tests do not get quarantined by Defender after config changes.

### 9.3 Documentation
- Update `README.md` with:
  - How to add a new injection test.
  - How to read the report.
  - How to update the Sysmon config.
- Keep `reports/detection_surface_report.md` in sync after each phase.

---

## Timeline Summary

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| 0 — Foundations | 1–2 days | Repro script, report diff tool, refreshed snapshot |
| 1 — Herpaderping / Ghosting / Doppelgänging | 3–4 days | EID 25 from tampering-at-creation techniques |
| 2 — More injection techniques | 4–5 days | AtomBombing, module overloading, hooks, thread pool, map-view, cross-arch |
| 3 — Evasion-of-telemetry | 3–4 days | ETW/AMSI/CLR patching tests producing EID 25 |
| 4 — Broader Sysmon config | 2 days | File, registry, pipe, delete events |
| 5 — ETW-TI / AMSI / PowerShell | 3–4 days | Additional telemetry sources merged into JSONL |
| 6 — Persistence behaviors | 3 days | Run keys, tasks, services, WMI, startup |
| 7 — Memory-protection telemetry | 2–3 days | `NtProtectVirtualMemory` visibility |
| 8 — Reporting improvements | 2 days | MITRE tags, severity, findings summary |
| 9 — Validation & docs | 2 days | Stable repeatable runs, updated docs |

**Total estimated effort:** ~25–33 days of focused work, depending on how many public PoCs can be reused.

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Sysmon does not fire EID 25 for some techniques even with correct code | Validate with public PoCs first; document as known gap |
| ETW-TI provider requires higher privileges or specific Windows build | Test on the VM first; fall back to in-guest hooks |
| New Sysmon rules flood logs | Use tight include filters (paths, image names) |
| Defender blocks new injection tests | Maintain exclusions; consider self-signed test payloads |
| Cross-architecture tests are fragile | Build dedicated 32-bit harness variant if needed |

---

## Recommended Order of Attack

1. **Phase 0 + Phase 1 first** — this gives the biggest win (EID 25 for tampering-at-creation).
2. **Phase 3 next** — ETW/AMSI patching is small code and reliably fires EID 25.
3. **Phase 2** — additional injection primitives.
4. **Phase 4 + Phase 6** — broaden event coverage and add persistence.
5. **Phase 5 + Phase 7** — deeper telemetry (ETW-TI, memory protections).
6. **Phase 8 + Phase 9** — polish reporting and harden.
