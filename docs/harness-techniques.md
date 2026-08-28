# InjectionHarness Techniques & Expected Telemetry

This table maps each test in `samples/InjectionHarness/InjectionHarness/Program.cs` to the Sysmon / ETW-Ti signals it is expected to produce.

| Test Method | MITRE ID | Description | Expected Telemetry |
|-------------|----------|-------------|-------------------|
| `TestRemoteThreadInjection` | T1055 | Opens a `cmd.exe` target and calls `CreateRemoteThread(ExitProcess)` | Sysmon EID 8 (`CreateRemoteThread`), EID 10 (`ProcessAccess`) |
| `TestApcInjection` | T1055.004 | Creates an alertable remote thread and queues `ExitProcess` via `QueueUserAPC` | Sysmon EID 8, EID 10; ETW-Ti `QUEUE_APC` |
| `TestThreadHijacking` | T1055.003 | Suspends target thread, sets RIP to `ExitProcess` shellcode, resumes | Sysmon EID 10; ETW-Ti `SET_CONTEXT_THREAD` |
| `TestProcessHollowing` | T1055.012 | Suspended `notepad.exe` → unmap image → allocate RWX shellcode → redirect RIP | Apitrace `ApitraceInjectionChain` ("Process hollowing into <pid>"). **No EID 25**: Sysmon's tamper check runs at process-create time and only sees FILE-based tampering (verified empirically across 3 runs) |
| `TestProcessHollowingPeReplacement` | T1055.012 | Suspended `notepad.exe` → unmap → write full `cmd.exe` PE → update PEB.ImageBase | Same: Apitrace `ApitraceInjectionChain` hollowing variant, EID 10, EID 7 |
| `TestEarlyBirdApcInjection` | T1055.004 | Suspended `notepad.exe` → queue APC → resume | Sysmon EID 1 (`ProcessCreate`), EID 8; ETW-Ti `QUEUE_APC` |
| `TestDllInjection` | T1055.001 | Writes DLL path to target and `CreateRemoteThread(LoadLibraryA)` | Sysmon EID 8, EID 7 (InjectedDll.dll), EID 10, EID 11 (file create) |
| `TestSectionMappingInjection` | T1055 | Pagefile-backed section mapped RW locally then RX remotely, remote thread | Sysmon EID 8, EID 10; ETW-Ti `MAP_VIEW`, `ALLOCVM` |
| `TestProcessHerpaderping` | T1055.013 | `NtCreateSection(decoy)` → `NtCreateProcessEx` → overwrite file → thread | Sysmon EID 25 (`Image is replaced`), possible EID 255 if image resolution races |
| `TestProcessHerpaderpingClassic` | T1055.013 | `CreateProcess(suspended)` → overwrite file → resume | Blocked on modern Windows (file locked) — no telemetry expected |
| `TestProcessGhosting` | T1055.013 | Write payload → mark delete-pending → `NtCreateSection(SEC_IMAGE)` → delete file → process/thread | Sysmon EID 25 (`Image is locked for access`), EID 255 (`IMAGE_LOAD: Failed to find process image name`) |

## Phase-2 additions (PLAN.md #10-15)

| Test Method | MITRE ID | Description | Expected Telemetry |
|-------------|----------|-------------|--------------------|
| `TestAtomBombing` | T1055 | `GlobalAddAtom` + `QueueUserAPC(GlobalGetAtomNameW, atom)` into alertable remote thread | Sysmon EID 10; apitrace `NtQueueApcThread` |
| `TestModuleOverloading` | T1055 | SEC_IMAGE map of legit `version.dll` into remote target + `.text` overwrite | Sysmon EID 7 (target), EID 10 |
| `TestSetWindowsHookExInjection` | T1055 | `WH_GETMESSAGE` hook with embedded HookDll.dll forces the DLL into notepad | Sysmon EID 7 (HookDll.dll in target) |
| `TestApcExInjection` | T1055.004 | `NtQueueApcThreadEx(ExitProcess)` into alertable remote thread | Sysmon EID 10; apitrace `NtQueueApcThreadEx` |
| `TestMapViewInjection` | T1055 | Section written via local view, mapped RX remotely, started via `NtCreateThreadEx` | Sysmon EID 10, EID 8; apitrace `NtMapViewOfSection`/`NtCreateThreadEx` |
| ~~#13 thread-pool injection~~ | T1055 | **Not implementable as a public-API test** — remote thread-pool insertion needs PoolParty-style undocumented `TP_WORK`/`TP_DIRECT` primitives (2023 research) | Harness logs an explicit `SKIPPED` line every run |

Phase-2 tests run individually wrapped (`RunSafely`) so one experimental
failure can't abort the rest of the harness (Main exits nonzero with a
`failures=N` count if any test failed). Assertions live in both mirrors:
`orchestrator/harness_validation.py` (alerts-based) and
`scripts/harness_assertions.py` (events + alerts) — keep them in sync.
Two spec kinds: Sysmon EID + pid-field (+ optional Type fragments), and
behavioral alert (`alert_event_type` + pid-templated fragment).

## Notes

- EID 25 for **ghosting** currently appears as `Image=<unknown process>` and `Type=Image is locked for access` because the on-disk file has been deleted before Sysmon resolves the path.
- EID 25 for **herpaderping** usually resolves to the decoy path (`C:\Sandbox\herpaderping.exe`) with `Type=Image is replaced`, but occasionally appears as `<unknown process>` depending on callback timing.
- The two recurring **Sysmon EID 255** events are caused by ghosting; see `docs/sysmon-255-investigation.md`.
