# Sandbox behavioral monitor (Track 3)

A purpose-built, compiled API-tracing monitor (CAPE/Cuckoo `capemon`-style) for
argument-level behavioral tracing of samples and their children. Built fresh on
**MinHook** (BSD 2-Clause, vendored under `vendor/minhook/`) for the inline-hook
engine, so the result stays license-clean (CAPE's capemon is GPLv3 and is used
only as a design reference for the hookset, never ported).

## Why compiled, not Frida

This sandbox's golden image enforces a WDAC / Code-Integrity policy that blocks
unsigned/JIT code but trusts on-disk compiled binaries. A compiled monitor DLL
fits that model; an unsigned Frida agent does not. The one open question the WDAC
policy raises is whether it will let our DLL *load* -- see the feasibility gate.

## Components

| Source | Artifact | Role |
|---|---|---|
| `monitor/monitor.cpp` | `monitor_x64.dll` | Injected into the sample; installs inline hooks, streams JSON API events over a named pipe. |
| `loader/monitor_loader.cpp` | `monitor_loader.exe` | Launches the sample **suspended**, injects the DLL, waits for a "hooks live" handshake, then resumes. Propagates exit code. |
| `../apitrace_collector.py` | (script) | Named-pipe **server**: accepts one connection per traced process, stamps + writes events to `apitrace.jsonl`. Pure-stdlib ctypes (no guest wheel). |

Binaries are built on the host and **shipped prebuilt in `agent/windows/`** (like
`Sysmon64.exe`). Build + stage them with `scripts/build_monitor.ps1`.

## IPC contract

Newline-delimited JSON, monitor -> collector, over `\\.\pipe\sandbox_apitrace`:

```json
{"api":"NtCreateFile","category":"file","pid":29572,"tid":29484,"arg0":"\\??\\C:\\Windows\\win.ini"}
```

The collector adds `ts` (receive time, for the telemetry merge-sort) and
`source":"apitrace"`. A `__monitor_attached__` meta event is sent on connect so
an attach is observable even if the sample calls no hooked API.

## Two correctness details

- **Ordering handshake.** Hooks must be live before the sample's first
  instruction. The loader creates a manual-reset event `Local\sandbox_monitor_ready_<pid>`
  before injecting; the monitor's init thread signals it after `MH_EnableHook`;
  the loader waits on it before `ResumeThread`. (A naive inject-then-resume races
  and misses the sample's early calls.)
- **Re-entrancy guard.** A `thread_local` flag makes a hook handler call the
  original directly while it is emitting, so logging can't recurse into a hooked
  API.

## Hookset

**Current (Track 3.1 shipped):**
- File: `kernel32!CreateFileW`, `ntdll!NtCreateFile`
- Process: `kernel32!CreateProcessW`
- Memory: `ntdll!NtAllocateVirtualMemory`, `ntdll!NtProtectVirtualMemory`,
  `ntdll!NtWriteVirtualMemory`, `ntdll!NtMapViewOfSection`
- Thread/injection: `ntdll!NtCreateThreadEx`, `ntdll!NtResumeThread`
- Registry: `ntdll!NtSetValueKey`

The Nt-layer hooks matter: file activity that bypasses the Win32 wrappers
(e.g. `cmd`'s `copy`) is caught only at `NtCreateFile` -- proven in bring-up,
where `CreateFileW` fired zero times but `NtCreateFile` captured the real
source/dest paths.

**Shipped (Track 3.2):**
- **Child-following** via `ntdll!NtCreateUserProcess`: every non-WoW64 child
  gets this same DLL injected **fire-and-forget** (no ready handshake — see
  below). Shared injector lives in `common/inject.cpp`, used by both the
  loader (root, strict handshake) and the monitor (children).
- **Volume control:** per-API caps, a cross-thread time-windowed dedup ring,
  per-API cap-reached meta events, and `SANDBOX_APITRACE_GLOBAL_CAP` /
  `SANDBOX_MONITOR_NO_CHILD_FOLLOW` env overrides.
- **Startup-resume suppression:** kernel32's auto-resume of a just-created
  child's initial thread is NOT an injection resume — `NtResumeThread` events
  are suppressed for fresh child handles so `ApitraceRemoteThread` doesn't
  false-positive on every benign child spawn.

**Why fire-and-forget for children:** holding a child frozen through a full
load+hook+handshake cycle while the parent is mid-`CreateProcessW` inside
kernel32 corrupts the child's own startup (observed: nested `cmd` failing
with `ERROR_ACCESS_DENIED`). Fire-and-forget returns in ~1ms; the child loads
the monitor concurrently with its own init. Tradeoffs (accepted, documented):
children run ~10–50ms unhooked (short-lived children may attach without
emitting events), the remote DLL-path string is intentionally leaked (~520
bytes/child), and a child whose monitor fails to load is only visible via a
missing `__monitor_attached__` for its pid.

**Planned (Track 3.2+):** network, loader (`Ldr*`), crypto, injection/APC,
sleep-skipping (`NtDelayExecution`), WoW64 (`monitor_x86.dll`).

## Status

- **(a) inject + IPC + argument-level hooking:** proven host-side.
- **(b) WDAC DLL-load in the golden image:** proven — the DLL loads under the
  enforced WDAC/Code-Integrity policy without an allowlist step.
- **(c) live execution wiring:** proven — `-BehavioralTracing` streams events
  in-guest and merges them into the report.
- **(d) behavioral signatures:** implemented in
  `orchestrator/behavioral_signatures.py` (Track 3.3).
- **(e) child-following:** live-verified in-guest (2026-07-21,
  InjectionHarness run `ebd65b15`) — 3 spawned targets + root all attached,
  harness behavior identical to baseline, injection-chain signatures fired.

## Build

```
pwsh scripts/build_monitor.ps1        # configure + build (Release) + stage to agent/windows/
```

Manual:
```
cmake -G "Visual Studio 17 2022" -A x64 -S agent/windows/monitor_src -B C:\mb
cmake --build C:\mb --config Release
```
Keep the build dir path SHORT (e.g. `C:\mb`): MSBuild's file tracker overflows
MAX_PATH under deeply nested build dirs and fails configure with MSB6003.
