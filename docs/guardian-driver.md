# SandboxGuard — guardian driver

Status: **WS-A0 spike artifacts ready** — driver builds + signs host-side;
in-guest load test pending (runbook below). Plan of record:
`C:\Users\giammy\.kimi\plans\cyclops-beta-ray-bill-iron-fist.md`.

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

_Pending — fill in after the spike run._

- CI policy enforcement status:
- testsigning accepted:
- driver load (`sc start`):
- PING handshake:
- process-create capture (notepad.exe):
- **Decision:** GO / NO-GO
