# User-Mode Telemetry Roadmap

## Goal

Replace the kernel EDR driver with a user-mode-only telemetry stack for the sandbox.
This removes driver signing, test signing mode, and GPO registry restrictions.
The new stack will run on any standard Windows VM.

---

## 1. Local Test Plan (host Windows, no VM)

Before touching Hyper-V, validate every telemetry source locally.
Use benign malware-simulation scripts (`test-sample.bat`, a small PowerShell dropper,
and a C# or Python injector) so we can build detection logic safely.

### Test targets to generate telemetry

| Target | Behavior to detect |
|--------|-------------------|
| `test-dropper.bat` | Creates `HKCU\...\Run`, writes `%APPDATA%\payload.exe`, spawns `notepad.exe` |
| `test-injector.ps1` | Uses `CreateRemoteThread` / `NtAllocateVirtualMemory` to inject into notepad |
| `test-dns.py` | Resolves suspicious domains, makes HTTP request |
| `test-delete.exe` | Self-deletes, clears Event Log |

All targets must be benign — no actual malicious code.

---

## 2. Telemetry Sources (in priority order)

### 2.1 ETW Kernel Providers (no admin required for some, admin recommended)

| Provider | Events |
|----------|--------|
| `Microsoft-Windows-Kernel-Process` | Process start/stop, command line |
| `Microsoft-Windows-Kernel-File` | File create/read/write/delete |
| `Microsoft-Windows-Kernel-Registry` | Registry create/delete/set value |
| `Microsoft-Windows-Kernel-Network` | TCP connect/accept, UDP send/receive |
| `Microsoft-Windows-Threat-Intelligence` | `NtAllocateVirtualMemory` exfil, remote thread, APC, process hollowing |
| `Microsoft-Antimalware-Scan-Interface` | Script content scans |
| `Microsoft-Windows-PowerShell` | PowerShell script block logging |

**Tech options:**
- `logman start` + `tracerpt` / `xperf` (built-in)
- `pywin32` + `wevtapi` or ETW API
- PowerShell `Register-EtwEventSession`
- `krabs` (C++) if we later need performance

**Local success criteria:**
Run the test dropper and capture:
- Process creation with full command line
- File write to `%APPDATA%`
- Registry set value in `Run` key
- Network DNS query

### 2.2 Sysmon (Microsoft-signed, free)

Sysmon gives us rich, structured XML events without writing a driver.

| Event ID | Use |
|----------|-----|
| 1 | ProcessCreate |
| 3 | NetworkConnect |
| 7 | ImageLoad |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess |
| 11 | FileCreate |
| 12 / 13 / 14 | Registry events |
| 17 / 18 | Pipe events |
| 22 | DNSQuery |
| 25 | ProcessTampering |

**Deployment:**
- Ship `sysmon.exe` + `sysmonconfig.xml` in `agent/windows/`.
- Install: `sysmon.exe -accepteula -i sysmonconfig.xml`
- Uninstall before snapshot revert: `sysmon.exe -u`

**Local success criteria:**
Same as ETW, but output is XML in Event Viewer / `Get-WinEvent`.

### 2.3 Windows Event Log Forwarding

- Forward `Security`, `System`, `Application`, `Microsoft-Windows-Sysmon/Operational`
- Parse with `Get-WinEvent -FilterHashtable @{LogName='...'; StartTime=$ts}`

**Local success criteria:**
Query Sysmon events from PowerShell and convert to JSON.

### 2.4 API Hooking / User-Mode Tracing (optional advanced)

For higher-fidelity arguments that ETW/Sysmon miss:
- `EasyHook` or `Detours` on target process
- Hook `CreateFileW`, `RegSetValueExW`, `WinExec`, `InternetConnectW`, etc.

**When to add:** after ETW + Sysmon are working.

### 2.5 Periodic Forensic Snapshots

User-mode cannot protect itself, but we can detect tampering after the fact:
- Registry snapshot before/after (`reg export HKLM\...`)
- File tree snapshot (`robocopy /L` or hash walk)
- Service/driver list (`sc query`, `fltmc filters`)

---

## 3. New Agent Architecture

```text
+--------------------------------------------------+
|  Sandbox VM                                      |
|                                                  |
|  +----------------+     +---------------------+  |
|  |   bootstrap    |---->|   telemetry agent   |  |
|  |   (Launcher)   |     |   (Python service)  |  |
|  +----------------+     +----------+----------+  |
|                                  |               |
|         +------------------------+               |
|         |                                        |
|    +----v----+   +-----------+   +----------+   |
|    |   ETW   |   |  Sysmon   |   |  Event   |   |
|    | session |   |  service  |   |  queries |   |
|    +----+----+   +-----+-----+   +-----+----+   |
|         |              |              |         |
|         +--------------+--------------+         |
|                        |                        |
|              +---------v---------+              |
|              |  JSONL log file   |              |
|              |  C:\sandbox\logs  |              |
|              +---------+---------+              |
|                        |                        |
|              +---------v---------+              |
|              |  HTTP SSE server  |              |
|              |  0.0.0.0:8443     |              |
|              +-------------------+              |
+--------------------------------------------------+
```

The orchestrator connects to `http://<vm-ip>:8443/api/stream` and receives
normalized JSON events, just like it does today with the EDR agent.

---

## 4. Implementation Phases

### Phase 0 — Static analysis ✅

- [x] Build `orchestrator/static_analysis.py`
- [x] File type, hashes, entropy, strings, PE parsing
- [x] YARA rule matching
- [x] Signature check
- [x] Optional VirusTotal lookup stub
- [x] Integrate into `executor.py` and `reporting.py`

### Phase A — Local ETW collector ✅

- [x] Build `agent/windows/etw_collector.py`
- [x] Capture Process, File, Registry, Network events via `NT Kernel Logger`
- [x] Output normalized JSONL to `logs/etw_test.jsonl`
- [x] Run local test dropper and verify events (cmd.exe → reg.exe → Notepad.exe chain captured)
- [x] Add `tests/local/inspect-etw.py` and `summarize-etw.py` diagnostics

### Phase B — Sysmon integration ✅

- [x] Add `agent/windows/sysmonconfig.xml` tuned for malware analysis
- [x] Build `agent/windows/sysmon_manager.py` (install/start/stop/uninstall)
- [x] Build `agent/windows/sysmon_parser.py` to query `Microsoft-Windows-Sysmon/Operational`
- [x] Add `tests/local/summarize-sysmon.py` and `run-sysmon-test.ps1`
- [x] Build unified `agent/windows/telemetry_collector.py` (Sysmon primary)
- [x] Update `orchestrator/executor.py` to deploy agent and collect Sysmon JSONL
- [x] Update `config/config.yaml` with `telemetry:` section
- [ ] Run local test and verify process/file/registry/network events

### Phase C — ETW gap-fillers (advanced, optional)

- [ ] Implement `agent/windows/etw_ti_collector.py` (ETW Threat-Intelligence) — deferred; the real gate is PPL/Antimalware-Light code signing, not SYSTEM privilege (see `docs/detection-gap-tracker.md`)
- [x] Add AMSI script content capture (`agent/windows/amsi_collector.py` + `etw_common.py`)
- [x] Add PowerShell script block logging (`agent/windows/powershell_logging_manager.py` + `powershell_parser.py`)
- [x] Enable via `telemetry.sources: [sysmon, amsi, powershell]` (`etw_ti` stays commented out)

### Phase D — VM deployment

- [ ] Install Python 3.11 in the analysis VM (or port telemetry scripts to PowerShell)
- [ ] Pre-install Sysmon in the VM and snapshot as `SANDBOX-CLEAN`
- [ ] Verify orchestrator can copy agent, run sample, and collect telemetry end-to-end

### Phase C — Telemetry agent service

- [ ] Build `agent/windows/telemetry_agent.py`
- [ ] Start ETW + Sysmon on boot
- [ ] Expose SSE endpoint on `0.0.0.0:8443`
- [ ] Support start/stop/status via named pipe or HTTP

### Phase D — Orchestrator integration

- [ ] Add `agent/` folder deployment in `executor.py`
- [ ] Replace `edr_consumer.py` with generic `telemetry_consumer.py`
- [ ] Update `config.yaml` to use `telemetry.mode: usermode`
- [ ] Keep `telemetry.mode: kernel` as optional for later

### Phase E — Snapshot forensics

- [ ] Pre-analysis snapshot: registry, file hashes, services, scheduled tasks
- [ ] Post-analysis snapshot and diff
- [ ] Add diff report to `reporting.py`

### Phase F — Hardening (optional)

- [ ] Watchdog process to restart telemetry agent
- [ ] Hide agent files / process name
- [ ] Detect and report agent tampering

---

## 5. Normalized Event Schema

Every telemetry source emits the same JSON shape:

```json
{
  "ts": "2026-06-15T13:37:00.123456Z",
  "task_id": "task-uuid",
  "source": "sysmon",
  "event_type": "ProcessCreate",
  "pid": 1234,
  "ppid": 5678,
  "image": "C:\\Windows\\System32\\notepad.exe",
  "command_line": "notepad.exe C:\\Users\\...\\evil.txt",
  "user": "DESKTOP\\gigi",
  "ioc": {
    "md5": "...",
    "sha256": "...",
    "signature": "Microsoft Windows"
  },
  "raw": { }
}
```

`source` can be: `etw`, `sysmon`, `eventlog`, `snapshot`, `amsi`.
`event_type` uses the same MITRE-friendly vocabulary everywhere.

---

## 6. VM Deployment Plan (after local validation)

1. Create clean Windows VM.
2. Create user `gigi / gigi`.
3. Disable UAC prompts or set auto-elevate policy.
4. Install Python 3.11 in VM.
5. Copy `agent/windows/` to `C:\sandbox-agent\`.
6. Register telemetry agent as a scheduled task or service.
7. Open Windows Firewall port 8443 inbound.
8. Shut down and snapshot as `SANDBOX-CLEAN`.

No test signing, no driver install, no GPO registry edits.

---

## 7. Open Questions

1. Do we keep the existing EDR dashboard UI, or build a new minimal SSE server?
2. Should the agent run as a Windows service, a scheduled task, or a console process auto-started via Run key?
3. Do we want real-time streaming during analysis, or collect after-the-fact logs?
   → **Answered 2026-07-27** for the console-view angle: keep the passive
   WMI-thumbnail view (optionally higher-res/faster); an interactive
   browser console (RDP+Guacamole) is viable but must stay an opt-in
   per-job mode — see `docs/interactive-console-streaming.md`.
4. Should we include a fake user environment (documents, browser history, cookies) for anti-evasion?
   → **Answered 2026-07-27: yes, implemented** — `agent/windows/apply_dressing.py`
   + `POST /api/vm/provision-dressing` bake documents, Edge history/bookmarks,
   RunMRU/TypedPaths and Recent shortcuts into the golden snapshot
   (verify-gated recapture). See `docs/environment-dressing.md`. Uptime stays
   unfakeable without hypervisor time control (accepted).

---

## 8. Deliverables

| File | Purpose |
|------|---------|
| `agent/windows/etw_collector.py` | ETW capture and normalization |
| `agent/windows/sysmon_installer.py` | Sysmon install/start/stop |
| `agent/windows/sysmonconfig.xml` | Tuned Sysmon config |
| `agent/windows/telemetry_agent.py` | SSE server + orchestrator glue |
| `agent/windows/requirements.txt` | `pywin32`, `websockets`, etc. |
| `orchestrator/telemetry_consumer.py` | Replaces `edr_consumer.py` |
| `orchestrator/executor.py` (updated) | Deploys agent, starts/stops telemetry |
| `config/config.yaml` (updated) | `telemetry.mode` switch |
| `tests/local/` | Benign dropper/injector/dns scripts |
