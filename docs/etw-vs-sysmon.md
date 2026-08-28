# ETW vs Sysmon Coverage Analysis

## Conclusion

**Sysmon is the primary sandbox telemetry source. ETW is kept only for specific gap-filling providers.**

Sysmon is essentially a curated, Microsoft-maintained ETW consumer with a kernel minifilter. For malware analysis sandboxes, it covers the vast majority of interesting behaviors with cleaner output than raw ETW.

---

## What Sysmon covers (ETW kernel trace is redundant here)

| Behavior | Sysmon Event | ETW equivalent | Verdict |
|----------|--------------|----------------|---------|
| Process creation + command line + hashes | 1 | Kernel-Process | Sysmon better |
| Process termination | 5 | Kernel-Process | Sysmon better |
| Network connection with IP/port | 3 | Kernel-Network | Sysmon better |
| DNS query | 22 | DNS-Client ETW | Sysmon better |
| File create/delete/rename with path | 11, 23, 26 | Kernel-File | Sysmon better |
| Registry create/set/rename/delete | 12, 13, 14 | Kernel-Registry | Sysmon better |
| DLL load | 7 | Kernel-Process ImageLoad | Sysmon better |
| Remote thread injection | 8 | Kernel-Process ThreadStart | Sysmon better |
| Process access (OpenProcess) | 10 | — | Sysmon unique |
| Raw disk access | 9 | — | Sysmon unique |
| Named pipe create/connect | 17, 18 | — | Sysmon unique |
| Driver load | 6 | — | Sysmon unique |
| WMI event subscription | 19, 20, 21 | — | Sysmon unique |
| Process tampering | 25 | — | Sysmon unique |

---

## What ETW covers that Sysmon misses

These are the only ETW providers worth keeping as gap-fillers.

### 1. ETW Threat-Intelligence (ETW-Ti)

**Provider:** `Microsoft-Windows-Threat-Intelligence`  
**GUID:** `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`  
**Introduced:** Windows 10 1903 (build 18362)

**Why Sysmon is not enough:**
- Sysmon Event 8 (`CreateRemoteThread`) fires **after** the injection sequence is complete.
- It does not see the earlier steps: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtQueueApcThread`.
- ETW-Ti sees the **full injection chain** at kernel level, including direct syscalls that bypass user-mode hooks.

**What ETW-Ti detects:**
- `NtAllocateVirtualMemory` with `MEM_COMMIT | MEM_RESERVE`
- `NtProtectVirtualMemory` changing pages to `PAGE_EXECUTE_READWRITE`
- `NtCreateThreadEx`
- `NtQueueApcThread`
- `NtMapViewOfSection`
- `NtSetContextThread`
- Cross-process memory operations on high-value targets (`lsass.exe`, `winlogon.exe`, etc.)

**Use case for sandbox:** detect process hollowing, reflective DLL injection, manual mapping, APC injection, and direct syscalls.

### 2. AMSI (Anti-Malware Scan Interface)

**Provider:** `Microsoft-Antimalware-Scan-Interface`  
**GUID:** `{2a576b87-09a7-520e-c21a-4942f0271d67}`

(Verified empirically against a real captured session; commonly-cited GUIDs
like `{00604C86-2D25-46D6-B814-CD149BFDF0B3}` belong to third-party AMSI
*provider* implementations, not this ETW *event* provider.)

**Why Sysmon is not enough:**
- Sysmon sees that `powershell.exe` ran and what command line it had.
- It does **not** log the actual script content scanned by AMSI.

**What AMSI provides:**
- Full PowerShell / VBA / JScript / Office macro content
- Scan results and scan requests
- Obfuscated or encoded scripts as they are decoded

**Use case for sandbox:** extract C2 URLs, commands, and payloads from script-based malware.

### 3. PowerShell Script Block Logging

**Provider:** `Microsoft-Windows-PowerShell`  
**Event ID:** 4104 (script block), 4103 (module logging)

**Why keep it:**
- Logs the full deobfuscated PowerShell script blocks.
- Complements AMSI; sometimes captures content AMSI misses.

### 4. Windows Defender / Antimalware Events

**Provider:** `Microsoft-Windows-Windows Defender`, `Microsoft-Antimalware-AMFilter`

**Why keep it:**
- If the sample triggers Defender, these events give detection names and actions.
- Useful for correlation even if the sandbox has its own telemetry.

### 5. .NET Runtime Events

**Provider:** `Microsoft-Windows-DotNETRuntime`

**Why keep it:**
- For .NET malware: loaded assemblies, JIT compilation, method entries.
- Helps identify packers and reflective .NET assembly loading.

---

## What both miss

| Technique | Why both miss | Possible supplement |
|-----------|---------------|---------------------|
| Kernel driver / rootkit | Runs below both | Kernel minifilter (custom EDR driver) or memory forensics |
| Hypervisor/firmware attacks | Out of scope | Chipsec, dedicated research env |
| Encrypted C2 content | Both see metadata only | TLS interception proxy (mitmproxy/Burp) |
| Fileless in-memory only | Need memory dump | MemProcFS / Volatility |
| ETW/Sysmon tampering | Self-protection problem | Watchdog + kernel self-protection driver |

---

## Recommended Architecture

```text
Telemetry stack
├── Primary:   Sysmon (process, file, registry, network, DNS, DLLs, threads, pipes)
├── Gap-fill:  ETW-Ti (direct syscalls, injection chains, RWX allocations)
├── Gap-fill:  AMSI (script content)
├── Gap-fill:  PowerShell script block logging
├── Extras:    Windows Defender events
└── Fallback:  ETW kernel trace (optional, legacy)
```

---

## References

- JPCERT/CC Eyes — "ETW Forensics - Why use Event Tracing for Windows over EventLog?"  
  https://blogs.jpcert.or.jp/en/2024/11/etw_forensics.html
- SysWhispers4 — "ETW-Ti and Kernel-Level Detection"  
  https://joasasantos-syswhispers4.mintlify.app/advanced/etw-ti-limitations
- Nextron Systems — "AURORA – Leveraging ETW for Advanced Threat Detection"  
  https://www.nextron-systems.com/2025/07/31/aurora-leveraging-etw-for-advanced-threat-detection/
