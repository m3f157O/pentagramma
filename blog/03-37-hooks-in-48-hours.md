# 37 hooks in 48 hours: designing an apitrace monitor

> **Series:** PENTAGRAMMA, part 3/11 · **Draft skeleton** · Sources: `docs/corpus-and-hookset-changes.md` (2026-07-26/27), `docs/coverage-table.md`

**Lede:** Sysmon sees what the OS reports. To see what malware *does*, you need to sit inside the process. Over one weekend we grew our user-mode monitor from 11 to 37 MinHook hooks — loader, injection, APC, token, crypto, anti-debug — and learned that the hard part isn't hooking, it's not crashing and not crying wolf.

## Outline

### The monitor in 60 seconds
- DLL injected pre-entry into the sample (later: by a kernel driver — part 8), hooks via MinHook, events over a named pipe, x64 **and** WoW64 (`monitor_x86.dll`, verified: 730 events from a 32-bit sample).

### Tier 1 (11 → 18): loader/timing/crypto
- BCrypt hooked on `bcrypt.dll`, **not** `bcryptprimitives.dll` (empirical; the primitives DLL is a passthrough on modern Windows).

### Tier 1.5 (18 → 33): the injection toolkit
- APC, token manipulation, cross-process read, hollowing, Ex-variants, anti-debug.
- New signatures: `ApitraceTokenManipulation`, `ApitraceCrossProcessRead`, `ApitraceAntiDebug`.

### Tier 2 (33 → 37): watching the watchers
- Address emission (`base=`/`start=`) so signatures reason about *where*, not just *what*.
- `ApitraceAntiTamper` — catches ntdll/amsi.dll unhooking (yes, we hook the unhookers).
- Timer-APC arming (hello Ekko/Foliage), `ApitraceTransactionAbuse` (doppelgänging), `ApitracePpidSpoof`.

### The unglamorous 80%: stability and false positives
- Crash repro: .NET/multithreaded samples killed the monitor **10/10 runs** → CRT-free TID-table re-entrancy guard → **0/10**. SEH safe-reads everywhere; pipe reconnect-then-report.
- FP engineering: exec-alloc threshold 30 → 100 after measuring a benign CLR process making **62 RWX allocations**. *Measure the benign before flagging the malicious.*
- Benign FP report score: 70 → 37.

### The honesty section
- Same pass admitted our headline metrics (precision 1.000 / recall 0.989) were **in-sample fit on 19 hand-curated scripts** — the confession that spawned the real-corpus program (→ part 11).
- Residual blind spot: direct syscalls with remapped ntdll — in-process memcpy beats any user-mode hook (→ part 8).

**Takeaway:** hook count is a vanity metric; crash rate and FP rate are the product.

---
*Status: skeleton. Needs: hook list table, the 10/10→0/10 repro details, monitor architecture diagram.*
