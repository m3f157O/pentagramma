# What Sysmon can't see: injection techniques empirically tested

> **Series:** PENTAGRAMMA, part 6/11 · **Draft skeleton** · Sources: `docs/harness-techniques.md` (2026-08-17), `docs/coverage-table.md`, InjectionHarness

**Lede:** We built an InjectionHarness that performs 15+ process-injection and evasion techniques on demand, then detonated it against our own sandbox to draw the real technique→telemetry map. The results contradicted two popular beliefs — including what Sysmon's famous "process tampering" event actually detects.

## Outline

### The harness
- One binary, one flag per technique: hollowing, herpaderping, ghosting, doppelgänging, AtomBombing, module overloading, SetWindowsHookEx, NtQueueApcThreadEx, MapView injection…
- Every technique **live-asserted**: expected Sysmon/apitrace signals checked automatically per run (our detection regression suite).

### Belief #1, corrected: hollowing and EID 25
- Popular write-ups imply Sysmon EID 25 (ProcessTampering) catches hollowing. **Across 3 verified runs: zero EID 25.**
- Sysmon's tamper check only sees **FILE-based** tampering (image replaced/herpaderped on disk). Pure in-memory hollowing is invisible to it.
- Detection of hollowing has to come from apitrace (the allocation/write/create-resume pattern) — not from Sysmon.

### Belief #2, corrected: herpaderping
- Classic herpaderping is **blocked by modern Windows itself** (file lock semantics). The OS killed the technique before our detections had to.
- Ghosting still works — and leaves a fingerprint: EID 25 "Image is locked for access" + exactly **2 Sysmon EID 255** per run (the ghosted file deleted before image-name resolution; root-caused back in June).

### The technique that doesn't exist
- Thread-pool injection (#13): declared **not implementable** outside PoolParty-style research — honestly marked SKIPPED in the harness rather than faked.

### The residual gap class (stated plainly)
- Direct syscalls with remapped ntdll, KnownDlls remapping, in-process memcpy — no user-mode hook sees these. Full matrix in `docs/coverage-table.md`.
- This admission is the setup for parts 7–8: if you can't hook it from user mode, you go to the kernel.

**Takeaway:** the published behavior of security telemetry is folklore until you detonate the technique yourself and count the events.

---
*Status: skeleton. Needs: technique→telemetry table excerpt, EID 255 ghosting evidence, coverage matrix figure.*
