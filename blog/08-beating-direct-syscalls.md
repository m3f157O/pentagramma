# Beating direct syscalls: kernel-side injection placement

> **Series:** PENTAGRAMMA, part 8/11 · **Draft skeleton** · Sources: `docs/guardian-driver.md` §4 (2026-09-03), `syscall_spawn.exe` test

**Lede:** Every user-mode hook has the same weakness: the sample can dodge it with direct syscalls — recover the SSN, call `NtCreateUserProcess` straight, and your beautiful apitrace goes dark on the child. So we moved monitor *placement* into the kernel, and then attacked ourselves with halos-gate to prove it holds.

## Outline

### The dodge
- User-mode hooks see `CreateProcessW`. Malware calls `NtCreateUserProcess` via a fresh ntdll mapping — no hooks, no apitrace on the new process.
- The child runs naked: exactly the process the sample wanted unmonitored.

### The fix: placement from ring 0
- SandboxGuard's process-create callback fires **below** any user-mode trick — you cannot syscall your way past a kernel callback.
- On create: queue an APC → `LoadLibraryW(monitor)` into the child **before its entry point runs**. Parent's trickery is irrelevant.
- WoW64 covered too: `guardian_loadlib_x86.exe` helper places the 32-bit monitor (`GuardianInjectionPlaced Wow64=true` verified).

### The proof: attacking ourselves with halos-gate
- Built `syscall_spawn.exe`: recovers SSN 200 via **halos-gate** (walking neighboring stubs *past our own hooks*, which add `jmp` bytes that break naive SSN extraction), spawns a child via raw `NtCreateUserProcess`.
- Result: apitrace on the parent — dark (as expected; it dodged our user hooks). Driver — **placed the monitor into child PID 3284 anyway. PASS.**
- This is the part 6 gap class closed: in-process memcpy beats user hooks; it does not beat kernel callbacks.
- *[placeholder: diagram — syscall path vs callback path]*

### Why pre-entry matters
- Placement before the entry point runs = the child's *first* instruction is already traced. No race window, no "we missed the first 2 seconds."
- Same mechanism double-serves benign injection verification (A1a's `wkscli.dll` check).

### The honest limits
- A sample that brings its *own* kernel driver is out of scope (stated in part 7). Kernel-vs-kernel is a different war.
- Unhooking inside the child is still possible post-placement — that's what the (deferred) hook-integrity *verify* role is for.

**Takeaway:** if your monitor depends on the malware's cooperation (calling hooked APIs), it's optional equipment. Kernel placement makes monitoring unconditional.

---
*Status: skeleton. Needs: halos-gate explainer, callback/APC sequence diagram, the PID 3284 run reference.*
