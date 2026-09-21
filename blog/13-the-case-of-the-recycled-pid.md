# The case of the recycled PID: when your evasion detector flags itself

> **Series:** PENTAGRAMMA, part 13/? · **Draft skeleton** · Sources: git `5559ad8`, `tests/test_blindspot_detection.py`, flagged canary report (2026-09-12)

**Lede:** We built a cross-check to catch malware that blinds our user-mode hooks: Sysmon (kernel view) vs apitrace (in-process view), joined per PID, ±2 seconds. Weeks of silence. Then it fired for the first time ever — on our own *benign canary*. The malware hadn't outsmarted us. Windows had recycled a process ID, and our detector compared the ghost of one program against the life of another.

## Outline

### The two-eyes design
- Apitrace can be blinded from user mode (unhook, direct syscalls). Sysmon can't. So every "hookable" Sysmon event should have an apitrace counterpart **from the same PID**. 86 misses → `ApitraceBlindSpot` alert, +15.
- The join key is the PID. That was the bug.

### The timeline of pid 7964
- 15:30:29 — the canary's `certutil.exe` child starts as pid **7964**; monitor attaches, sees 2 calls; certutil exits.
- 15:30:52 — an unrelated `powershell.exe` (guest background noise, spawned by svchost, never hooked) gets **the same pid** from the OS.
- Sysmon dutifully logs its 82 ImageLoads + 4 FileCreates under 7964 → correlator looks up certutil's stale apitrace slot → 86 phantom misses → clean canary scored suspicious/15.
- The data was correct. The *identity* was wrong: PID ≠ process, it's a name the OS hands out again.

### Why now and never before
- Needs a traced process to die *and* the OS to recycle that exact pid mid-run. Pure timing luck — shorter adaptive windows + guest noise made the collision real.
- The offline corpus gate can't catch this class: replay works on stored reports, and none contained the collision. Only live runs and canaries see it.

### The fix
- Sysmon EID 1 (ProcessCreate) names every process birth. An EID 1 for a pid *strictly after* our monitor attached to that pid means: new incarnation, never hooked → exclude its events from the cross-check. (The first EID 1 precedes attach — that's the traced process itself.)
- Offline replay of the flagged report: suspicious/15 → clean/0. +1 regression test (`test_pid_reuse_suppressed`), 137 unit tests green.
- Known sibling: `_detect_telemetry_silence` has the same reuse-vulnerability class (potential *true*-positive if reuse lands after traced death) — noted, not yet triggered.

**Takeaway:** every correlator that joins telemetry streams on PID carries a hidden assumption — that PIDs are stable identities. They aren't. The first live trigger of your evasion detector might be the detector.

---
*Status: skeleton. Needs: nothing blocking; could add a short "how we'd have caught it without the canary" sidebar.*
