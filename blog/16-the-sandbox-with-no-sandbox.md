# The sandbox with no sandbox: detonating on the orchestrator's own machine

> **Series:** PENTAGRAMMA, part 16/? · **Draft skeleton** · Sources: git `ef8b5ae` + `b7b4184`, `docs/local-mode.md`, `scripts/install_local.ps1`, host canary validation 2026-09-18

**Lede:** What if the VM dies the day before a demo? We gave the sandbox a second personality: `sandbox.mode: local` runs the *entire* detonation pipeline — Sysmon, apitrace, memory dumps, the lot — on the orchestrator's own machine. No Hyper-V, no snapshot, no mercy. The trick was a single seam: every guest operation in our 2,600-line PowerShell helper was already a scriptblock + credential splat; one `-LocalMode` flag swapped `Invoke-Command -VMName` for `& $scriptblock`, and 21 call sites changed transport without changing a word of logic.

## Outline

### The seam
- Every guest op was a hashtable of Invoke-Command args → `Invoke-AnalysisCommand` wrapper picks the transport. VM mode = PSDirect; local mode = in-process, as the orchestrator's elevated identity.
- Lifecycle verbs become structured no-ops (`{Status: skipped, Reason: local-mode}`); `clean_local_state()` is the poor man's snapshot revert (wipes `C:\Sandbox`, agent jsonl, dumps).
- The demo-able one-liner: *the same ps1 file is both the VM driver and the local driver.*

### Validating on the dev host (carefully)
- Canary contract held on bare metal: bat clean/0 + exit-stop, tier1-crypto clean/0, InjectionHarness **malicious/90** with full apitrace injection chains.
- Caught live: `vm_name: "pentagramma"` leaking into local-mode reports (config fallback bug) — fixed to always `"local"`.
- Defender on a dual-use host: RTP popped 30+ detections — all `MpTest!amsi`, our own readiness probe. Fix = path exclusions, not RTP-off.
- Host telemetry is *loud*: ~49k events/run including the orchestrator's own scriptblocks (PS logging captures the shim itself) and a Sysmon EID 25 ProcessTampering self-flag on our python collector. Verdict unaffected; comparison runs need the caveat.

### Why bother
- Emergency/portable analysis kit: one machine, no hypervisor role, `install_local.ps1` and go.
- It also forced the architecture to be honest: every "guest" assumption is now explicit (`environment.mode` in every report).

**Takeaway:** if your guest operations are already pure scriptblocks behind one transport seam, "run it on the host" is a 163-line subclass — and a surprisingly good test of whether your isolation abstractions were real.

---
*Status: skeleton. Assets: local-vs-VM alert counts, Get-LocalStatus checks JSON, install_local.ps1 flow.*
