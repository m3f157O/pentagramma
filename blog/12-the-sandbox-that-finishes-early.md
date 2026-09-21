# The sandbox that finishes early: adaptive detonation windows

> **Series:** PENTAGRAMMA, part 12/? · **Draft skeleton** · Sources: `docs/adaptive-detonation-window.md`, git `735ca57`, `5c3165c`

**Lede:** Every commercial sandbox runs a fixed timer — 120 seconds, 300 seconds — and everyone knows the failure modes: patient malware sleeps past the timer, boring samples waste 90% of the window. We replaced the timer with two honest questions: *is the sample's process tree still alive?* and *is it still making API calls?* The window now ends when the sample does — and the first thing the new logic caught was a bug in itself.

## Outline

### Two stop conditions, one contract
- **Exit-stop:** track the whole sample process tree (Win32_Process BFS @1Hz), not just the launcher. Empty tree → stop. Persistent children are no longer orphaned mid-run; at end, the whole tree is killed.
- **Idle-stop (traced path only):** after a minimum window, if the apitrace JSONL hasn't grown for `idle_grace` seconds, stop — the dead-C2 staller class. Final memory dump still taken. Missing signal file = never stop blind.
- Config: `analysis.adaptive_window {enabled, min_window_seconds: 45, idle_grace_seconds: 30}`; defaults preserve legacy behavior.

### Lineage v2: adopting the injected-into
- Inject-and-exit samples break the tree heuristic: the launcher dies, the payload lives on in `explorer.exe`. The apitrace collector now publishes its attached PIDs (`apitrace.jsonl.pids`, atomic tmp+replace @1Hz); the wait-loop **adopts** injected-into processes as extra tree roots.
- Deliberate asymmetry: adopted OS hosts are *counted* but never *killed* (kill stays descendants-only).
- Result fields: `StoppedEarly=exit|idle|timeout`, `AdaptiveWindowActive`, `TreePidsMax`, `AdoptedPidsMax`.

### The `$null`-guard bug (a PowerShell trap worth its own paragraph)
- `$arr -ne $null` doesn't test for null — it *filters out* nulls. A tree-refresh that momentarily returned `$null` passed the "guard", froze a stale non-empty tree, and silently turned exit-stops into idle-stops. Correct form: `$null -ne $arr`.
- Found by the benign canary, which came back with the wrong stop-reason. The canary contract pays for itself again.

### Validation
- Canary: clean/0, `StoppedEarly=exit`, 225s → **118s**.
- InjectionHarness: still malicious/90 — but as an *idle-stop* variant: adopted hosts stayed alive while apitrace went silent (`TreePidsMax=19`, `AdoptedPidsMax=36`).
- Staller sample: idle-stop at 95s of a 300s window, final dump intact.
- Corpus gate (27 runs, offline replay): recall 1.000, FPR 0.000, precision 1.000 — zero verdict drift from cutting windows in half.

**Takeaway:** the timer wasn't measuring the sample; it was measuring our patience. Measure liveness instead — and keep a canary that notices when your "is it alive?" logic lies.

---
*Status: skeleton. Needs: time-saved stats across a full corpus batch, any future stop-variant additions.*
