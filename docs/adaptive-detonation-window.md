# Adaptive detonation window (2026-09-11)

Replaces the fixed detonation window ("watch the root process until it exits or
the timeout burns out") with tree-aware, activity-aware early stopping.
Motivation: `docs/emotet-investigation.md` — the alive-but-silent staller class
(emotet unpacking then retrying dead 2022 C2s) burned the full 120s timeout
producing nothing, while the opposite case (root exits, persistent child lives
on) had its collectors torn down mid-work.

## Semantics

The guest wait-loop (`scripts/hyperv-vm.ps1` `Invoke-SampleExecution`) polls at
`poll_interval_ms` and stops on the FIRST of:

| Stop | Condition | `StoppedEarly` |
|---|---|---|
| **exit-stop** | whole sample tree dead AND `min_runtime_seconds` (30s) elapsed | `exit` |
| **idle-stop** | traced run, apitrace JSONL has not grown for `idle_grace_seconds` (30s), after `min_window_seconds` (45s) elapsed | `idle` |
| **timeout** | hard `timeout_seconds` cap | `timeout` |

**Sample tree** = BFS over `Win32_Process` `ParentProcessId` (1 Hz refresh),
rooted at the traced sample pid (or the launcher when untraced), **plus adopted
pids**: every process the monitor is attached to, mirrored by
`apitrace_collector.py --pids-file` (atomic tmp+replace, 1 Hz). Adoption means a
sample that injects into `explorer.exe` and exits still counts as ALIVE.
The monitor loader's own pid is excluded (tooling must not hold the window).

**Idle signal** = apitrace JSONL file size (the collector is line-buffered, so
size is a live proxy for hooked-API activity). Missing file = no signal = never
idle-stop blind. Untraced runs never idle-stop.

**Minimum-runtime floor** = exit-stop is gated on 30s regardless of tree state:
an instantly-dying sample still gets a baseline window for late Sysmon flush,
dropped files landing, and post-exit second stages. (The only pre-existing
"settle" was a host-side 2s sleep AFTER collectors had already stopped.)

On any non-exit stop: one **final memory dump** (exempt from `max_dumps`; alive
staller holds the unpacked payload), then the **descendant tree is killed**.
Adopted injection hosts are deliberately NOT killed (bluescreening the guest
mid-teardown would cost the telemetry; the per-run VM revert discards them).

`execution_info` gains: `StoppedEarly` (`exit|idle|timeout`),
`AdaptiveWindowActive`, `TreePidsMax`, `AdoptedPidsMax`. `TimedOut` keeps its
legacy meaning (killed before natural exit: true for both `idle` and `timeout`);
idle-stops also prefix stderr with `[adaptive] stopped early: ...`.

## Config (`config/config.yaml`)

```yaml
analysis:
  adaptive_window:
    enabled: true
    min_window_seconds: 45   # earliest idle-stop consideration
    idle_grace_seconds: 30   # silence required before idle-stop
    min_runtime_seconds: 30  # floor for exit-stop
```

Plumbing: `executor.py` → `hyperv.py::execute_sample` →
`Execute-Sample -AdaptiveMinWindowSeconds/-AdaptiveIdleGraceSeconds/
-ActivityFilePath/-AdoptedPidsFile/-MinRuntimeSeconds`. Defaults preserve the
legacy fixed window when the config block is absent. Interactive mode
(`execute_sample_interactive`) is not affected.

## Live validation record (2026-09-11)

| Test | Expected | Got |
|---|---|---|
| `test-sample.bat` canary | clean/0, exit-stop | clean/0, exit-stop at ~3s; wall 225→118s vs the buggy first run |
| `test-tier1-crypto.ps1` canary | clean, exit-stop | clean/8 (8 = its own powershell ImageLoad + PSHost pipe, baseline class accepted by design), exit-stop |
| InjectionHarness | malicious/90 | malicious/90, exit-stop, `TreePidsMax=19`, `AdoptedPidsMax=36` (adoption live), assertions 8/9 |
| Synthetic staller (activity burst → 600s sleep) | idle-stop with final dump | idle-stop at **95s** of a 300s timeout (~68% window saved), final dump **Success** at t=95s, 5/5 periodic dumps ok |

Regression found & fixed during validation: the tree-update guard
`if ($refreshed -ne $null)` hit PowerShell filter semantics — an empty-array
query result (tree dead) evaluated falsy, freezing a stale non-empty tree
forever so exit-stop never fired. Fix: `$null` on the left
(`if ($null -ne $refreshed)`). Lesson: any `-ne $null` guard on a possibly
empty array in this codebase must keep `$null` left.

## Known limitations

- **Network-only silence**: a sample that only talks on sockets (no hooked
  APIs) looks idle. Mitigated by `min_window`+`idle_grace` being conservative;
  proper fix is network apitrace hooks (roadmap #6).
- **PID reuse**: a dead tree pid reused by an unrelated process within the
  window can graft it into the tree (delays exit-stop, never causes a wrong
  early stop). Accepted, same class as the existing lineage code.
- **CIM failure** degrades gracefully to the legacy `$proc.HasExited` check.
- InjectionHarness `mapview` assertion failure is a **pre-existing Sysmon
  visibility gap** (victim invisible to Sysmon), unrelated — tracked in
  `docs/TODO.md` deferred bugs.
