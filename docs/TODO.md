# PENTAGRAMMA — Work Queue (2026-09-21, second refresh)

## Done 2026-09-21 PM (uncommitted pending validation)
- **Job-slot resilience**: `_run_ps` subprocess timeout (caller timeout + 300s
  margin, else 900s) + stale-job watchdog in `jobs.py` (reaps jobs running
  >1h) + idempotent `release(job_id)` — the 25-min slot wedge cannot recur.
- **Own-loader injection FP fixed** (the big one): goodware detonations caught
  rg.exe at **malicious/45** — the monitor loader's own injection into the
  sample scored as sample behavior whenever the loader's ProcessCreate was
  missing from telemetry. Fix: `reporting._suppress_monitor_injection_artifacts`
  now also identifies the loader via guardian/apitrace markers (trace root =
  first `__monitor_attached__`, `GuardianInjectionPlaced` targets), Sysmon-
  independent. Replay: rg 45→20, 7za 28→13, curl 23→8, plink 15→0.
- **Guest clock sync**: after snapshot revert the guest resumed at the
  snapshot's save time (2026-09-02!) and only re-synced ~30s in — early events
  fell out of the telemetry window. New `Sync-GuestTime` verb + executor step
  before telemetry_init.
- **Sysmon blind-window readiness gate**: the sample launch chain's
  ProcessCreate events vanish inside a racy seconds-long window around launch
  (MachineGUID atomic lost loader/cmd/reg PCs 3/3 runs; apitrace proved the
  processes existed). New `sysmon_manager.py wait-ready` canary probe +
  `sysmon_ready` executor step right before sample launch — never launch
  blind; degraded runs are loud in the report.
- **YARA `suspicious_cmd_commands`**: PE files now need 2+ strings (ripgrep
  legitimately embeds `cmd.exe /e:ON /v:OFF /d /c`).
- **Goodware renamed to real names** (7za/curl/plink/rg.exe): the `gw_real_*`
  staging names tripped vendored "renamed binary" Sigma rules — honest
  detections of an artificial filename. Labels updated (old names kept for
  stored reports).
- ART gap tracker: 15 remaining misses classified in
  `docs/detection-gap-tracker.md`. NOTE: two of yesterday's "fixed" ART scores
  (TelemetryController 25, scarab 15) were self-injection artifacts — true ART
  score is ~38-40/55, not 42/55.
- Tests: 26/26 suite files + 25 pytest tooling tests + 4 readiness tests;
  corpus metrics gate green (recall 1.000, FPR 0.000).

## Done 2026-09-21 (all committed)
- **ART detonation batch + coverage audit** (`0dd49b5`): 55/55 atomics
  detonated; verdict recall 36 → 40/55 stored (42/55 incl. replay), TTP 37/55.
  8 new sigma rules (recon-chain correlation, MachineGUID, prefetch-disable,
  CredSSP, fsutil deletejournal, TelemetryController, Recycle-Bin CLSID,
  var-slice) — gated: corpus precision/recall 1.000, FPR 0.000, canaries
  unchanged (bat 0, tier1 8, harness 90).
- **DisableRegistryTools removed from golden image** (`4c103ba`): policy was
  neutering every reg.exe-driven sample (found via ART; probe: High-IL admin +
  rc=1). `registry_tools_manager.py` + verify-gated
  `POST /api/vm/provision-registry-tools`; SANDBOX_READY re-baked.
- **Subprocess/PSDirect hardening** (`d1c2761`): cp1252 `errors="replace"` on
  all text-mode subprocess calls (reader-thread `UnicodeDecodeError` was
  silently truncating telemetry); `Invoke-AnalysisCommand` retries transient
  transport errors (PSSessionStateBroken/InvalidVMState) up to 4 min —
  first-job-after-revert race eliminated.
- Blog drafts 19 (ART report card) + 20 (registry policy) in `blog/`.

## Backlog (priority order)

1. **CAPE scoring validation** — `cape_signatures.score: false` flip gate
   (docs/cape-integration.md checklist): replay `--all --changed-only` +
   detection_metrics, no FPR regression → enable. Expected to close ~7 of the
   clean/8 ART misses (sigs already fire enrichment-only). Corpus is now big
   enough to make the gate meaningful.
2. **Medium→high rule bumps** (after #1, same replay harness): wmic process
   create, replace.exe UNC — single-hit verdict on unambiguous actions.
3. **ART re-detonation sweep** — with the blind-window gate + clock sync +
   loader-suppression live, stored ART reports are stale (several scores were
   self-injection artifacts or blind-window victims). Re-run the 55-atomic
   batch when time allows (~4.5h) for a truthful scoreboard.
4. **Elevated-launch support** — ART manifest records `elevated` flags but
   nothing honors them; add a launch-path flag for samples needing SYSTEM.
5. **detection_metrics.py runtime** — full corpus replay now exceeds 1h
   (second correlation scans every event of every 60k-event report).
   Optimize (prefilter base-rule candidates / parallelize) before the gate
   becomes too painful to run.
6. **Throwaway-VM local-mode full validation** — real corpus sample + alert
   parity vs hyperv mode, inside a disposable VM (`scripts\install_local.ps1`).
7. **Fake-C2 / inetsim** (roadmap #1 value) — revives dead-C2 stallers
   (emotet); acceptance = emotet weak-run re-scoring.
8. **Network apitrace hooks** — Winsock/WinHTTP/WinINet argument-level
   coverage for C2 (beyond Sysmon EID 3/22).
9. **Office golden image** — second analysis VM (doc/xls/macro samples);
   fleet member #2, exercises the per-VM credential registry for real.
10. **Fleet next steps** — guest health probing for GUI-registered VMs,
    Hyper-V MCP adapter, provision a fresh VM end-to-end from the GUI.
11. **2 emotet signatures** — from the 09-11 investigation.
12. **Elastic RTA subset** — detection validation corpus.
13. **Monitor-ready flaky timeout** — InjectionHarness batch run had
    `[loader] monitor-ready wait returned 258` → empty apitrace → score 32;
    re-run was fine (90). Watch for recurrence; consider raising
    `monitor_pid_wait_seconds` or a loader retry.

## ART misses: deliberate non-fixes (FP traps, do not "fix")
- Suspicious threshold 10 → 8; `sigma.min_level` below medium.
- Bare single-command recon scoring (tasklist/systeminfo alone).
- Proxy-enable single-write rule; generic HKLM-write scoring.
- Recycle-Bin CLSID atomic: TrustedInstaller-owned key, write denied even as
  admin — technique genuinely fails here; clean/0 is truthful.
- T1059.003 var-slice: cmd expands `%VAR:~-3,1%` before spawning, so no
  ProcessCreate ever contains the pattern (rule kept for literal launchers;
  closing the atomic needs cmd-line auditing/script-block, low value).

## Known sample quirks / deferred bugs
- **fc7a60ad** — NoneType crash during analysis (needs a repro + guard).
- **c7bbc23f** — zero-export DLL: nothing to invoke; decide rundll32 behavior
  for export-less DLLs (skip with reason vs DllMain-only run).
- **agenttesla** — socket drops mid-run (telemetry gaps under load?).
- **mapview Sysmon gap** (deferred 2026-09-11) — InjectionHarness mapview victim
  invisible to Sysmon (no ProcessCreate/EID 8 for its pid; apitrace sees all);
  pre-existing (baseline a16ecb9e fails identically). Suspect event burst +
  snapshot-resume clock skew. Assertion lives in harness_assertions.py.
- **WMI ETW fix** — wmi_etw source robustness.
- **flightsim network validation**.
- Local-mode leftovers: local screenshots, standard-user launch,
  self-extracting installer.
- **DisableRegistryTools historical taint** — pre-fix corpus samples that
  drove reg.exe scored lower than they should have; telemetry is frozen, so
  only re-detonation fixes their verdicts. Identify the affected set during
  the next corpus pass; no bulk re-run planned unless a label matters.
