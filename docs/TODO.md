# PENTAGRAMMA — Work Queue (2026-09-18)

## Done 2026-09-18 (all pushed)
- **Local mode** (`ef8b5ae`, `b7b4184`): host canaries pass (bat clean/0 exit-stop,
  tier1-crypto clean/0, InjectionHarness malicious/90); GUI mode switch
  (`/api/config/mode`, hot-applied); Defender path exclusions on the host.
- **Fleet management** (`b7093c2`): `/api/fleet` (local + all host VMs), per-VM
  credential registry (`hyperv.vms` + GUI-managed `config/vms.yaml`), guest
  instrumentation health (`Get-GuestHealth`, per-VM 30s TTL), Manage modal with
  credential form + 5-step in-place provisioning. Acceptance test: stripped
  pentagramma (Sysmon out, agent dir gone) → rebuilt via API → canary ran →
  reverted to SANDBOX_READY.
- **Streaming** (`53f1dab`): live telemetry tail (`/api/jobs/active/events`,
  byte-offset JSONL read through the LocalMode seam, dashboard panel);
  console per fleet VM (`?vm=`, per-VM ConsoleManager registry, report taint
  only for the run's own VM).
- **Defender self-detection fix** (`53f1dab`): constant-folding put the AMSI
  test string into `defender_manager.cpython-311.pyc`; engine 4.18.26080
  started flagging it mid-run → canary suspicious/25. Fixed (non-foldable
  join + agent-dir heuristic filter); canary back to clean/0 (`dfc87684`).

## Backlog (priority order)

1. **Throwaway-VM local-mode full validation** — real corpus sample + alert
   parity vs hyperv mode, inside a disposable VM (`scripts\install_local.ps1`).
2. **ART detonation batch + coverage audit** — `scripts/detonate_corpus.py
   --worklist out\_art_missing.txt` (55 samples, ~2.5–3h), then
   `scripts/verify_atomic_coverage.py --gaps` → gap tracker.
3. **Real goodware detonations** — 4 `samples/goodware_real/*.exe` (7za, curl,
   plink, rg) staged + labeled.
4. **Fake-C2 / inetsim** (roadmap #1 value) — revives dead-C2 stallers
   (emotet); acceptance = emotet weak-run re-scoring.
5. **Network apitrace hooks** — extend the MinHook monitor to Winsock/network
   APIs (connect/send/recv/WSA*, WinHTTP/WinINet) so C2 behavior gets
   argument-level apitrace coverage, not just Sysmon EID 3/22.
6. **Office golden image** — second analysis VM with Office installed
   (doc/xls/macro samples); becomes fleet member #2 and exercises the per-VM
   credential registry for real.
7. **Fleet next steps** — guest health probing for GUI-registered VMs (vms.yaml
   creds path into fleet probes), Hyper-V MCP adapter (thin, after fleet
   stabilizes), provision a *fresh* VM end-to-end from the GUI.
8. **2 emotet signatures** — from the 09-11 investigation.
9. **Elastic RTA subset** — detection validation corpus.

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
