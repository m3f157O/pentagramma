# CAPE Community-Signature Integration

**Status:** Implemented 2026-07-27 — matches flow as **enrichment/attribution
alerts only** (`cape_signatures.score: false`). Verdict scoring is gated until
corpus validation passes (see "Enabling scoring" below).

## What it is

The vendored [CAPE community signature corpus](https://github.com/CAPESandbox/community)
(458 modules → **758 unique signature classes**) replayed over our apitrace
stream — the same detection corpus CAPE/Triage users curate, without a CAPE
deployment. Every detonation's `ApiCall` events are translated into the
Cuckoo results model and run through all signatures; each match becomes a
`CapeSignature` alert with per-signature severity, families, and TTP tags.

## Architecture

| Piece | File |
|---|---|
| Compat layer (dependency-free extraction of CAPEv2's `Signature` base + stub `lib.cuckoo.common.*` modules) | `orchestrator/cape_compat.py` |
| Engine (loader, apitrace→Cuckoo model translation, CAPE-exact dispatch, alert shaping, config singleton) | `orchestrator/cape_engine.py` |
| Vendored corpus (+ provenance) | `cape_signatures/` (`.source_label`) |
| Verdict classification (`CapeSignature` branch, score gate) | `orchestrator/detectors.py` |
| Pipeline wiring (one alert-assembly path) | `orchestrator/reporting.py::compute_detection` |
| Config | `config/config.yaml::cape_signatures` |
| UI (rules catalog CAPE tab, report "Detections applied" family block, severity dots) | `orchestrator/static/{rules.html,js/rules.js,js/report_detail.js}` |
| Tests | `tests/test_cape_engine.py` (11 tests) |

**CAPE-exact semantics** (mirrors `lib/cuckoo/core/plugins.py::RunSignatures`):
a signature is *evented* only if it overrides `on_call` (everything else runs
via `run()`, including `evented = True` classes that don't); `on_call`
returning truthy marks the signature matched and skips `on_complete`;
non-evented matches are decided by `run()`'s return value.

**Telemetry mapping:** Nt-level API names match `filter_apinames` through an
alias table (`NtWriteVirtualMemory` ⇄ `WriteProcessMemory`, …); `call["api"]`
always stays the true hooked name. Arguments are normalized to exact CAPE
conventions (`Protection="0x00000040"`, `NewAccessProtection`, `BaseAddress`,
`Size`, `StartAddress`, synthesized `ProcessHandle` — `0xffffffff` for
same-process calls, which community injection sigs explicitly exclude).

## FP guards (both validated on live guest runs)

1. **Lineage-scoped summaries.** `executed_commands`/files/keys summaries are
   built only from the sample's own process tree (`pid_lineage`). Without
   this, command-scanning summary sigs (`clears_logs`,
   `suspicious_command_tools`, `dotnet_csc_build`, …) fired **identically on
   benign and malicious runs** — they were matching the sandbox's own guest
   tooling.
2. **Spawn-artifact exclusion.** `NtWriteVirtualMemory`/`NtResumeThread`
   targeting the actor's own just-created child (per the monitor's own
   `child_pid=` events — same-stream lineage) are dropped from the model:
   kernel32's CreateProcess parameter-block write is spawning noise, not
   injection (`injection_write_process` FP'd on a benign .bat without this).

## Coverage reality (measured, `_cape_coverage_estimate.py`)

- 758 loaded (4 load errors, network-only deps) — 521 (69%) statically
  reachable with the 37-hook set, 153 need unhooked API families, 41 need
  network results, 43 need disk/YARA result blocks.
- "Reachable" overstates it: sigs needing OpenProcess handle sequences,
  buffer contents, or return values can't match. Expect a handful of
  matches per run, not dozens.
- Value today: **breadth heuristics + family attribution + TTP tags** — the
  overlap with our 14 custom signatures + Sigma is high on the current
  19-script corpus; the payoff comes with the Workstream-A real corpus.

## Enabling scoring (checklist)

1. `cape_signatures.score: true` in `config/config.yaml` → matches get
   `cape_score: true` and `detectors.py` classifies them
   (sev 1→low/3, 2→medium/8, ≥3→high/15; group_key per signature name).
2. Before flipping: `scripts/replay_detection.py --all --changed-only` and
   `scripts/detection_metrics.py` on the labeled corpus must show no FPR
   regression; `tests/test_corpus_metrics.py` is the gate.
3. Expect double-counting with our own signatures for shared behaviors
   (e.g. `injection_rwx` ↔ `ApitraceExecProtection`) — accepted, same as
   Sigma/heuristics overlap; revisit if calibration shows inflation.

## Known limitations

- No network block (Suricata/DNS/threat-intel lookups stubbed off offline).
- `results["info"]["package"]` is hardcoded `"exe"`; target metadata minimal.
- Signature refresh = re-vendor `cape_signatures/` from upstream master
  (keep `.source_label` in sync).
