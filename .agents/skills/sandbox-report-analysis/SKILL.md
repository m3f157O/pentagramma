---
name: sandbox-report-analysis
description: Analyze malware sandbox reports and telemetry produced by this repo's Hyper-V sandbox — explain a verdict/score, triage alerts (Sigma, YARA, behavioral apitrace, CAPE community signatures, heuristics), drill into Sysmon/AMSI/apitrace events, inspect artifacts (screenshots, process dumps, dropped files, PCAP), compare two reports, and measure detection quality over the labeled corpus. Use whenever the task involves reading, explaining, or comparing `reports\*.json` files, investigating why a sample scored a certain way, hunting for IOCs in a detonation, or evaluating detection precision/recall.
---

# Sandbox Report Analysis

How to read and interrogate detonation output. For running samples or operating the VM/orchestrator, use the `sandbox-ops` skill.

## Triage workflow

1. **Start small**: `reports\<id>.summary.json` (11 flat keys: status, alert_count, total_events, runtime, eid25_count, ...) or `GET /api/reports/{id}/summary`.
2. **Trimmed report**: MCP `get_report(analysis_id)` or `GET /api/reports/{id}`. This view keeps sample-scoped alerts inline but omits the raw `events` stream, environment-scoped alerts (count only), and full PE string dumps. Full JSON is on disk at `reports\<id>.json` (21 top-level keys — see `references/report-schema.md`).
3. **Deep dives**: paginate instead of loading the full file —
   - `GET /api/reports/{id}/events?offset=&limit=&source=&event_type=&q=` (sources e.g. `sysmon`, `amsi`, `apitrace`)
   - `GET /api/reports/{id}/alerts?offset=&limit=&scope=sample|environment&event_type=&q=`
   - Offline, load `reports\<id>.json` in Python and filter `report["events"]` / `report["alerts"]` directly.
4. **Artifacts** (per-report endpoints under `/api/reports/{id}/`): `screenshots`, `process-dumps` (+ `/download`), `dropped-files` (+ `/download`), `network-summary` / `network-packets`. Raw files also under `logs\<id>_*` dirs.
5. **Verdict explanation**: `report["verdict"]` = `{score, level, top_reasons[]}` — read top_reasons first; they name the scoring contributions in weight order.

## Alert anatomy — know the families

Every alert has `source`, `event_id`, `event_type`, `timestamp`, `data`, `mitre {primary, candidates}`, `in_sample_scope`. Families:

- **Sigma over Sysmon** (`source: "sysmon"`, `sigma` block with rule id/title/level + rule-specific `mitre_candidates`). Driven by `sigma_rules\` + `sigma_rules_custom\`, gated by `sigma.min_level`.
- **YARA** (`source: "yara"`) — matches on sample, process dumps, dropped files.
- **Behavioral apitrace** (`source: "apitrace"`, event types `Apitrace*`) — the custom hook-based signatures (injection chains, exec protection, tokens, timing, tamper) plus the blind-spot correlation pair: `ApitraceBlindSpot` (high — a Sysmon event had no hooked-API counterpart ⇒ unhooking or direct syscalls) and `ApitraceSilence` (medium — a traced PID went quiet while Sysmon stayed busy). The hook↔Sysmon counterpart mapping lives in `orchestrator\data\coverage_map.yaml` (generated matrix: `docs\coverage-table.md`); server-attached `severity` on all of them.
- **CAPE community** (`source: "cape"` / `provider_name: "CapeSignatures"`, `event_id: 9300`, `event_type: "CapeSignature"`). Metadata lives in `data`: `Name`, `Description`, `SeverityStr`, `Categories`, `Families`, `Evidence`. **`cape_score: false` = visibility-only enrichment; CAPE matches never drive the verdict.** Do not cite them as score reasons.
- **Heuristics** — non-filtering triage hints; add `priority`/`priority_reason` to a subset of alerts.
- **Planned source**: `guardian` (SandboxGuard kernel driver) — hook-restored / protected-access / module-remap events once the driver lands; treat as high-severity tamper signals.

`in_sample_scope: false` = environment/baseline noise (dropped from the trimmed view to a count). Missing key = treated as sample-scoped.

## Verdict semantics

- Additive score over scoring families (Sigma levels, YARA, Defender/AMSI, behavioral severities). Levels: benign < suspicious < malicious; canaries: benign BAT/PS1 = `suspicious/37`, InjectionHarness = `malicious/90`.
- An unexpected score → list contributions via `verdict.top_reasons`, then find the underlying alerts by `event_type`/`source`. To test "what would the verdict be with current code", replay offline instead of re-detonating: `python scripts\replay_detection.py <id> --json`.

## References

- `references/report-schema.md` — full report JSON key-by-key, summary projection, trimmed-view rules, per-family alert shapes. Read when you need exact field names or artifact structures.
- `references/detection-quality.md` — offline tooling: replay_detection, compare_reports, detection_metrics (labeled corpus, train/test splits), calibrate_verdict; baseline expectations. Read before running detection-quality measurements or drift checks.
