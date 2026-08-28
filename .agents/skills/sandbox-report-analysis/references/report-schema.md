# Report schema reference

Ground truth: `orchestrator\report_view.py` (trim/paginate/summarize transforms shared by REST + MCP).

## Full report — `reports\<id>.json` (21 top-level keys)

`report_version`, `analysis_id`, `status`, `error`, `timestamp`, `verdict`, `sample`, `environment`, `summary`, `alerts`, `events`, `mitre_coverage`, `process_tree`, `static_analysis`, `network_capture`, `screenshots`, `process_dumps`, `dropped_files`, `ioc_summary`, `execution_info`, `apitrace`

Key shapes:

- `verdict`: `{score, level: benign|suspicious|malicious, top_reasons: [{weight, reason}]}` — top_reasons are the scoring contributions in weight order; read them first when explaining a verdict.
- `sample`: `{filename, sample_type, hashes: {md5, sha1, sha256}, ...}`.
- `events`: raw merged telemetry stream. Normalized shape: `{source, provider_name, event_id, timestamp, computer, event_type, data}`. Sources: `sysmon`, `apitrace`, `amsi`, `powershell`, `security_log`, `system_log`, `defender_log`, `etw_ti` (if ever enabled), `telemetry_agent`, `guardian` (planned).
  - Sysmon: `data` = all Sysmon XML fields flattened (ProcessId, ProcessGuid, Image, TargetProcessId, TargetFilename, TargetObject, GrantedAccess, CommandLine, ...). **EID 10/8 attribute the target under `TargetProcessId`**; most others under `ProcessId`.
  - Apitrace: `event_id: 9200`, `event_type: "ApiCall"`, `data: {Api, Category, ProcessId, ThreadId, Arg0}`. `Arg0` is a plain string or space-separated `k=v` (parse with `behavioral_signatures._parse_kv`). Meta events in `Api`: `__monitor_attached__`, `__event_cap_reached__`, `__pipe_lost__`, `__wow64_follow__`.
- `alerts`: detection output. Common keys: `source`, `provider_name`, `event_id`, `event_type`, `timestamp`, `severity` (behavioral+cape), `data`, `mitre: {primary, candidates}`, `in_sample_scope` (false = environment noise; missing = treated as sample-scoped). Per-family extras:
  - Sigma: `sigma` block (rule id/title/level, `mitre_candidates`).
  - Behavioral: `provider_name: "BehavioralSignatures"`, `event_type: "Apitrace*"`.
  - CAPE: `source: "cape"`, `event_id: 9300`, `event_type: "CapeSignature"`, `cape_score: false`, metadata in `data` (`Name`, `Description`, `SeverityStr`, `Categories`, `Families`, `Evidence`).
- `execution_info`: `{ProcessId, LauncherPath, Stdout, Stderr, ExitCode, ...}` — sample stdout/stderr live here.
- `mitre_coverage`: ATT&CK technique rollup over alerts.
- `process_tree`: process hierarchy from ProcessCreate events.
- `static_analysis`: hashes, entropy, PE parse, YARA matches, capa results, `strings: {interesting, ascii[], unicode[]}` (big).
- `network_capture` / `screenshots` / `process_dumps` / `dropped_files`: artifact metadata + per-artifact indices (download via API or `logs\<id>_*` dirs).
- `ioc_summary`: extracted IPs/domains/paths/mutexes rollup.

## Trimmed view (MCP `get_report`, `GET /api/reports/{id}`)

`trim_report()` drops: `events` (→ `events_total` + `events_omitted`, unless `include_raw_events=true` → first `max_events` + `events_truncated`), environment-scoped alerts (→ `environment_alerts_total` + `environment_alerts_omitted`; sample-scoped stay inline), and `static_analysis.strings.ascii/unicode` (→ counts; `interesting` kept).

## Summary projection — `reports\<id>.summary.json`, `GET /api/reports/{id}/summary`

Flat, 11 keys: `analysis_id, timestamp, filename, sample_type, sha256_short, status, alert_count, total_events, runtime_seconds, eid25_count, is_injection_harness`.

## Pagination endpoints

- `GET /api/reports/{id}/events?offset=&limit=&source=&event_type=&q=` — returns `{total, filtered_total, sources[], events[]}`.
- `GET /api/reports/{id}/alerts?offset=&limit=&scope=sample|environment&event_type=&q=`.
- Artifacts: `.../screenshots[/{idx}]`, `.../process-dumps[/{idx}/download]`, `.../dropped-files[/{idx}/download]`, `.../network-summary`, `.../network-packets[/{idx}]`, `.../harness-validation`.
