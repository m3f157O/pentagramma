---
name: sandbox-ops
description: Operate the Hyper-V malware sandbox in this repo — check VM/orchestrator health, manage the SANDBOX_READY snapshot, submit samples/URLs for detonation via the hyperv-sandbox MCP tools, run the InjectionHarness, restart/reload the orchestrator correctly, and validate detection-pipeline changes against the canary samples. Use whenever the task involves running a sample in the sandbox, starting/stopping/restarting the orchestrator or VM, verifying a detection change end-to-end, or running the project's test scripts.
---

# Sandbox Ops

Operational knowledge for the Hyper-V malware sandbox (this repo). For interpreting reports after a run, use the `sandbox-report-analysis` skill.

## Topology

- Orchestrator: FastAPI/uvicorn on `http://127.0.0.1:18000`, started elevated via `start.ps1`. UI at `/ui/`, API under `/api/`.
- VM: `pentagramma`, snapshot `SANDBOX_READY` (reverted automatically per run). Guest agent dir `C:\SandboxAgent`, sample drop folder `C:\Sandbox`.
- Python: `.venv\Scripts\python.exe`. Config: `config\config.yaml`.

## Orchestrator lifecycle — read before touching processes

- The orchestrator runs **elevated**; the agent CANNOT stop or restart it (`Stop-Process` → Access denied). Always ask the user to restart it (rerun `start.ps1`).
- Changes under `orchestrator/`, `mcp_server/`, or `config/` require a restart to take effect — there is no `--reload`.
- Static UI files (`orchestrator/static/`) are served from disk: they go live on browser refresh, no restart. When editing JS/CSS, bump the `?v=N` cache-buster in every HTML file that references the file.
- Verify what the RUNNING server actually serves with `Invoke-WebRequest http://127.0.0.1:18000/api/...` — never assume a just-written endpoint is live.

## MCP tools (hyperv-sandbox)

- Call `sandbox_health` first; if it fails, the orchestrator is down — do not retry detonations, tell the user to start it.
- `submit_sample(sample_path, ...)`: uploads and detonates. **The MCP call usually times out client-side; the server-side run may be cancelled on disconnect** — the robust path is a direct POST from a background shell task instead: `curl.exe -s -X POST -F "file=@<path>" -F "timeout=300" --max-time 850 -o out\run.json http://127.0.0.1:18000/api/analyze`, then read `analysis_id` from `out\run.json` (or poll `reports\*.summary.json`). Never re-submit blindly — check whether the first run landed.
- Harness loop: rebuild `samples\InjectionHarness\InjectionHarness` with `dotnet publish -r win-x64 -c Release /p:PublishSingleFile=true /p:SelfContained=true`, detonate via the curl path, then validate offline: `python scripts\harness_assertions.py reports\<id>.json` (specs mirrored in `orchestrator\harness_validation.py` — keep both in sync; two spec kinds: Sysmon EID+pid_field and behavioral alert fragment).
- `submit_url(url, url_mode)`: `browse` = open in guest browser (drive-by behavior); `fetch` = curl.exe download (payload lands in `dropped_files`).
- `get_report` / `list_reports`: report retrieval; raw events omitted unless `include_raw_events=true`.
- `restore_clean_snapshot` / `ensure_clean_snapshot`: manual VM state ops; normally unnecessary (per-run revert is automatic).
- Golden-image provisioning endpoints (`POST /api/vm/provision-*`): verify-gated recapture pattern — the snapshot is only re-baked when guest verification passes. `provision-dressing` applies/ refreshes the anti-sandbox user environment (`docs\environment-dressing.md`).
- To build a golden image from a CLEAN pre-existing VM: elevated `scripts\provision_golden_image.ps1 -PythonInstaller <python-3.11.x-amd64.exe>` (verify-gated; snapshot captured only if all steps pass; manual prereqs: OS install, admin user + autologon, WDAC policy).
- `run_injection_harness`: rebuilds harness from source + runs (needs .NET 8 SDK, elevation). If a built `InjectionHarness.exe` already exists, prefer `submit_sample` + `validate_injection_harness`.

## Change-validation protocol (canary contract)

After ANY change to the detection pipeline (detectors, behavioral signatures, sigma/CAPE/YARA rules, scoring, monitor/hookset):

1. Detonate the benign pair: `test-sample.bat` and `test-tier1-crypto.ps1`. Both must stay `clean` with **zero behavioral (apitrace) alerts**. Expected scores: **0** for test-sample.bat; **≤8** for test-tier1-crypto.ps1 (its own powershell.exe ImageLoads + PSHost pipe = the baseline class deliberately kept per the stay-aggressive stance; 8 observed 2026-09-11). For test-sample.bat, any score above 0 = investigate the new `scope_reason`-less in-scope alerts first. Also check `execution_info.StoppedEarly`: both benign canaries should be `'exit'` (adaptive detonation window, see `docs/adaptive-detonation-window.md` — tree exit-stop with 30s floor, idle-stop only for silent stallers, injected-process adoption). If a benign canary shows `'idle'`, the tree tracking is broken (first bug of this class: `$refreshed -ne $null` filter-semantics on an empty array — keep `$null` LEFT in such guards).
2. Detonate `InjectionHarness.exe`. It must stay `malicious/90`.
3. Cross-check guest runs offline: `python scripts\replay_detection.py <id> --json`. The running server may execute stale code (pending restart); replay always uses on-disk code. Divergence = stale server, not a detection change.
4. Run the relevant test scripts (see below).
5. Never trust a single run's score without the replay cross-check.

## Tests and housekeeping

- No pytest. Tests are plain assert scripts: `.venv\Scripts\python.exe tests\test_<name>.py`. Suites exist for behavioral signatures, CAPE engine, sigma engine/correlation, verdict, capa, YARA loading, PID lineage, jobs, corpus metrics, detection quality.
- PowerShell heredoc pitfall: inline `python -c` with f-strings/quotes breaks. Write throwaway scripts as `scripts\_<name>.py` and run them. Watch for UTF-8 BOM if PowerShell rewrites a Python file — read with `encoding='utf-8-sig'`.
- Config knobs that matter: `analysis.timeout` (default 120s, max 600), `sigma.min_level`, `cape_signatures.score` (**false** — enrichment-only until corpus validation; do not flip without the checklist in `docs\cape-integration.md`), telemetry source toggles.
- Adding a hook (`kHooks[]` in monitor.cpp) or a Sysmon EID? Curate `orchestrator\data\coverage_map.yaml` and regenerate: `python scripts\build_coverage_table.py` — `tests\test_coverage_map.py` fails the build otherwise.
- Do not run `git commit/push/reset` unless the user explicitly asks.
