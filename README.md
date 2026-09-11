# Hyper-V Malware Analysis Sandbox

A snapshot-based dynamic malware analysis sandbox built on an **existing Hyper-V VM**.
The orchestrator never creates or deletes VMs — it reverts the VM to a clean
snapshot, detonates a sample inside it, collects layered telemetry, and produces a
scored JSON verdict with MITRE ATT&CK attribution.

It aims at a production, industry-standard detection bar: Sysmon behavioral telemetry
+ Sigma + YARA + capa + AMSI/Defender, fused into a **transparent additive verdict**,
plus an offline **detection-validation harness** (precision / recall / FPR against a
labeled corpus) so rule and weight changes can't silently regress. Compiled,
argument-level **API tracing** (a MinHook monitor) is in progress.

- **Host:** Python orchestrator (FastAPI) + PowerShell driver over PowerShell Direct.
- **Guest:** Sysmon + collectors, driven per-run; nothing runs on the host.
- **VM:** one existing VM (`pentagramma`) with a `SANDBOX_READY` snapshot.

---

## Detection pipeline

Every detonation is scored by fusing several independent signal sources, each mapped
to MITRE ATT&CK and scoped to the sample's own process lineage:

| Layer | What it does |
|---|---|
| **Sysmon + Sigma** | Behavioral telemetry evaluated against a large vendored Sigma ruleset (`min_level: medium`), incl. `event_count` correlations. |
| **Heuristics** | Hardcoded detectors — activity bursts, dump/dropped-file YARA hits, Defender detections, priority triage. |
| **YARA** | ~5,000+ rules (YARA-Forge core + custom) run on the sample, **memory dumps**, and **dropped files** — per-file compile isolation so one bad rule can't disable the set. |
| **capa** | Capability + ATT&CK/MBC detection on PE samples; high-signal capabilities feed the verdict and widen the coverage matrix. |
| **AMSI / Defender** | Defender is kept **ON** (it's the AMSI provider). Its own detections are surfaced as first-class alerts; a **readiness gate** waits until AMSI is actually armed before detonating. |
| **PID-lineage scoping** | Each alert is classified `in_sample_scope` vs. environment noise. |
| **Verdict** | Transparent **additive** scoring (`orchestrator/verdict.py` + `detectors.py`) → `clean` / `suspicious` / `malicious`, with per-reason contributions. |

Current measured quality on the labeled corpus (109 runs): precision(malicious)
**1.000**, FPR(malicious) **0.000**, recall(suspicious+) **0.989**, FPR(suspicious+)
**0.167** — enforced by a regression gate (see *Detection validation* below).

---

## Prerequisites

1. **Hyper-V enabled** on the host (Windows 10/11 Pro/Enterprise or Server).
2. **The analysis VM** named `pentagramma` (or edit `config/config.yaml → hyperv.analysis_vm`),
   with a snapshot `SANDBOX_READY`.
3. The **golden image** prepared once: Sysmon installed with `agent/windows/sysmonconfig.xml`,
   Python present, Defender **ON**, WDAC/Code-Integrity policy as desired. See *Golden image*
   (automated by `scripts/provision_golden_image.ps1`).
4. **PowerShell Direct** working (host + guest Windows; Integration Services running).
   The orchestrator must run with rights to manage Hyper-V (elevated / Hyper-V Administrators).
5. An **isolated virtual switch** so the VM can't reach production systems.

## Install

```powershell
cd <this repo>
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configure

Everything lives in `config/config.yaml`. Key sections:

```yaml
hyperv:
  analysis_vm: "pentagramma"
  snapshot_name: "SANDBOX_READY"

api:
  host: "127.0.0.1"
  port: 18000

analysis:
  default_timeout_seconds: 120
  vm_startup_timeout_seconds: 240
  defender_readiness_timeout_seconds: 90   # wait until AMSI is armed before detonating (0 disables)

telemetry:
  sources: [sysmon, amsi, powershell, security_log, system_log, defender_log]

sigma:
  enabled: true
  min_level: medium

static_analysis:
  capa:
    enabled: true
```

## Golden image / snapshot

To build a golden image from a **clean pre-existing VM** (Windows installed, admin user
per `config.yaml` + autologon, PowerShell Direct working), run elevated:

```powershell
.\scripts\provision_golden_image.ps1 -PythonInstaller C:\path\python-3.11.x-amd64.exe
# skips available: -SkipPython -SkipDressing -SkipNoiseReduction -SkipGuardian -DefenderOff; -Force recaptures an existing SANDBOX_READY
```

It boots the VM and verify-gates each step: guest Python 3.11 (silent install), agent
deploy to `C:\SandboxAgent`, pip requirements, Sysmon install, audit policy + PowerShell
logging, environment dressing, OS noise reduction (`agent\windows\apply_noise_reduction.py` —
disables updater/telemetry/CEIP/indexer tasks+services; Defender and wuauserv stay),
Defender posture, SandboxGuard driver — then captures
`SANDBOX_READY` only if every verification passes. Manual steps it does NOT do: VM
creation/OS install, user + autologon setup, WDAC/Code-Integrity policy (warns only).

To apply noise reduction to an ALREADY-provisioned image without full reprovisioning:
`POST /api/vm/provision-noise-reduction` (same verify-gated recapture pattern as
`provision-dressing`).

To just (re)capture the snapshot of an already-prepared VM, shut it down cleanly and run:

```powershell
.\scripts\create-snapshot.ps1
# or, with the orchestrator running:
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:18000/api/vm/snapshot
```

One-shot golden-image provisioning steps are exposed as endpoints (e.g. Defender
on/off, ETW-TI autologger) — they restore, boot, apply the change in-guest, verify,
and re-capture the snapshot only if verification passes.

## Run the orchestrator

```powershell
.\start.ps1                       # uvicorn on 127.0.0.1:18000
```

> The orchestrator loads code at startup with no `--reload`; restart it after
> changing anything under `orchestrator/` or `config/`. Guest-side scripts
> (`agent/windows/*`, `scripts/hyperv-vm.ps1`) are re-deployed / re-invoked per run,
> so those take effect without a restart.

## Submit a sample

REST (async job queue — one job at a time, since there's one VM):

```powershell
# async: returns a job_id immediately, poll for progress
$job = Invoke-RestMethod -Method POST -Uri http://127.0.0.1:18000/api/jobs `
  -Form @{ file = Get-Item C:\path\to\sample.exe }
Invoke-RestMethod -Uri "http://127.0.0.1:18000/api/jobs/$($job.job_id)"
Invoke-RestMethod -Uri "http://127.0.0.1:18000/api/reports/$($job.analysis_id)"
```

Or drive it from an agent via the **MCP server** (below), or detonate a whole
directory of samples with `scripts/detonate_corpus.py`.

## Web dashboard

With the orchestrator running, open **http://127.0.0.1:18000/ui/** (or `/`):

- **Dashboard** — VM status, live step-by-step progress of the running job, submit form, recent analyses.
- **Reports** — sortable/filterable history.
- **Report detail** — verdict + reasons, event-count chart, detections grouped by family (Sigma / YARA / **behavioral signatures** / heuristics / static), alerts with source badges and ATT&CK tags, process tree with **📡 API-trace attachment badges**, static analysis (PE sections, strings, YARA, **capa capabilities**, signature), execution stdout/stderr, a paginated raw-event browser (type + source filters), and a network-capture visualizer.
- **Rules catalog** — the active Sigma / YARA / heuristic / **behavioral-signature** / **CAPE community** / static inventory with counts and load-errors; lazy raw-source view.
- **Injection Harness** — per-technique pass/fail for `InjectionHarness.exe` vs. expected Sysmon EID 25 signals.

Plain HTML/CSS/JS, no build step, served from `orchestrator/static/`.

> **Live/interactive VM console:** evaluated, not implemented — a bigger/faster
> passive view is cheap; an interactive browser console (RDP + Guacamole) must
> stay opt-in per job (guest-visible evasion artifact). See
> `docs/interactive-console-streaming.md`.

## Detection validation & tuning

The measurement backbone (all offline — replays saved reports through the **current**
detection logic, no VM needed):

```powershell
# Replay every saved report through today's rules/weights; flag verdict drift
.\.venv\Scripts\python.exe scripts\replay_detection.py --all --changed-only

# Confusion matrix + precision/recall/FPR + per-family + FP drivers over the labeled corpus
.\.venv\Scripts\python.exe scripts\detection_metrics.py

# Sweep verdict thresholds under an FPR budget; prints a recommendation, never edits verdict.py
.\.venv\Scripts\python.exe scripts\calibrate_verdict.py

# Regression gate — fails if recall drops or FPR spikes on the frozen corpus
.\.venv\Scripts\python.exe tests\test_corpus_metrics.py

# Grow the corpus: detonate a directory of samples, then label the resulting reports
.\.venv\Scripts\python.exe scripts\detonate_corpus.py samples\goodware
```

The labeled ground truth lives in `tests/corpus/labels.json` (malicious families +
a `samples/goodware/` benign set for false-positive measurement).

## Vendoring rulesets

Curated rule corpora are vendored via scripts (mirroring `vendor_sigma_rules.py`),
each writing a `.source_label` + `LICENSE` and keeping a project-owned `*_custom/`
sibling out of the wipe-and-refresh path:

```powershell
python scripts\vendor_yara_rules.py <yara-forge-core.yar|dir> yara_rules --source-label <tag>
python scripts\vendor_sigma_rules.py ...
python scripts\vendor_capa_rules.py ...
```

## Behavioral API tracing

A purpose-built compiled monitor (CAPE-style) for argument-level Win32/Native API
tracing, built fresh on **MinHook** (BSD) so it stays license-clean:

- `agent/windows/monitor_src/` — `monitor_x64.dll`/`monitor_x86.dll` (inline hooks → newline-JSON over a named pipe) + `monitor_loader.exe`/`monitor_loader_x86.exe` (launch-suspended → inject → resume; bitness-aware child-following).
- `agent/windows/apitrace_collector.py` — stdlib named-pipe server.
- `orchestrator/behavioral_signatures.py` — 14 hand-written sequence signatures over the apitrace stream (injection chains, cross-process writes/reads, executable-memory transitions, remote thread/APC starts, token manipulation, anti-debug, anti-tamper/unhooking, doppelgänging, PPID spoof, timing/crypto bursts).
- `orchestrator/cape_engine.py` + `cape_signatures/` — the vendored **CAPE community signature corpus** (758 signatures) replayed over the same stream; matches surface as `cape` alerts with severity/family/TTP tags (enrichment only until `cape_signatures.score` is flipped — see `docs/cape-integration.md`).
- `scripts/build_monitor.ps1` — build + stage the binaries into `agent/windows/`.

**Status:** live in-guest with **37 hooks** (file/process/memory/thread/registry
+ loader/timing/crypto + token/anti-debug/transaction/APC surface), x64 **and**
WoW64/x86 monitors with bitness-aware child-following. Behavioral signatures and
CAPE matches feed alerts, the MITRE coverage matrix and (custom signatures only,
for now) the verdict. Network hooks remain the deferred work.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/vm/status` | VM power state and IP |
| POST | `/api/vm/snapshot` / `/api/vm/restore` | Ensure / restore the clean snapshot |
| POST | `/api/analyze` | Upload + analyze a sample (blocks until done) |
| POST | `/api/jobs` | Upload + analyze asynchronously (returns `job_id`) |
| GET | `/api/jobs` · `/api/jobs/{job_id}` | Job list + active job · live step progress |
| GET | `/api/reports` · `/api/reports/list` | Analysis IDs · summarized history |
| GET | `/api/reports/{id}` · `/{id}/summary` · `/{id}/events` | Full report · trimmed · paginated raw events |
| GET | `/api/rules` · `/api/rules/yara/{name}/raw` | Active Sigma/YARA/capa catalog · raw YARA source |
| GET | `/api/reports/{id}/network-summary` · `/network-packets` | pcapng summary · paginated packet browser |
| POST | `/api/vm/provision-defender-on` · `-off` · `provision-etw-ti` | One-shot golden-image provisioning (verify-gated, re-snapshots) |
| POST | `/api/harness/run` | Rebuild + run `InjectionHarness.exe` (needs .NET 8 SDK) |

Only one job runs at a time (one VM); a second submission while one is active returns
`409 Conflict` with the active `job_id`.

## MCP server

`mcp_server/server.py` exposes the orchestrator as MCP tools — `sandbox_health`,
`get_vm_status`, `ensure_clean_snapshot`, `restore_clean_snapshot`, `submit_sample`,
`submit_url`, `get_report`, `list_reports`, `validate_injection_harness`,
`run_injection_harness` — a thin wrapper over the REST API. Start the orchestrator first.

```powershell
# run from the repo root
claude mcp add hyperv-sandbox -- `
  ".venv\Scripts\python.exe" `
  "mcp_server\server.py"
```

Report tools omit the multi-MB raw event stream by default — pass
`include_raw_events=true` (with `max_events`) to fetch it.

## Repository layout

```
orchestrator/     FastAPI app, detection pipeline (sigma_engine, static_analysis,
                  capa_analysis, heuristics, detectors, verdict, reporting, executor,
                  hyperv, mitre_mapping, pid_lineage, ...) + static/ dashboard
agent/windows/    Guest-side collectors (sysmon/amsi/powershell/etw/defender),
                  telemetry_collector.py, defender_manager.py, monitor_src/ (Track 3)
scripts/          hyperv-vm.ps1 driver, vendor_* rule scripts, replay/metrics/
                  calibrate/detonate tooling, build_monitor.ps1
tests/            verdict, sigma, yara, capa, pid-lineage, jobs, detection-quality,
                  corpus-metrics gate + corpus/labels.json
config/           config.yaml
sigma_rules/ · sigma_rules_custom/ · yara_rules/ · yara/ · capa_rules/ · capa_sigs/
mcp_server/       MCP wrapper
reports/ · logs/ · samples/
```

## Tests

```powershell
foreach ($t in Get-ChildItem tests\test_*.py) { .\.venv\Scripts\python.exe $t.FullName }
```

Plain assert scripts with a `main()`. `test_corpus_metrics.py` is the slow
detection-regression gate (replays the labeled corpus); the rest are fast unit tests.

## Safety notes

- The orchestrator **never deletes the VM** — it only reverts the snapshot.
- Samples are copied in via PowerShell Direct / `Copy-VMFile` and **never run on the host**.
- Keep the VM network isolated from production.
- **No anti-VM / anti-debug hardening** is applied (deliberate). Defender stays **ON**
  (AMSI dependency). The golden image runs an enforced WDAC / Code-Integrity policy.
