# UI overhaul plan — telemetry-modular dashboard

Goal: make every telemetry module (Sysmon EID families, API trace, AMSI,
PowerShell, event logs, network, artifacts) a clearly separate, first-class
view, and pay down the UI debt found during the study.

Backup of the pre-overhaul frontend: `backups\static-20260819-0929\`
(17 files, all 6 pages + css + js + vendor).

Validated against the live system (2026-08-19):

- Events carry `source` (sysmon/amsi/apitrace/powershell/security/system/
  windefend) AND structured `event_type`+`event_id` for Sysmon
  (ProcessCreate/1, ImageLoad/7, CreateRemoteThread/8, ProcessAccess/10,
  ProcessTampering/25, ...) -> per-EID-family tabs need only the existing
  `/events` endpoint + one small server tweak (multi-value `event_type`).
- AMSI events carry full `Content` + `ScanResult`; PowerShell
  `ScriptBlockLogged` events carry `ScriptBlockText` + MessageNumber/Total +
  ScriptBlockId (fragment reassembly is client-side). Scripts tab needs NO
  new endpoint.
- `summarize_report()` has NO verdict fields -> verdict columns on the
  Dashboard/Reports lists need a 2-line server addition (report dict already
  contains `verdict.level/score`).
- `/harness-validation` already returns all 9 techniques dynamically, with a
  per-technique shape that differs by spec kind: behavioral specs expose
  `expected_alert`, event specs expose `expected_event_id` +
  `expected_type_fragments` + `pid_field`. Current `harness.js` reads
  `t.expected_type_fragment` (singular) which no longer exists -> the
  "Expected signal" column currently renders `undefined`. Pure JS fix.
- Hookset: `coverage_map.yaml` already has one curated entry per kHooks[]
  item (api, hook_module, category, coverage, counterparts). Serving it via
  a new `/api/hookset` endpoint removes the third hand-mirrored copy
  (HOOKSET in report_detail.js). Category descriptions get added to the yaml
  (top-level `category_descriptions:` map).

## Phase 1 — server changes (ONE orchestrator restart, batched)

All in `orchestrator/`, small and additive:

1. `report_view.py::summarize_report`: add `verdict_level`, `verdict_score`
   (null for pre-verdict reports).
2. `report_view.py::paginate_events` + `main.py` events endpoint: accept
   comma-separated `event_type` (e.g. `event_type=ImageLoad,CreateRemoteThread,ProcessAccess,ProcessTampering`).
3. `main.py`: new `GET /api/hookset` — parses `orchestrator/data/coverage_map.yaml`,
   returns hooks grouped by category with coverage class, counterparts, and
   category descriptions.
4. `orchestrator/data/coverage_map.yaml`: add `category_descriptions` map
   (text currently living in the JS HOOKSET constant, moved to the curated
   source of truth). Extend `tests/test_coverage_map.py` to validate it.

Old-UI compatibility is kept throughout (additive fields only).

## Phase 2 — report page restructure (static, the core)

Header + right rail stay as-is (verdict card, sample, event counts, process
tree, detections summary — hard-won, cross-referenced, low risk). The 15-chip
flat section area becomes **grouped telemetry tabs**. New shared component
`js/event_browser.js` (~150 lines, extracted from today's `loadEvents`):
server-paginated event table parameterized by (sources, event_types, column
renderer, search). Every telemetry tab is an instance of it.

New tab layout (chips visually grouped, counts kept):

| Group | Tabs |
|---|---|
| Findings | Alerts (unchanged browser) · MITRE |
| Telemetry | **Injection & memory** (EID 7/8/9/10/25) · API trace (hookset from `/api/hookset`) · **Blind spots** (ApitraceBlindSpot/Silence alerts + coverage-class summary) · **Scripts** (AMSI + PS script blocks) · **Processes** (EID 1/5 + execution output) · **Filesystem** (EID 2/11/15/23/26 + dropped files) · **Registry** (EID 12/13/14 + persistence IOCs) · **Event logs** (security/system/windefend, multi-source) · **Sysmon other** (EID 6/17/18/19-21/24/27-29/255) |
| Network | one merged tab: connections/domains/HTTP IOC lists + capture stats + packet browser (today's 4 IOC sections + network section collapse into one) |
| Artifacts | Screenshots · Dumps |
| Analysis | Static · Detections-by-engine (full-width version of the rail summary) · Env noise · Raw events (firehose, unchanged) |

Deep-linking via `#tab=scripts` hash (nice-to-have, cheap).

## Phase 3 — other pages + debt fixes (static)

1. **Mojibake sweep**: index/reports/report/rules/harness .html — replace
   double-encoded literals (`Â·`, `â€¦`, `â—€`, `â†'`) with HTML entities
   (architecture.html already does this correctly). Strip the stray BOMs.
2. **Cache-buster unification**: every shared asset gets one fresh version
   across ALL pages (style.css, api.js, poll.js).
3. **reports.html / index.html**: verdict badge column (renders "-" when the
   field is absent, so it works pre-restart too).
4. **harness.html/js**: dynamic techniques — latest-run table iterates
   `validation.techniques` (label map with key fallback), expected-signal
   cell renders `expected_alert` OR `EID n / fragments / pid_field`, trend
   table columns built from the union of techniques across the 10 runs,
   intro text updated (no longer "EID 25 signals" only).
5. **index.html**: replace `alert()` snapshot confirmations with inline
   status text.
6. rules.html and architecture.html: no structural change.

## Execution order (restart math)

1. Phase 1 server changes -> I verify with replay/unit-style checks that
   don't need the server (yaml parse, summarize/paginate functions).
2. **User restarts orchestrator** (one time) -> I verify the 3 new/changed
   endpoints with Invoke-WebRequest.
3. Phases 0/2/3 static work -> live on browser refresh. JS syntax-checked
   with `node --check`; pages smoke-checked with Invoke-WebRequest (200 +
   expected markers).
4. Final: bump cache-busters, user hard-refreshes; I walk through each page
   via HTTP checks and fix anything found.

## Out of scope (deliberately)

- No framework/build step; no visual redesign (theme, colors, layout
  mechanics stay).
- architecture.html guardian badges (flip when WS-A lands).
- Cross-source timeline view (defer — needs design input; the per-module
  tabs deliver 90% of the value).
- No changes to detection code, report schema, or trimming behavior.
