# PENTAGRAMMA — Development Timeline & Blog Series Plan

**Compiled:** 2026-09-05 (recovered from session `2f940f78` research; sources: git log, `docs/*.md`, README, handoffs)
**Purpose:** master chronology of the sandbox project + index for a blog series.

---

## 1. Timeline index by component

| Component | Started | Key milestones | State |
|---|---|---|---|
| **Orchestrator & guest agent** | 2026-06-15 | Hyper-V VM lifecycle, snapshot revert, Sysmon/pipe telemetry ingest, verdict engine, web UI | Core stable; FastAPI on :18000 |
| **Sysmon/ETW telemetry** | 2026-06-16 | Sysmon chosen as primary (07-01); config-tag bug fix (07-21); AMSI + PS script-block; WMI-Activity ETW (09-04) | Mature; ETW = gap-filler only |
| **Apitrace monitor (user-mode hooks)** | 2026-07-26 | 11 → 18 → 33 → 37 hooks over 3 days (07-26/27); WoW64 x86 DLL; anti-tamper detection | 37 hooks, x64+x86, 14 hand-written signatures |
| **CAPE community signatures** | 2026-07-27 | 458 modules → 758 signature classes, enrichment-only replay over apitrace | 521/758 statically reachable |
| **Static analysis (YARA/capa/.NET)** | 2026-07-18 | capa (07-18); YARA-Forge extended 10,763 rules (09-04); dnfile .NET analysis (09-04) | Integrated, overlapped with VM window |
| **Environment dressing** | 2026-07-27 | Decoy docs, Edge history, RunMRU/TypedPaths in golden image | Done; uptime can't be faked (accepted) |
| **Injection harness & coverage** | 2026-06-16 | 11 techniques + Phase-2 (08-17): AtomBombing, module overloading, SetWindowsHookEx, MapView… | Live-asserted regression suite |
| **Guardian kernel driver** | 2026-08-19 | Design (08-19) → A0 spike (09-01) → A1a (09-01) → A2 in golden image (09-02) → A4 closed (09-03) | Protect/verify/place, Verifier-soaked |
| **Interactive browser console** | 2026-09-03 | WMI thumbnail frames + named-pipe input; PSDirect proven non-interactive | Working E2E (msgbox clicked via browser) |
| **Corpus & ground-truth validation** | 2026-07-26 | Real corpus plan (07-26); 138-sample abuse.ch batch (09-04/05); forced-entry re-run done (09-11); 152 labels, stratified splits; gate PASS recall 1.000 / FPR 0.000 (09-12) | Stable; ART batch queued |
| **Adaptive detonation window** | 2026-09-11 | Tree exit-stop + apitrace idle-stop; lineage v2 injected-host adoption; min-runtime floor; live-validated (09-11/12) | Stable; StoppedEarly in reports |
| **Multi-file zip staging** | 2026-09-11 | All archive entries extracted into guest working dir (roadmap #3); staging manifest in report; live-validated (09-12) | Done; phase-2 static-analysis deferred |
| **Performance** | 2026-09-04 | Sigma literal-anchor prefilter (1.2–2.4×), static/VM overlap | Committed; activates on next restart |

---

## 2. Chronological master timeline

### 2026-06-15/16 — Foundations
- Orchestrator + guest agent + MinHook monitor + web UI exist (pre-git; git history starts 08-28 with a squashed "PENTAGRAMMA" commit).
- **PLAN.md (06-16):** "Sandbox Injection / Evasion Coverage" — phases 0–9, ~25–33 day estimate. Targets: EID 25 tampering, 6 more injection techniques, ETW/AMSI/CLR patching, broader Sysmon config, persistence suite, MITRE mapping.
- **sysmon-255-investigation:** every harness run emits exactly 2 Sysmon EID 255 → root-caused to process ghosting (file deleted before image-name resolution). Kept as corroborating signal.

### 2026-07-01 — Telemetry architecture decision
- **Sysmon = primary telemetry; ETW only as gap-filler.** Full coverage matrix; 5 ETW providers worth keeping (ETW-TI, AMSI, PS script-block, Defender, .NET runtime).
- Empirically corrected the AMSI ETW provider GUID (`{2a576b87-...}` — commonly-cited GUIDs are third-party providers).

### 2026-07-21 — The config that never worked
- **Critical bug:** Sysmon config used invalid XML tag names for registry/pipe/WMI — *eight event IDs had almost certainly never produced a single event*. Fixed → `persistence_runkey.ps1` yielded 22,840 RegistryCreateDelete + 1,410 RegistryValueSet; named-pipe C2 test → 81 PipeCreated + 81 PipeConnected. WMI stayed zero (Sysmon/build limitation → later solved with ETW, 09-04).
- Same pass: ImageLoad alerts 1,307 → 113 (conditional alerting); .NET stdout-redirection deadlock fixed (15s false-timeout → 0.33s); NetworkConnect/DnsQuery wired into alerts+MITRE; AMSI + script-block logging live-verified; **ETW-TI declared infeasible** (needs PPL with Microsoft Antimalware-Light signer).

### 2026-07-26/27 — The honest-metrics pivot + hook explosion
- **Corpus doc (07-26):** diagnosed headline metrics (precision 1.000 / recall 0.989) as *in-sample fit on 19 hand-curated scripts* — no held-out set, no CIs. Spawned the real-corpus workstream (→ the 138-sample batch 6 weeks later).
- **Hooks 11 → 37 in two days:** Tier-1 (18: loader/timing/crypto), Tier-1.5 + WoW64 (33: APC, token, cross-read, hollowing, anti-debug; `monitor_x86.dll`), Tier-2 (37: address emission, ApitraceAntiTamper for ntdll/amsi unhooking, timer-APC arm (Ekko/Foliage), TransactionAbuse, PpidSpoof).
- Stability: SEH safe-reads, CRT-free TID-table guard (10/10 → 0/10 crash repro); benign FP score 70 → 37; exec-alloc threshold 30→100 after measuring CLR's 62 benign RWX allocs.
- **CAPE integration (07-27):** 458 community modules → 758 signature classes replayed over apitrace, enrichment-only (verdict-gated pending corpus validation). 521/758 statically reachable.
- **Environment dressing (07-27):** ~15 decoy documents, Edge history/bookmarks, RunMRU/TypedPaths, verify-gated golden-image recapture.

### 2026-08-17 — Coverage matrix + harness Phase-2
- API-by-API apitrace↔Sysmon coverage table (37 hooks); residual gap class: direct syscalls w/ remapped ntdll, KnownDlls remapping, in-process memcpy.
- Harness extended: AtomBombing, module overloading, SetWindowsHookEx, NtQueueApcThreadEx, MapView injection — all live-asserted.
- Empirical findings: **process hollowing produces no EID 25** (Sysmon tamper check only sees FILE-based tampering); classic herpaderping blocked on modern Windows (file lock); thread-pool injection not implementable (PoolParty-only).

### 2026-08-19 — UI overhaul + the kernel decision
- Grouped telemetry tabs planned (validated against live system); pre-overhaul backup taken.
- **Guardian scope set:** one kernel driver, three roles — *protect* (Ob/Cm/minifilter), *verify* (hook-integrity), *place* (APC→LoadLibraryW injection).

### 2026-09-01 → 09-03 — Guardian driver, spike to closure
- **A0 (09-01):** testsigning, driver loads, PING handshake, process-create capture. GO.
- **A1a (09-01):** Ob access-strip, Cm registry protection, module-remap detection, pre-entry placement — 7/7 PASS. Bugs: 0x7E BSOD (swapped CmRegisterCallbackEx args), 64-bit truncation, drain paging.
- **A2 (09-02):** baked into golden image; canaries exact-baseline green. Bugs: boot-armed Cm protection blocked own telemetry_init (benign flipped malicious/45), provision reboot race.
- **A4 (09-03):** tamper canary — all protected actions denied (only telemetry-file delete succeeded → minifilter deferred); **direct-syscall-spawn proof**: raw `NtCreateUserProcess` (halos-gate SSN recovery past own hooks) still got the monitor placed by the driver; 20-run stability gate 15/20 (5 failures = 2 host OOM + 3 tooling-attribution verdict flaps → fixed via ProcessGuid-tree lineage; benign 37→12); WoW64 placement closed; **Driver Verifier soak: all PASS, no bugchecks.**
- **Interactive console (09-03):** key finding — **PSDirect sessions are non-interactive** (MessageBox never visible). Built instead: WMI thumbnail frames (~0.7 fps) + input via named pipe into interactive session (scheduled task as gigi). No RDP/VNC. E2E validated: msgbox clicked from the browser.

### 2026-09-04 — Detection-coverage pack + perf pack + GUI round
- YARA-Forge **extended** vendored: **10,763 compiled rules** (vs 5,174 core).
- `parse_dotnet()` .NET static analysis (dnfile; obfuscator markers).
- `NetworkBurstDetected` (EID 9105): port scan ≥15 ports, connection/DNS floods, DNS tunneling — zero verdict drift.
- Dropped-file gap closed: deep static re-analysis + Sysmon `C:\SandboxArchive` deleted-file retrieval (live-validated on self-cleaning dropper).
- WMI-Activity ETW collector (5857–5861) — finally covers what Sysmon EID 19–21 never could on this guest.
- **Perf:** Sigma literal-anchor prefilter (1,105/1,859 rules anchored, byte-identical alerts, 88s → 33s on an 83k-event report); static analysis overlapped with the VM window.
- **GUI visibility round:** WMI tab, alert-scope fix, severity fallback for 1,400+ alerts, network triage badges (DGA/OS-noise); SysmonEvent16 gap found via 30-report/1.7M-event empirical audit.

### 2026-09-04/05 — The 138-sample ground-truth batch
- Real malware corpus (abuse.ch): agenttesla 17, asyncrat 24, emotet 52, qakbot 24, redline 1, remcos 20. ~10h unattended batch.
- **Result: of the 107 runs where the sample actually executed — 95 malicious (89%) + 12 suspicious (11%) + 0 clean. Zero false negatives on real executions.**
- The 26 "clean" reports were DLL *launch* failures (ambiguous rundll32 entry point), not detection misses → 31-sample forced-entry-point re-run (running as of 09-05 morning).
- Genuine follow-ups: emotet (9/47 only suspicious, avg 63), qakbot (weak but tiny sample), one low remcos outlier.

### 2026-09-09 — Golden-image provisioning + housekeeping
- `provision_golden_image.ps1`: clean-VM → golden image, verify-gated; `install_guardian -NoRestore/-NoRecapture`; verify-gated `SandboxArchive` cleanup (`POST /api/vm/provision-clean-archive`) — the ~8.5 GB residue thread closed.
- VM references renamed bande nere → **pentagramma**; username scrubbed from tracked paths.

### 2026-09-11 — Emotet resolved, noise reduction, adaptive window, zip staging, eval tooling
- **Emotet investigation closed (`9ec0ac0`):** the 10 weak runs are behaviorally inert (unpack → dead-C2 retry → idle/exit) — environment starvation, not a detection gap. Real remedy = fake-C2/inetsim (roadmap #1). Tooling harvest: 200KB-head `json.loads` truncation had silently skipped all large reports (labels **19 → 152**); MITRE-overlap key bug fixed (**132/133** family checks pass); latest-report-per-sha supersession in metrics. 152 labels, stratified train/test splits.
- **Noise + FP pass (`46194dc`):** OS-noise reduction across sysmonconfig/Guardian/provision (live-validated, canary clean/0, **events −64%**); tooling-FP suppression (monitor-injection artifacts, dump-YARA interpreter-memory exclusion, `suspicious_powershell_download` context regexes); **two-tier goodware labels** (`goodware` must stay clean vs `goodware_boundary` susp-tolerated, boundary-malicious = gate failure); ART corpus builder + coverage verifier; Splunk attack-data → Sigma offline validator (full run: **276/339 datasets covered**, 448 rules, 63 zero-match triaged).
- **Adaptive detonation window (`735ca57` + hardening `5c3165c`):** sample-tree exit-stop (Win32_Process BFS @1Hz) + apitrace-silence idle-stop (dead-C2 staller class; final dump preserved); **lineage v2** — monitor publishes attached pids (`apitrace.jsonl.pids` @1Hz), injected-into hosts adopted as extra tree roots (counted, never killed); 30s min-runtime floor. Fixed a PowerShell `$null`-guard filter-semantics bug found by the canary. Validated: canary clean/0 exit-stop (225→**118s**), tier1-crypto clean/8, InjectionHarness malicious/90 (idle variant, AdoptedPidsMax=36), staller idle-stop 95s/300s. Corpus gate PASS: 27 runs, **recall 1.000 / FPR 0.000 / precision 1.000**.
- **Multi-file zip staging — roadmap #3 (`8b38782` + `ac597a8`):** every zip entry re-packed under sanitized relative paths (zip-slip-proof by construction, AES fallback) → guest `Expand-Archive` into the working dir before launch; fail-open to single-file; `sample.staging` manifest in report (was silently dropped by the report whitelist — fixed). Live-validated 09-12: sibling-DLL + nested-config markers resolved in-guest (`SIBLING_DLL_OK`, `NESTED_CONFIG_OK`).

### 2026-09-12 — The recycled-PID false positive
- First live trigger of the `ApitraceBlindSpot` correlator (+15) fired on the *benign canary* (suspicious/15): certutil child pid 7964 attached/exited, OS reused the pid for an unrelated powershell → 82 ImageLoad + 4 FileCreate judged against certutil's stale apitrace slot → 86 phantom misses. Fix (`5559ad8`): a second Sysmon EID 1 for a pid strictly after monitor-attach marks the new, untracked incarnation; its events are excluded. Replay: suspicious/15 → clean/0. +1 regression test; 137 unit tests green; corpus gate re-run PASS.

---

## 3. Blog series outline

**Draft skeletons:** `blog/README.md` (11 sample pages, 2026-09-05; +4 posts 2026-09-12 covering the work below).

Proposed posts, in narrative order. Each maps to a self-contained story with a hook, an empirical finding, and a takeaway.

| # | Post (working title) | Core material | Hook |
|---|---|---|---|
| 1 | **Building a malware sandbox on Hyper-V from scratch** | 06-15→07-01: orchestrator, guest agent, snapshot lifecycle, Sysmon-over-ETW decision | Why not VirtualBox/VMware; why Sysmon as spine |
| 2 | **The Sysmon config that silently never worked** | 07-21 tag-name bug; 8 EIDs dead for weeks | "22,840 events appeared after a one-word fix" — validation by detonation, not by schema |
| 3 | **37 hooks in 48 hours: designing an apitrace monitor** | 07-26/27 tiers, crash repro, CLR RWX false-positive measurement | FP-driven engineering: measure the benign before flagging the malicious |
| 4 | **Replaying 758 CAPE signatures offline** | 07-27 CAPE engine, reachability analysis, FP guards | Community detections as free enrichment |
| 5 | **Teaching the sandbox to lie: environment dressing** | 07-27 dressing | Anti-anti-sandbox arms race |
| 6 | **What Sysmon can't see: injection techniques empirically tested** | 08-17 harness Phase-2; hollowing→no EID 25; herpaderping blocked by OS | Published-behavior vs measured behavior |
| 7 | **Writing a kernel driver to protect a malware sandbox** | 08-19→09-03 Guardian A0–A4: BSODs, tamper canary, Verifier soak | The malware tried to kill our telemetry; the driver said no |
| 8 | **Beating direct syscalls: kernel-side injection placement** | A4 `syscall_spawn.exe` halos-gate test | User-mode hooks are optional; kernel placement isn't |
| 9 | **A remote desktop for malware: clicking message boxes from the browser** | 09-03 console; PSDirect non-interactive finding | WMI thumbnails + named pipes, no RDP |
| 10 | **Speed-running Sigma: a literal-anchor prefilter** | 09-04 perf pack, byte-identical A/B proof | 2.4× with zero detection drift |
| 11 | **Ground truth: 138 real malware samples vs our sandbox** | 09-04/05 batch + metrics | 0 false negatives; why "clean" reports were launch failures, and why qakbot DLLs don't run themselves |
| 12 | **The sandbox that finishes early: adaptive detonation windows** | 09-11 `735ca57`/`5c3165c`; `docs/adaptive-detonation-window.md` | Stop when the sample stops: tree exit-stop + apitrace idle-stop; canary 225→118s, zero verdict drift |
| 13 | **The case of the recycled PID** | 09-12 `5559ad8` | First live trigger of the evasion detector was a detector bug — PID reuse broke the Sysmon↔apitrace join |
| 14 | **When the malware won't perform: the emotet gap that wasn't** | 09-11 `9ec0ac0`; `docs/emotet-investigation.md` | Dead-C2 starvation; measurement tooling lied 3 ways silently (labels 19→152) |
| 15 | **Grading the grader: goodware gates, attack-data validation, quieter guests** | 09-11 `46194dc`/`5002531`, zip staging `8b38782` | −64% events; two-tier goodware contract; 276/339 Splunk datasets; zip feature found two bugs |
| 16 | **The sandbox with no sandbox: detonating on the orchestrator's own machine** | 09-18 `ef8b5ae`+`b7b4184`; `docs/local-mode.md`; host canary validation | One `-LocalMode` seam swaps PSDirect for in-process across 21 call sites; canaries pass on bare metal; Defender exclusions > RTP-off on dual-use hosts |
| 17 | **A fleet of one: strip the VM, rebuild it from a web page** | 09-18 `b7093c2`; fleet acceptance test (reports `0e821527` vs `028b8490`) | Fleet page + per-VM creds + health probes + API provisioning; acceptance diff caught Defender flagging our own defender_manager .pyc (constant-folding defeated source fragmentation; engine 4.18.26080 update) — fixed with non-foldable join + agent-dir heuristic filter; canary back to clean/0 (`dfc87684`) |
| 18 | **Watching the paint dry: live telemetry streaming + a console for every VM** | 09-18 post-`b7093c2` (uncommitted) | Byte-offset JSONL tail through the LocalMode seam (both transports, zero guest changes); console singleton → per-VM registry; report tainting only for the run's own VM |

### Post-ready assets already in repo
- `out\batch_138_summary.md` — ground-truth numbers for post 11
- `docs/coverage-table.md` — API coverage matrix (post 6)
- `docs/harness-techniques.md` — technique→telemetry table (post 6)
- `docs/guardian-driver.md` + `guardian-driver-future-work.md` — full A0–A4 narrative (posts 7–8)
- `docs/interactive-console-streaming.md` — console design (post 9)
- `docs/cape-integration.md` — CAPE reachability stats (post 4)

---

## 4. Open threads (as of 2026-09-18)

- **Live local-mode full validation** — canaries passed on the dev host; real-malware + alert-parity runs still belong to a throwaway VM (`scripts\install_local.ps1` inside it).
- **ART detonation batch queued:** 55 Atomic Red Team samples (`scripts\detonate_corpus.py --worklist out\_art_missing.txt`, ~2.5–3h) → `verify_atomic_coverage.py`.
- **4 real-goodware detonations** (`samples/goodware_real/*.exe`) staged + labeled, not yet run.
- **Fake-C2/inetsim (roadmap #1)** — top value; acceptance test = emotet weak-run re-scoring (part 14).
- **Fleet next steps:** per-VM health on demand for unregistered VMs (needs creds), Hyper-V MCP adapter (thin, after fleet stabilizes), provision-from-GUI for a *fresh* VM end-to-end.
- **Closed since 09-12:** local mode (M1–M3 + host canary validation); GUI mode switch; guest instrumentation health; credential registry (config list + GUI vms.yaml); fleet page + manage modal + API provisioning; pentagramma strip-and-rebuild acceptance test (found + fixed defender-off reboot gap).
- Deferred-by-design: Guardian minifilter (A1b), hook-integrity verifier, network apitrace hooks, Office golden image, mapview Sysmon gap (harness expects EID 8 on victim, Sysmon shows none — logged in gap tracker), 2 emotet signatures, Elastic RTA, zip-staging phase 2 (static analysis of non-chosen entries).
