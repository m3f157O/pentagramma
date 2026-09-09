# Proposed Changes: Real Corpus + Benign Set + Sound Measurement, and Hookset Expansion

**Status:** Proposed (not yet implemented), **review-corrected 2026-07-21** (see
"Correction" markers: snapshot-revert framing downgraded to hygiene, host-AV
handling added for acquisition, LdrLoadDll scope corrected, reflective-load
signature variant flagged unimplementable without base addresses, pipe-loss
reporting changed to reconnect-then-report, MalShare API-key requirement,
per-sample budget corrected to 2–4 min, AV-blocked-at-launch added as a
first-class corpus outcome)
**Date:** 2026-07-26
**Source plan:** internal planning doc (not in repo)

This document collects every proposed change from the approved plan into one
project-owned reference. Nothing here has been built yet.

---

## Why

Two problems from the sandbox evaluation drive this work:

1. **Detection quality is currently unmeasurable.** The headline numbers
   (precision 1.000 / recall 0.989) are an *in-sample fit on 19 hand-curated
   scripts*: detection rules and verdict thresholds were tuned against the same
   samples, deterministic replays of those samples are counted as "109 runs",
   there is **no held-out set**, and **no confidence intervals**. We need a real
   in-the-wild corpus across many families, a larger behaviorally-realistic
   benign set, a **train/test split**, and **Wilson CIs** so calibration can't
   train on the test set and the metrics mean what they claim.

2. **The monitor hookset has blind spots.** Today 11 hooks (file/process/
   memory/thread/registry); **loader, timing/anti-sandbox, and crypto** are
   invisible. Widening the hookset must be preceded by **stability fixes**
   (SEH on pointer-arg derefs; pipe-write failure handling) because — per the
   evaluation — silent event loss and in-hook crashes currently turn malicious
   runs into "clean" reports. Widening without fixing those makes results worse.

### Decisions taken
- **Acquisition:** tooling + recipes that the operator runs on the sandbox host
  (live malware cannot be fetched from the analysis environment).
- **Benign set:** all three sources — signed active binaries, public benign-PE
  datasets, and expanded script goodware.
- **Hookset:** stabilize first, then **Tier 1** (loader / timing / crypto).
  Network and WoW64/x86 are **deferred**.

### ⚠️ Prerequisite notes (corrected 2026-07-21 review)
Network containment (isolated switch + fakedns/InetSim sinkhole) is
**operator-managed and out of scope** for this plan.

- **End-of-run snapshot revert is RECOMMENDED HYGIENE, not a hard blocker.**
  Every run already **restores the clean snapshot at run start**
  (`orchestrator/executor.py:397-399`), so a crashed/infected run cannot
  poison the next detonation, and the golden snapshot is only ever
  re-captured by the verify-gated `provision-*` endpoints. The residual risk
  a `finally`-revert addresses is narrower: a dirty/infected VM left
  **running** between runs. Implement it as recommended hardening before
  live-malware detonation, not as a gate.
- **Host-side AV handling for acquisition (must be decided BEFORE A1 runs).**
  The fetchers write live PE malware to `samples/incoming/` on the host,
  where **host Defender is ON** — files will be quarantined on write. Choose
  one: (a) keep samples **password-zipped** (`infected`) until detonation
  (the pipeline already handles those), (b) a documented host AV exclusion
  for the samples tree, or (c) encrypted-at-rest storage. Option (a) is the
  default recommendation.

The acquisition tooling and the **benign** set can be built and detonated
first.

---

## Workstream A — Real corpus + benign set + sound measurement

### A1. Acquisition tooling — `scripts/collect/` (new; operator runs)

Pure fetchers — **dedup by sha256, size caps, zip-bomb guards, never execute**.
Each writes a sidecar manifest row
`{source, family, sha256, platform, intended_label}` feeding the labeler.

| File | What it does |
|---|---|
| `scripts/collect/lib/__init__.py` (+ helpers) | Shared: sha256 dedup, size/entry caps, **safe one-entry `ZipFile.read()`** (reuse the pattern proven safe in `orchestrator/sample_types.py:372`), manifest writer |
| `collect_malwarebazaar.py` | `POST https://mb-api.abuse.ch/api/v1/` — `query=get_siginfo&signature=<fam>` / `get_taginfo&tag=<t>`, then `get_file` per sha256; **keep the passworded zip** (pw `infected`) as the on-disk form per the host-AV note above, unzip only at detonation time → `samples/incoming/malwarebazaar/<family>/` |
| `collect_malshare.py` | `https://malshare.com/api.php` — `action=search&query=pe32`, `action=getfile`; PE32-only → `samples/incoming/malshare/...`. **Requires a free MalShare API key** (env var / config entry, not hardcoded) |
| `collect_vxug.py` | Mirror a VX Underground Windows subfolder (HTTP index walk) → `samples/incoming/vxug/<year-set>/` |
| `fetch_benign_datasets.py` | EMBER / BODMAS / DikeDataset **benign** halves → raw PEs → `samples/benign/datasets/<set>/` |
| `prepare_signed_binaries.py` | Manifest-driven (editable URL list) fetch of **Sysinternals suite + signed portable installers + dev tools/compilers + signed updaters** → `samples/benign/signed/` (best FP stress) |
| `expand_goodware.py` | Curate additional `.ps1/.bat/.vbs/.js` benign scripts → `samples/goodware/` |

Each puller is **family-stratified + globally capped** (counts are CLI args) so
one prolific family can't drown the rest.

### A2. Corpus schema, split & CI — extend existing tooling

| Change | File | Detail |
|---|---|---|
| Add optional metadata fields | `tests/corpus/labels.json` | `source`, `split` (`train\|test`), `platform` (`pe32\|dotnet\|script`), `outcome` (`ran\|av_blocked` — see A3 note on guest Defender). Metadata only — `_index_labels`/`_match_label` precedence (`report→sha256→filename`) unchanged |
| Seeded stratified 80/20 splitter | `scripts/corpus_split.py` (new) | → `tests/corpus/splits.json` (`sha256 → split`). Idempotent (preserves existing assignments); tiny families (n<4) → all-train |
| Wilson score CIs | `scripts/detection_metrics.py` | `_wilson(k,n,z=1.96)` in `_rates`/`compute_metrics` (`:123-183`); render `[lo–hi]` in `render_text`/`render_markdown` (`:194-246`); caveat when n small / CI wide |
| Split selector | `scripts/detection_metrics.py` | `--split {train\|test\|all}`; report test-set metrics distinctly |
| Train-only calibration | `scripts/calibrate_verdict.py` | restrict `cache_scores`/`sweep` (`:40-106`) to `split=train` |
| Test-split regression gate | `tests/test_corpus_metrics.py` | run on **frozen test split**; keep floors (`:30-33`); non-fatal CI/low-n caveat |
| Methodology doc | `docs/corpus-methodology.md` (new) | split rule, CI interpretation, sources, "calibrate on train, measure on test" |

### A3. Detonation + labeling workflow

- **`scripts/corpus_detonate.py`** (new): walks an acquisition manifest, submits
  to `POST /api/jobs` via the existing `detonate_corpus.py` submit/poll helpers
  (`:67-99`), **resumable** (skip sha256 already present per
  `orchestrator/samples.py:48-55`), and after the run emits a labeling worklist
  **pre-seeded with the manifest's intended labels** (extends
  `detection_metrics.py --bootstrap`, `:249-266`). Reuse `SampleManager.store_sample`
  (`samples.py:29-73`) — no new storage code.
- **Phased targets:** Milestone 1 ≈ 100 malicious (≥15 families) + 50 benign;
  grow toward ≈ 300 malicious + 200 benign. **Budget ≈ 2–4 min/sample**
  end-to-end on one VM (revert + boot + timeout + collection — measured, not
  1 min) → 100 samples ≈ 3–6 hours; batch/resume overnight.
- **"AV-blocked at launch" is a first-class corpus outcome, not a failed
  detonation.** Guest Defender is ON by design, so a share of live families
  will be killed before exhibiting behavior; the pipeline already surfaces
  this as `DefenderThreatDetected`. Labels/metrics must account for it
  (e.g. an `outcome: ran|av_blocked` field), or the corpus will quietly
  over-represent only the families that evade Defender.

---

## Workstream B — Hookset expansion (stabilize → Tier 1)

All hooks follow the confirmed **8-touch single-table recipe** in `monitor.cpp`:
`ApiIndex` (`:69-82`) + `kApiNames` (`:83-87`) + `kApiCaps` (`:90-102`) + typedef
(`:285-305`) + `o_*` original (`:307-317`) + `h_*` handler + `kHooks[]` row
(`:570-582`) + (no init edit). Signatures follow the **6-touch recipe**: event-id
const + detector + wire-in (`behavioral_signatures.py:469`) + severity
(`detectors.py:96`) + MITRE (`mitre_mapping.py:41`) + catalog
(`behavioral_signatures.py:390`).

### B1. Stability prerequisites (must precede new hooks)

- **SEH-wrap pointer-arg derefs** — add `__try/__except` safe-read helpers
  (`safe_read_ptr`/`safe_read_us`); apply at every confirmed unsafe deref:
  `h_NtCreateFile:390-400`, `h_NtAllocateVirtualMemory:408-410`,
  `h_NtProtectVirtualMemory:425-427`. Fixes the **H5** false-clean crash
  (malicious sample faults in-hook → reads as clean). Today only
  `copy_unicode_string` (`:253-265`) is wrapped.
- **`pipe_write` failure handling** (`monitor.cpp:214-219`) — check `WriteFile`
  return; on loss set `g_pipeLost` (later emits no-op cheaply). Note the
  mechanism must be **reconnect-then-report, not emit-into-a-dead-pipe**: the
  monitor retries the pipe connection and only THEN emits one
  `__pipe_lost__` meta event (marking the gap), so an empty or truncated
  `apitrace.jsonl` is explainable (fixes the **H4** silent-loss direction).
  Bump collector `_BUFSIZE` (`apitrace_collector.py:45`) 64 KB → 256 KB; log
  quiet disconnects (D2).

### B2. Module-resolution generalization (unblocks crypto + later network)

Lift the **kernel32/ntdll-only** restriction in the `kHooks` loop
(`monitor.cpp:619-622`) to resolve an arbitrary module list (lazy
`LoadLibraryW` before `GetProcAddress`). Required for `bcryptprimitives.dll`
now and `ws2_32.dll`/`winhttp.dll` later.

### B3. Tier 1 hooks — all chatty ones via `emit_detail` with caps (never bare `emit`)

| Family | APIs | Notes |
|---|---|---|
| **Loader** | `LdrLoadDll` (ntdll) | Captures module path; closes the **loader-mediated loads that bypass the `kernel32!LoadLibrary` wrapper** blind spot. **Correction:** it does NOT close the reflective/manual-map blind spot — manual mapping never calls `LdrLoadDll` by definition; that coverage comes from the existing memory hooks (`NtAllocateVirtualMemory`/`NtProtectVirtualMemory`/`NtWriteVirtualMemory`) and the alloc→write→thread signatures. SEH-wrap UNICODE_STRING args. Cap ~500 |
| **Timing / anti-sandbox** | `NtDelayExecution` (ntdll), `GetTickCount64` (kernel32), `NtQuerySystemTime` (ntdll) | Choke point for sleep-skip + timing-check detection. Low caps ~200; dedup so loops collapse |
| **Crypto** | `BCryptEncrypt`, `BCryptDecrypt`, `BCryptHashData` (bcryptprimitives, via B2) | Capped; dedup by `(api, key-handle)` so ransomware encrypt-loops collapse but distinct ops pass |

Volume tuning without rebuild via existing `SANDBOX_APITRACE_GLOBAL_CAP` env
(`monitor.cpp:601-608`). Rebuild via `scripts/build_monitor.ps1`.

### B4. Behavioral signatures + MITRE + scoring (one per new family)

| Signature / event_type | Sequence | MITRE |
|---|---|---|
| `behavioral.reflective-load` / `ApitraceReflectiveLoad` | `LdrLoadDll` from an unusual path (unsigned/non-standard dir). **Correction:** the "alloc(RX)+thread on same addr" variant is **not implementable today** — the monitor captures no base addresses by design (volume control). Either extend the memory hooks to emit `base=0x…` (small change, volume implications — decide at build time) or drop that variant | T1055 / T1027 |
| `behavioral.anti-sandbox-timing` / `ApitraceAntiSandboxTiming` | rapid `GetTickCount64`/`NtQuerySystemTime` polling + long `NtDelayExecution` | T1497 |
| `behavioral.crypto-burst` / `ApitraceCryptoBurst` | `BCryptEncrypt/Decrypt` above threshold over many distinct targets in a window (presence+threshold) | T1486 |

Each wired into `detect_behavioral_signatures`, `_APITRACE_SIGNATURE_SEVERITY`
(`detectors.py:96`), `EVENT_TYPE_TO_MITRE` (`mitre_mapping.py:41`),
`describe_signatures` (`behavioral_signatures.py:390`). Raw `ApiCall` events stay
unmapped (existing design); only synthesized signatures get MITRE.

### B5. Deferred (not in scope)

Network (`WSASend`/`connect`/`getaddrinfo`/`WinHttpSendRequest`) and
**WoW64/x86** (`monitor_x86.dll` — a second CMake target + bitness-aware
`inject.cpp`) are enabled by B2 but explicitly out of scope here.

---

## Files touched (summary)

**Workstream A (new):** `scripts/collect/lib/`, `scripts/collect/{collect_malwarebazaar,collect_malshare,collect_vxug,fetch_benign_datasets,prepare_signed_binaries,expand_goodware}.py`, `scripts/corpus_split.py`, `scripts/corpus_detonate.py`, `docs/corpus-methodology.md`.
**Workstream A (edits):** `tests/corpus/labels.json`, `scripts/detection_metrics.py`, `scripts/calibrate_verdict.py`, `tests/test_corpus_metrics.py`.
**Reuse:** `orchestrator/samples.py:29-86`, `scripts/detonate_corpus.py:67-99`, `scripts/detection_metrics.py:249-266`.

**Workstream B (edits):** `agent/windows/monitor_src/monitor/monitor.cpp` (SEH helpers + `pipe_write` + module loop + 6 new hooks), `agent/windows/apitrace_collector.py` (buffer + logging), `agent/windows/monitor_src/CMakeLists.txt` (if needed), `orchestrator/behavioral_signatures.py`, `orchestrator/detectors.py`, `orchestrator/mitre_mapping.py`.
**Reuse:** `scripts/build_monitor.ps1` (build + stage).

---

## Verification (how each will be checked when built)

**A (offline parts need no VM):**
- Collectors run dry (manifests sane, dedup/caps honored, nothing executed);
  benign fetchers populate `samples/benign/`.
- After a detonation batch + labeling: `detection_metrics.py --split test`
  prints **test-set precision/recall/FPR with Wilson CIs**; `calibrate_verdict.py`
  (train-only) recommends; `test_corpus_metrics.py` passes on the **test split**;
  `replay_detection.py --all --changed-only` reports drift after rule edits.
- Confirm calibration never saw test (diff train vs test confusion matrices).

**B (rebuild + in-guest + offline unit):**
- `scripts/build_monitor.ps1` rebuilds/stages; a small **benign** in-guest test
  binary calling `LdrLoadDll`/`Sleep`/`BCrypt*` → `apitrace.jsonl` contains the new
  events and **the sample does not crash** (SEH fix verified).
- Re-run the injection harness → existing signatures (`ApitraceInjectionChain`
  etc.) **unchanged** (regression).
- Python unit tests for the 3 new signatures over synthetic event lists (pure
  functions, no VM); `detection_metrics.py` replay shows **no verdict drift** on
  the existing corpus (the new hooks/signatures are additive).
- Confirm `__pipe_lost__` / `__monitor_attach_failed__` make an empty trace
  explainable (manual: kill collector mid-run).

---

## Task breakdown

| # | Task | Workstream | Status |
|---|---|---|---|
| A1 | Collector lib + malicious fetchers (malwarebazaar, malshare, vxug) | A | pending |
| A2 | Benign-set fetchers (datasets, signed binaries, expand goodware) | A | pending |
| A3 | Train/test split + Wilson CIs | A | pending |
| A4 | Detonation workflow + labels schema + methodology doc | A | pending |
| B1 | Monitor stability (SEH + pipe) | B | **done 2026-07-27** (+ 2 extra stability fixes found in validation, see below) |
| B2 | Module resolution + Tier 1 hooks (loader/timing/crypto) | B | **done 2026-07-27** (note: BCrypt* hooks target `bcrypt.dll`, NOT `bcryptprimitives.dll` — the plan's forwarding assumption is wrong on BOTH the Win10 guest and the Win11 host: `GetProcAddress(bcryptprimitives, "BCryptHashData") == 0`, hooks silently never installed; `bcrypt.dll` build verified in-guest) |
| B3 | Behavioral signatures + MITRE + tests | B | **done 2026-07-27** (24/24 unit tests) |

### Implementation notes (2026-07-27)

Two significant bugs were found and fixed during B-validation, both
pre-existing (not caused by the Tier-1 work):

1. **In-hook crash on multithreaded/.NET samples (H5 confirmed, root cause
   found).** The monitor's re-entrancy guard used `thread_local`, whose
   implicit TLS slot is not populated on threads still inside
   `LdrpInitializeThread` — and ntdll calls hooked Nt* functions from there.
   Any heavily-threaded sample (e.g. PowerShell/.NET) crashed with
   0xC0000005 as soon as the collector pipe was connected (hooks live before
   the sample's threads spawn). cmd.exe/native samples never triggered it.
   Fix: re-entrancy guard reimplemented as an allocation-free TID table
   (Interlocked CAS) — no TLS, no FLS (`FlsSetValue` allocates → re-entered
   the hooked alloc → stack overflow), no CRT. Emit path also made CRT-free
   (custom SBuf formatting replaces `_snprintf_s` in every hook handler).
   Verified: 10/10 crash repro → 0/10 with full hookset + collector.
2. **Two false positives on benign process-spawning samples:**
   - kernel32's CreateProcess writes the parameter block into every new
     child → `ApitraceCrossProcessWrite` FP. Fixed: writes into the actor's
     own just-created children are excluded (hollowing still caught via the
     chain signature — needs a caller-initiated resume).
   - MinHook trampolines flip a 5-byte region RX per hook →
     `ApitraceExecProtection` FP. Fixed: `size==5` same-process protects are
     filtered signature-side (raw events stay in the trace).

3. **Four more signature-side FPs found by detonating a benign PowerShell
   sample** (powershell polls time, spawns own threads, JIT-flips small
   pages, and loads Defender's AMSI provider from `ProgramData\Microsoft`):
   - `ApitraceRemoteThread`: same-process `NtCreateThreadEx`
     (`cross_process=0`) no longer fires — only cross-process starts.
   - `ApitraceReflectiveLoad`: `\programdata\microsoft\` excluded (Defender
     platform DLLs load into every powershell via AMSI).
   - `ApitraceExecProtection`: same-process protect→exec now requires
     `size >= 4096` (MinHook trampolines are 5 B, .NET JIT flips are small);
     cross-process fires on any size.
   - `ApitraceAntiSandboxTiming`: poll threshold 5 → 15 dedup-surviving
     events (a normal powershell startup polls ~6-10 times).

Also folded `__pipe_lost__` into the `ApiTraceTruncated` transparency alert.

**Verification done:** 24→28/28 unit tests; host stress 0/10 crashes with
collector (was 10/10); guest detonations of benign .bat/.ps1 complete with
exit 0 and no behavioral alerts (residual score = pre-existing AMSI
self-test artifact, out of scope); BCryptHashData/BCryptEncrypt,
LdrLoadDll, NtDelayExecution, GetTickCount64, NtQuerySystemTime events
confirmed in live guest traces; replay shows InjectionHarness verdict
unchanged (malicious/90) and the pre-fix FP report dropping 70→37.

### Tier-1.5 expansion + WoW64 (2026-07-27, user-directed, beyond the original plan)

Hookset grew 18 → **33 hooks**, reaching CrowdStrike parity on the
memory/thread/token surface:

- **Injection finishers**: `NtQueueApcThread(+Ex)`, `NtSetContextThread`,
  `NtSuspendThread`, `NtGetContextThread` — APC injection and thread
  hijacking (both invisible to Sysmon).
- **Token**: `NtOpenProcessToken` (cross-only), `NtDuplicateToken`,
  `NtAdjustPrivilegesToken` (SeDebug/SeImpersonate only) → new
  `ApitraceTokenManipulation` signature (T1134; fires only on
  privilege+cross-open or open+duplicate — stock powershell noise
  documented in tests).
- **Read side + hollowing**: `NtReadVirtualMemory` (cross-only → new
  `ApitraceCrossProcessRead`, T1005), `NtUnmapViewOfSection(+Ex)` (folded
  into the injection-chain signature as the hollowing tell).
- **Ex-variant bypass closed**: `NtAllocateVirtualMemoryEx`,
  `NtMapViewOfSectionEx` — existing memory signatures accept both names
  (confirmed: the x86 CLR really calls NtUnmapViewOfSectionEx on Win10).
- **Anti-debug**: `NtSetInformationThread` (HideFromDebugger),
  `NtSetInformationProcess` (debug classes) → new `ApitraceAntiDebug` (T1622).
- **WoW64 shipped**: `monitor_x86.dll` + `monitor_loader_x86.exe` (same
  source, bitness-aware CMake); guest launch sniffs the PE machine type and
  picks the x86 pair for 32-bit samples; x64 monitor delegates WoW64
  children to `monitor_loader_x86.exe attach` (verified: 32-bit guest
  powershell + certutil traced, 730 events, BCrypt included; x86 monitor
  follows its own WoW64 children; x64 children from x86 parents are the
  accepted residual blind spot).
- **NtDelayExecution overflow fixed** (LLONG_MIN magnitude was UB → absurd
  delay_ms FP'ing the timing signature; clamped monitor-side + signature
  plausibility guard).

40/40 unit tests; host stress 0/10 (x64) and 0/4+ (x86); benign x64+x86
guest runs produce zero behavioral alerts with final thresholds.

### Phase-2 expansion (2026-07-27, Tier-2 evasion gaps)

Hookset grew 33 → **37 hooks**; memory/thread events now carry
`base=0x…`/`start=0x…` addresses.

- **A — Address emission + anti-tamper**: writes/protects landing inside
  **ntdll or amsi.dll** are annotated `targets_module=` and flagged only when
  ACTIONABLE (a write into the module image, or a protect flipping it to
  EXECUTABLE) → new `ApitraceAntiTamper` (high, T1562.001: unhooking,
  ETW/AMSI blinding). Reflective-load gained the **same-address variant**
  (exec alloc at B + thread start at B) that phase 1 had to drop.
  FP fights won during validation: MinHook's own 5-byte patch-site protects
  (suppressed during hook installation) and the CLR's routine RW↔RO flips
  inside ntdll (46 in one powershell run) — killed by the actionable-only
  rule.
- **B — Timer hooks**: `NtCreateTimer`, `NtSetTimer`; `NtSetTimer` with an
  APC routine feeds the timing signature's **timer-APC arm**
  (Ekko/Foliage sleep-obfuscation).
- **C — Transaction hooks**: `NtCreateTransaction`, `NtRollbackTransaction`
  → new `ApitraceTransactionAbuse` (medium, T1055.013 doppelgänging
  primitive).
- **D — PPID spoof parse**: `NtCreateUserProcess` decodes
  `PS_ATTRIBUTE_LIST` and emits `ppid_spoofed=1` when the named parent
  differs from the real creator → new `ApitracePpidSpoof` (high, T1134.004).
- **Alertable-wait exclusion**: the timing signature now ignores
  `alertable=1` delays (parked runtime threads — benign guest powershell
  showed 10s and 7-day alertable waits); plain `Sleep` stays covered and
  APC-based evasion is caught by the timer-APC arm.
- **Exec-alloc threshold raised 30 → 100**: the x64 guest CLR (powershell
  5.1 + AMSI) measured 62 RWX allocs on a trivial script; bar now sits with
  ~60% headroom over the worst measured benign runtime.
- **UI**: behavioral alerts now carry their catalog `severity` (attached in
  `enrich_alert` from `detectors.py`'s map — single source of truth), so
  `report_detail.js` colors/groups every Apitrace* signature correctly
  without a hardcoded name list (previously CryptoBurst/ReflectiveLoad/etc.
  rendered as "low").

**Verification:** unit tests pass (incl. new regression tests for the
alertable-wait and RWX-volume FPs); host smoke (1949 events, 0 tamper-
flagged, base= flowing); guest benign BAT + PS1 re-detonated — exit 0,
**zero behavioral alerts** (residual score 37 = pre-existing AMSI self-test
artifact). Targeted replay of the 12 historical reports carrying
ExecProtection/AntiSandboxTiming alerts: InjectionHarness runs unchanged
(malicious/90, TPs preserved), attack-sim ps1 samples stay malicious
(67–71), benign script FPs drop (70→37). Note: traces captured with the
pre-fix monitor still carry tamper-flagged CLR flips, so AntiTamper still
fires when REPLAYING those old captures — inherent to the stale telemetry,
not a code regression; fresh captures are clean.
