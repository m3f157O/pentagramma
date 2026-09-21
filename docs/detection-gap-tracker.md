# Detection Gap Analysis & Remediation Tracker

Ongoing evaluation of the sandbox's evidence-gathering coverage, evidence
type by evidence type. For each type: what's gathered today, what gaps were
found, what got fixed, and what remains open. Distinct from
`reports/detection_surface_report.md` (a one-time snapshot of the
injection-harness technique-to-EID detection matrix) — this tracks gaps
across the whole telemetry pipeline, not just the harness.

## Status overview

| # | Evidence type | Status |
|---|---|---|
| 1 | Static file analysis (pre-execution) | Evaluated + fixed |
| 2 | Process lifecycle (Sysmon EID 1/5) | Evaluated + fixed |
| 3 | Image/driver loads (EID 7/6) | Evaluated + fixed |
| 4 | Process injection & tampering (EID 8/10/25) | Evaluated + partially fixed |
| 5 | File system activity (EID 11/15/23/26/9) | Evaluated + fixed |
| 6 | File timestomping (EID 2) | Evaluated + fixed |
| 7 | Sysmon active file blocking (EID 27/28) | Confirmed rejected (intentional non-goal) |
| 8 | Registry activity (EID 12/13/14) | **Live-confirmed fixed** — `RegistryCreateDelete` and `RegistryValueSet` events now flow on every run (was producing **zero events**, see below) |
| 9 | Named pipes (EID 17/18) | **Live-confirmed fixed** — `PipeCreated`/`PipeConnected` events now flow (was producing **zero events**, see below) |
| 10 | WMI persistence (EID 19/20/21) | **Evaluated but still non-functional** — correct `WmiEvent` config confirmed, yet Sysmon still emits zero WMI events on this guest. This is a known Sysmon/build limitation, not a config bug (was producing **zero events**, see below) |
| 11 | Network connections, Sysmon's own view (EID 3) | Evaluated + fixed (was collected but never alerted/MITRE-mapped) |
| 12 | DNS queries, Sysmon's own view (EID 22) | Evaluated + fixed (was collected but never alerted/MITRE-mapped) |
| 13 | Clipboard access (EID 24) | Fixed (as a side effect of #5's pass) |
| 14 | Full network packet capture (pktmon/pcapng) | Evaluated, no gaps found |
| 15 | Process execution metadata (stdout/stderr/exit code) | Evaluated + fixed (was producing **false timeouts + truncated output**, see below) |
| 16 | ETW Threat-Intelligence | Confirmed infeasible this pass (PPL/code-signing gate); deferred, transparency note kept |
| 17 | AMSI script-content scanning | Evaluated + fixed (implemented, live-verified with real events) |
| 18 | PowerShell script-block logging | Evaluated + fixed (implemented, live-verified with real events) |
| 19 | Apitrace↔Sysmon blind-spot correlation | Implemented — curated coverage map (`orchestrator/data/coverage_map.yaml`, generated matrix in `docs/coverage-table.md`) + `ApitraceBlindSpot`/`ApitraceSilence` detectors in `behavioral_signatures.py`. A Sysmon event whose hooked-API counterpart is missing = unhooking or direct syscalls (T1562.001). Direct syscalls remain a documented visibility gap for argument fidelity (only ETW-TI/hypervisor sees them); Sysmon still captures their kernel-level effects. |

## ⚠️ Correction to the original 8/9/10 assessment

The initial evaluation of categories 8 (registry), 9 (named pipes), and 10
(WMI persistence) said they were "already fully wired end-to-end, just
noisy." **That was wrong.** `agent/windows/sysmonconfig.xml` had been using
invalid Sysmon XML tag names for all three families since before this
tracker existed — `RegistryCreateDelete`/`RegistryValueSet`/
`RegistryKeyValueRename`, `PipeCreated`/`PipeConnected`, and
`WmiEventFilter`/`WmiEventConsumer`/`WmiEventConsumerToFilter` are this
project's own Python-side per-EID labels, not real Sysmon config elements.
The actual schema uses one shared tag per family — `RegistryEvent` (EIDs
12/13/14), `PipeEvent` (17/18), `WmiEvent` (19/20/21) — confirmed against
Microsoft's own Sysmon documentation and TrustedSec's `SysmonCommunityGuide`.
Combined with all three defaulting to exclude-everything when a tag isn't
recognized, **these eight event IDs had almost certainly never produced a
single event** in any analysis this sandbox has ever run. Separately, EIDs
19/20/21 were also entirely missing from `sysmon_parser.py::_classify()`'s
mapping, so even a correctly-configured Sysmon would have mislabeled them as
generic `SysmonEvent19`/`20`/`21` rather than the names `heuristics.py`/
`mitre_mapping.py` already expected. Both bugs are now fixed — see below.

## 1–5: what changed

- **Static analysis**: real `ssdeep` fuzzy hashing, `packed_suspected`/`packing_reasons` verdict (7.2 entropy threshold, shared with the existing YARA rule), VirusTotal plumbing wired (still needs a key).
- **Process lifecycle**: `ProcessCreate` MITRE-mapped and conditionally alert-worthy (LOLBin/encoded-command pattern on real `CommandLine`); short-lived process burst detector.
- **Image/driver loads**: `ImageLoad`/`DriverLoad` moved from unconditional to conditional alerting (unsigned or unusual path) — verified 1,307 → 113 alerts on real data; Sysmon self-noise excludes added.
- **Process injection & tampering**: `ProcessAccess` `GrantedAccess` mask broadened (2 justified additions); self-noise exclude added.
- **File system activity**: added missing `FileCreateStreamHash`/`FileDelete`/`ClipboardChange` Sysmon rules; dual MD5+SHA256 hashing; `ArchiveDirectory` (stops discarding deleted-file content); mass-file-modification burst detector.

New shared module: `orchestrator/heuristics.py` (conditional alert selection + burst detection). All changes verified against real historical event data — EID 25/ProcessTampering alerts confirmed byte-identical before/after, `scripts/harness_assertions.py` verdicts unchanged.

## 6–10: what changed

- **File timestomping**: new `FileCreateTime` Sysmon rule (EID 2 was entirely uncaptured); `sysmon_parser.py` relabel (`ProcessChangedFile` → `FileCreateTime`, matching Sysmon's real event name); `T1070.006` MITRE mapping; unconditionally alert-worthy.
- **Active file blocking (EID 27/28)**: re-confirmed as an intentional non-goal, not a gap — Sysmon only emits these when actually configured to intervene, which would corrupt the sandbox's own observation of the sample. No change.
- **Registry / named pipes / WMI persistence**: fixed the critical config-tag bug described above (`RegistryEvent`/`PipeEvent`/`WmiEvent`), fixed the missing EID 19/20/21 classifier entries, and fixed a stale `sysmon_parser.py` mislabel (EID 29 was wrongly `"Error"`, corrected to `"FileExecutableDetected"` — the real Sysmon Error event is EID 255, already handled correctly per `docs/sysmon-255-investigation.md`).
- **New non-filtering priority annotation** (`heuristics.py::annotate_priority()`): tags registry/pipe alerts with `priority="high"` + `priority_reason` when they touch a high-value persistence/hijack key (Run/RunOnce, Winlogon, IFEO, AppInit_DLLs, LSA packages, COM CLSID, service ImagePath/ServiceDLL, Defender tamper, Active Setup StubPath — each sourced from real SigmaHQ rules) or a known malicious/tooling pipe name (PsExec, PAExec, RemCom, Cobalt Strike's exclusion-free default pipes). Deliberately *not* the same conditional-filtering approach used for `ImageLoad` — the high-value-key/known-pipe surface is open-ended, so filtering would risk silently dropping real persistence not on the list. Every registry/pipe alert still fires exactly as before; this only adds triage hints.

All changes re-verified against the same real historical report and `harness_assertions.py` regression check as the 1–5 pass — EID 25 still byte-identical, verdicts still unchanged.

### Live verification (2026-07-21)

Three real detonations confirmed the 8/9/10 assessment:

- `persistence_runkey.ps1` produced **22,840 `RegistryCreateDelete`** and **1,410 `RegistryValueSet`** events.
- `c2_named_pipe.ps1` produced **81 `PipeCreated`** and **81 `PipeConnected`** events.
- `wmi_persistence.ps1` produced **zero** `WmiEventFilter`/`WmiEventConsumer`/`WmiEventConsumerToFilter` events despite the correct `WmiEvent` tag being in place.

So the config-tag bug for registry and pipes is **confirmed fixed on a live VM**. WMI is **confirmed as a real Sysmon limitation** on this guest (not a config bug) and is therefore deferred rather than "fixed."

## 16–18: what changed

Of the 3 "configured but non-functional" sources, this pass resolved the
open feasibility question for each and shipped 2 of the 3 as real, working
features.

- **PowerShell script-block logging (18)**: new `agent/windows/
  powershell_logging_manager.py` (idempotent registry-policy enable/status,
  mirroring `sysmon_manager.py`'s style) + `powershell_parser.py` (queries
  `Microsoft-Windows-PowerShell/Operational`, filtered to EID 4104 only —
  4103/module logging deliberately excluded, same noise-risk reasoning as
  `ImageLoad` pre-gating). Wired into `telemetry_collector.py`, MITRE-mapped
  to `T1059.001`, unconditionally alert-worthy. **Live-verified**: enabled
  the real `HKLM` policy key, ran a real PowerShell script with a unique
  marker, queried it back through the new parser, got exactly 1 matching
  event (of 16 total EID 4104 events in the window) with all expected
  fields populated. Registry key reverted afterward.
- **AMSI script-content scanning (17)**: new `agent/windows/etw_common.py`
  (shared `logman`-session + offline `.etl`-file decoding helpers, built on
  the vendored `pywintrace` library) + `amsi_collector.py` (captures the
  `Microsoft-Antimalware-Scan-Interface` ETW provider, EID 1101, decodes the
  actual scanned script/buffer content). Wired into `telemetry_collector.py`,
  MITRE-mapped to `T1027`, unconditionally alert-worthy. **Confirmed this
  pass: AMSI does not require SYSTEM/PPL, only Administrator** — unlike
  ETW-TI below, this was a real, shippable gap-filler. **Live-verified**:
  real end-to-end capture on this host caught a real PowerShell command's
  decoded content, including a unique marker string, through the actual
  production `AmsiCollector` class. Several implementation details were
  wrong in the initial sourced research and had to be corrected empirically
  — the provider GUID (commonly-cited third-party value doesn't match the
  real ETW provider), the `pywintrace` callback payload shape, and the
  low-level API needed for offline `.etl` parsing — see the corrected
  `Microsoft-Antimalware-Scan-Interface` provider name/GUID in
  `docs/etw-vs-sysmon.md`.
- **ETW Threat-Intelligence (16)**: **deferred, not implemented.** The
  original hypothesis was that a SYSTEM-owned collector process (e.g. via a
  `schtasks /ru SYSTEM` trick) could unlock this provider — confirmed this
  pass to be a dead end. The actual gate on
  `Microsoft-Windows-Threat-Intelligence` is that the *consuming process*
  must be a Protected Process Light (PPL) with the Antimalware-Light signer
  level, which requires an actual Microsoft antimalware code-signing
  certificate. SYSTEM privilege and PPL protection are orthogonal — a
  SYSTEM-owned process fails the same kernel check a normal Administrator
  session does today. The only known workaround (an AutoLogger + a native,
  function-hooking PPL-bypass consumer, Windows-build-specific) is genuine
  multi-day native-code research with real fragility risk, not a small
  addition. The existing transparent stub is unchanged
  (`execution_info["etw_ti_status"] = "not_implemented"` in `executor.py`).

All three changes are pure additions (new event types, new alert-type set
entries, new MITRE mapping entries) — re-verified against the same
historical-report regression check used in prior passes: EID 25/
ProcessTampering alerts stayed byte-identical, all pre-existing unconditional
alert-type counts stayed unchanged.

## 11–15: what changed

- **Network connections (11) / DNS queries (12)**: both were fully wired at
  the Sysmon config + parser level (real `NetworkConnect`/`DnsQuery` events
  flowing correctly), but `heuristics.py` had no entry for either event type
  — not unconditional, not conditionally gated — and `mitre_mapping.py` had
  no mapping for either. Every outbound connection and DNS lookup a sample
  made, including a real C2 callback or C2 domain resolution, was silently
  absent from the Alerts panel and the MITRE coverage matrix; the only way
  to see them was manually paging the raw event browser. Verified volume
  across 35 real historical reports before fixing (29–35 `NetworkConnect`
  and 16–21 `DnsQuery` events per run, stable) — nowhere near `ImageLoad`'s
  1,307-event noise problem, so both were added to
  `UNCONDITIONAL_ALERT_TYPES` directly (no gating needed) and MITRE-mapped
  (`NetworkConnect` → T1071 Application Layer Protocol, `DnsQuery` → T1071.004
  DNS, both Command and Control tactic).
- **Full packet capture (14)**: traced the whole pktmon pipeline
  (`agent/windows/network_capture.py` start/stop/convert,
  `hyperv-vm.ps1`'s `Invoke-NetworkCaptureStop` correctly chaining stop→
  convert, `Copy-NetworkCaptureFromVM`) — no functional gaps found, no
  changes made.
- **Execution metadata (15)**: **confirmed and fixed a real, severe bug** in
  `scripts/hyperv-vm.ps1::Invoke-SampleExecution`. The original code
  redirected both stdout and stderr but called `WaitForExit()` *before*
  draining either stream — the classic .NET `Process` redirection deadlock
  (Microsoft's own docs warn about this exact pattern). Reproduced directly
  on this host: a child process writing ~300KB to stdout blocked completely
  once the ~4KB anonymous pipe buffer filled, and `WaitForExit(15000)`
  timed out at the full 15 seconds even though the child's actual work was
  instant — only 4,030 bytes of stdout were recoverable afterward. Real
  impact: any sample logging more than ~4KB to stdout during execution
  (extremely common — verbose loops, banners, debug output) was incorrectly
  marked `TimedOut: true`, force-killed early, and had its stdout/stderr
  truncated to whatever fit in the pipe buffer — corrupting
  `execution_info` in every affected report and undermining
  `harness_assertions.py`'s PID-extraction-from-stdout for the injection
  harness. Fixed by switching to `StandardOutput.ReadToEndAsync()` /
  `StandardError.ReadToEndAsync()` started immediately after `Process.Start()`
  (before `WaitForExit()`), which drains both pipes concurrently and
  eliminates the deadlock; also added an explicit `WaitForExit()` (no
  timeout) after `Kill()` so `ExitCode` is always safe to read, and a
  200,000-char truncation cap per stream (previously unbounded, unlike
  other large-content fields elsewhere in the project). **Verified
  empirically twice**: (1) extracted the exact production scriptblock from
  the edited file and ran it locally against the same 300KB-stdout repro —
  completed in 0.33s with the full output captured (vs. hanging the full
  timeout before), and (2) re-verified the genuine timeout+kill path still
  correctly detects a real hang, kills the process, and returns partial
  output rather than blocking indefinitely.

All changes re-verified against the same historical-report regression check
and heuristics unit suite used in prior passes — EID 25 still byte-identical,
all pre-existing unconditional alert-type counts unchanged;
`NetworkConnect`/`DnsQuery` now correctly appear as newly alert-worthy on
real historical data.

## Still open (deferred or not fixed by the above)

**Static analysis**
- No VT API key configured — cloud reputation still doesn't run.
- ~~Only one YARA file (~5 rules)~~ **Resolved 2026-09-04**: YARA-Forge **extended** tier vendored (10,763 compiled rules, `yara-forge-extended-20260830`, via new `scripts/fetch_yara_forge.py` + `vendor_yara_rules.py`); project-owned customs stay in `yara/`. Per-sample drift scan over all 92 on-disk samples: zero new hits; one upstream removal (`COD3NYM_DOTNET_Singlefilehost_Bundled_App`, used to fire on InjectionHarness → its next *live* score drops ~15 pts from the lost static-YARA weight; replays unaffected).
- ~~No .NET/CLR-aware analysis~~ **Resolved 2026-09-04**: `static_analysis.py::parse_dotnet()` (dnfile — already installed as capa's backend): CLR runtime version, assembly name, entrypoint token, IL-only/mixed-mode flag, metadata streams, TypeRef/TypeDef names, `#US` user-strings heap, obfuscator markers (ConfuserEx/Dotfuscator/SmartAssembly/… → scored +5 in `classify_static`). capa already auto-extracted .NET; the UI static tab now shows the .NET subsection + capa `dotnet` format badge.
- No overlay/appended-data detection, no certificate chain/revocation validation.
- `ssdeep` hash computed but nothing consumes it (no similarity search).

**Process lifecycle**
- `IntegrityLevel` still captured but unused.
- No parent→child anomaly detection beyond the LOLBin regex.
- LOLBin pattern list untested for false positives against a larger benign corpus.
- No reputation/hash cross-referencing of spawned child processes.

**Image/driver loads**
- **Core structural blind spot untouched**: reflective/manually-mapped DLLs generate no `ImageLoad` event at all (needs working ETW-TI).
- "Standard path" allowlist is fixed, doesn't adapt to this VM's actual installed software.
- No DLL search-order-hijacking-specific check.

**Process injection & tampering**
- Herpaderping/ghosting `Image`/`Type` flakiness and duplicate EID 255 events — unresolved (believed inherent OS timing behavior).
- ETW-TI still non-functional (only a transparency note was added).
- **Reflective/direct-syscall injection chains now have telemetry**: the MinHook API monitor (`Track 3`) captures `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtResumeThread`, `NtProtectVirtualMemory`, etc., and `orchestrator/behavioral_signatures.py` turns those events into alerts (`ApitraceInjectionChain`, `ApitraceCrossProcessWrite`, `ApitraceRemoteThread`, `ApitraceExecProtection`). This is the structural gap ETW-TI was supposed to fill.
- Harness coverage extended (2026-08-17): AtomBombing, module overloading, SetWindowsHookEx, NtQueueApcThreadEx, MapView injection added and live-asserted (`docs/harness-techniques.md`); thread-pool injection explicitly out of scope (PoolParty-only); WoW64 covered by the monitor expansion. Still no harness coverage for ETW/AMSI/CLR self-patching.
- `GrantedAccess` allowlist is inherently whack-a-mole.
- EID25+EID255 ghosting-correlation heuristic (suggested, not built).

**File system activity**
- ~~Dropped-file retrieval is still the single largest gap~~ **Resolved 2026-09-04**: (a) lineage-scoped dropped files now get full deep static re-analysis (`StaticAnalyzer.analyze()` — entropy/packing/PE/.NET/strings/YARA; capa on flagged PEs within a per-run budget of 3) instead of hash+YARA only, plus `DroppedFileCapaHit` alerts (EID 9106) for high-signal capa capabilities; (b) Sysmon's `C:\SandboxArchive` deleted-file content is now retrieved and hash-correlated to sample-lineage `FileDelete` events (`origin: "sysmon_archive"` in the report) — self-cleaning droppers no longer lose their payload.
- Mass-file-modification threshold untested against real ransomware behavior.
- `RawAccessRead` has no significance-scoring (no distinction for `$MFT`/SAM/SYSTEM raw reads).
- No path scoping (kept broad on purpose).

**File timestomping**
- `FileCreateTime` is unconditionally alert-worthy with no further triage — fine for now given how rare it should be, but untested against any real timestomping sample (no historical data existed for this EID either).

**Registry activity**
- Priority annotation is additive/non-filtering by design, but the sourced key-pattern list is not exhaustive (registry persistence surface keeps growing) — treat `priority=high` as "definitely worth a look," not the absence of it as "definitely benign."
- No inspection of `Details` content beyond the existing LOLBin regex — a persistence payload stored as raw shellcode/binary data in a `REG_BINARY` value wouldn't be caught.

**Named pipes**
- `PipeCreated`↔`PipeConnected` correlation (who connected to what) explicitly deferred — no real pipe data existed yet to design or tune it against.
- Priority pattern list deliberately excludes the broader Cobalt Strike pipe-name rule (its patterns overlap legitimate Windows RPC pipes and need allow-list exclusions this pass doesn't implement) — some malleable-profile C2 pipes may still go untagged.

**WMI persistence**
- **Confirmed non-functional on this guest even with correct Sysmon config** (`WmiEvent` tag present, verified XML schema) — Sysmon simply emits zero WMI events here. This is a known Sysmon/build limitation, not a config bug; deferred unless an alternative telemetry source (ETW-TI, custom provider) becomes available.
- No Filter+Consumer+Binding chain reconstruction (three independent alerts, no stitching to answer "which WQL query triggers which payload") — the raw `Query`/`Destination` fields are present in each alert's `data`, just not cross-referenced.
- `report_detail.js::renderAlerts()`'s 4th column still shows the WMI consumer *class* rather than the actual payload — cosmetic, the raw JSON/event browser already has it, not fixed this pass.

**Network connections / DNS queries**
- No priority annotation (unlike registry/pipe events) — an outbound connection to a known-malicious IP/port or a DGA-looking domain gets the same unconditional-alert treatment as a benign one; no allow-list for common OS background traffic (Windows telemetry, time sync, license activation) either, so those show up as alerts too.
- ~~No burst detection for connection/DNS floods~~ **Resolved 2026-09-04**: `NetworkBurstDetected` (synthetic EID 9105, `heuristics._detect_network_bursts`) — per-process 10s-window detection of port scans (≥15 distinct ports per destination), connection floods (≥40), DNS floods (≥50) and DNS-tunneling suspects (≥20 mostly-unique queries averaging ≥52 chars); MITRE T1046/T1071.004/T1572/T1048, high severity for port_scan/dns_tunnel_suspect. Canary replay: zero verdict drift.
- Not cross-referenced with the separate pcap capture (14) — Sysmon's `NetworkConnect` has process/PID attribution that raw packets don't, and pcap has full payload bytes that Sysmon doesn't; today these are two independent views, not one correlated one.

**Full network packet capture (pktmon/pcapng)**
- TLS-encrypted C2 traffic is opaque at the packet level — inherent limit, would need in-VM TLS interception (a much larger, separate effort), not attempted.
- Not correlated with Sysmon's `NetworkConnect` events (see above) for process/PID attribution.

**Process execution metadata**
- Only the top-level sample process's stdout/stderr/exit code are captured — no metadata for child processes it spawns (those still show up via Sysmon `ProcessCreate`/`ProcessTerminate`, just without their own stdout/stderr).
- No CPU/memory/resource-usage metrics captured for the sample process.
- 200,000-char truncation cap on stdout/stderr is a reasonable but untuned constant — not validated against real verbose-malware output volumes.

**PowerShell script-block logging**
- 4103 (module/pipeline logging) deliberately not captured — same noise-risk reasoning as pre-gated `ImageLoad`.
- Multi-part script-block stitching (`MessageNumber`/`MessageTotal` for scripts split across multiple 4104 records) not implemented — most scripts fit in one record, so this is a real but non-blocking refinement.
- Live-verified on this host only, not yet on the actual guest VM — whether the `gigi` account's effective rights and the guest's Windows build behave identically is very likely but not 100% proven.

**AMSI script-content scanning**
- System-wide provider, not scoped to the sample process — a busy VM could produce a large volume of unrelated AMSI events during one analysis window; `MAX_EVENTS = 5000` is a reasonable safety net but untuned against real malware-sample AMSI behavior.
- Content decoding assumes UTF-16LE hex-encoded payloads (verified empirically); non-script AMSI content types (e.g. some Office macro paths) haven't been tested against real samples.
- Live-verified on this host only, not yet on the actual guest VM — whether `pywintrace` (unmaintained since 2019) behaves identically on the guest's specific Python 3.11 install is the biggest remaining unknown.

**ETW Threat-Intelligence**
- Still non-functional by design — the PPL/Antimalware-Light code-signing requirement is a genuine multi-day native-code research spike (AutoLogger + function-hooking PPL-bypass consumer), not attempted this pass.
- **Structural blind spot partially closed**: reflective/manually-mapped DLL injection and direct-syscall injection chains are now visible through the MinHook API monitor + behavioral signatures, though memory-region-level correlation (e.g. `ALLOCVM` → `SET_THREAD_CONTEXT` via ETW-TI events) is still unavailable.

**Cross-cutting**
- None of the above fixes have been confirmed on a **live** Hyper-V run yet — verified via rebuilding reports from historical event data and unit tests only, deliberately avoiding the real VM this pass. **This caveat is strongest for categories 6/8/9/10**: since those event types produced zero historical data, there's nothing to replay — the config fix is structurally verified only (correct XML, correct tag names per Microsoft's docs), not confirmed producing real events yet. **Categories 17/18 are the exception** — both were live-verified against real events, but on this host, not the actual guest VM. **Category 15's fix** was verified by extracting the exact edited `Invoke-SampleExecution` scriptblock and running it locally (proving the deadlock fix and the timeout/kill path both work against real `cmd.exe`/`ping.exe` processes) — high-fidelity since the logic is pure .NET `Process` code with no VM-specific dependencies, but not yet run through actual PowerShell Direct into the guest.
- Heuristic thresholds (burst window sizes, min counts) are hand-picked constants, not empirically tuned against real malware or false-positive rates.

**Environment noise (2026-09-05, in progress)**
- Quantified on benign canary d89f08b6: the sample lineage produced 140 of 39,246 events (0.4%); the canary's entire 12-point score was sandbox/OS noise (own monitor-DLL ImageLoad + apitrace pipe + a LOCAL SERVICE WMI health probe false-attributed via recycled-PID adoption).
- Fixed (attribution-side, replay-verified): `reporting._suppress_os_noise_scope_leaks` — de-scopes own-tooling ImageLoad/PipeConnected, GUID-less alerts from known OS-noise images (EdgeUpdate/OneDriveSetup/CompatTelRunner/SearchIndexer/TiWorker/MoUSO...), and Security-Center WMI health-probe subscriptions. Canary replay: 12 → clean/0; 10 weak emotet runs unchanged or −4 (their own apitrace-pipe points).
- Fixed (collection-side): `agent/windows/sysmonconfig.xml` exclude groups for the same OS-noise images (full paths where fixed; svchost/WmiPrvSE/MsMpEng deliberately kept); `guardian_agent.py` Sysmon-liveness polling switched from a 1 Hz `tasklist.exe` spawn to a Toolhelp32 snapshot (no child-process churn).
- Fixed (guest-side): `agent/windows/apply_noise_reduction.py` (apply/verify; disables updater/telemetry/CEIP/indexer tasks+services + telemetry policies; Defender and wuauserv kept) + `provision_golden_image.ps1` step + `POST /api/vm/provision-noise-reduction`.
- Remaining: the WmiEvent Sysmon gap (#10) stays open.
- **Live-validated 2026-09-11** on the recaptured SANDBOX_READY (noise reduction applied via `provision-noise-reduction`): benign canary clean/0 (was suspicious/12), events 39,246 → 14,200, alerts 29,437 → 6,730; InjectionHarness still malicious/90, amsi_detection malicious/48 (was 52: −4 = the suppressed own-apitrace-pipe group, real detections intact), defender_tampering malicious/47 (in the ~42–46 band). New canary contract: benign **clean/0**, amsi **48**, tamper **~42–47**, harness **90**.

## Splunk attack-data → Sigma validation (2026-09-05)

Offline validation of the production Sigma engine against the Splunk
`attack_data` dataset repo (`scripts/validate_sigma_attack_data.py`): each
dataset's Sysmon JSONL is parsed through the agent's own `SysmonParser._parse_xml`
and fed through `sigma_engine.evaluate`, exactly as live telemetry would be.
Full run: **276/339 datasets (81%) produced ≥1 Sigma alert, 448 distinct rules
fired**. Full output: `out/_attack_data_validation_full.txt`; the 63 zero-match
datasets: `out/_attack_data_zero_match.txt`.

Methodology caveats before reading the gap list:
- This replays **Sysmon only**. Live runs additionally have apitrace, AMSI,
  behavioral heuristics, static/dump YARA, and PCAP — several zero-match classes
  below are covered by those layers in the sandbox (e.g. T1486 mass-encryption
  is caught by the `mass_file_modification` heuristic, T1055 by the
  InjectionHarness telemetry) — the gap is in the *Sigma* layer only.
- Several datasets are not Windows-Sysmon telemetry at all (network appliance
  logs, ESXi, empty files) — unwinnable by any Sysmon rule.

### Zero-match datasets, grouped (63 total)

**A. Not Sysmon telemetry / empty datasets — out of scope (≈14):**
T1195.001 npm ×3 (0/0/12 ev), T1562.004 ART (0 ev), T1190 proxyshell (0 ev) /
sap / screenconnect / crushftp (appliance exploits), T1195.002 3CX (network),
T1570 + T1569.002 remcom (network), T1021.003 speechruntime (network),
T1542.003 bootkits (network-winlogon), T1136.001 esxadmins (ESXi),
T1110.001 rdp_brute (Security-log 4625s, not Sysmon).

**B. High-value rule gaps — candidates for new Sigma rules (top priority):**
- **T1033 AD_discovery (2987 ev)** — `net group "domain admins" /domain`,
  nltest, dsquery-style discovery commandlines; no discovery-recon rules loaded.
- **T1047 lateral_movement (3487 ev)** — WMI `process call create` remote
  execution; surprising gap, review why loaded WMI rules missed it.
- **T1053.002 lateral_movement (3534 ev)** — remote `schtasks /s`.
- **T1548.002 LocalAccountTokenFilterPolicy (5335 ev)** — registry write under
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`; classic
  UAC-bypass/persistence rule candidate.
- **T1561.002 mbr_raw_access (1769 ev)** — raw access to `\\.\PhysicalDrive0`.
- **T1485 ransomware_extensions/notes ×3 (217/217/9 ev)** and **T1486 dcrypt
  (343 ev)** — ransom-note file drops + extension renames; sandbox-side
  heuristic covers live runs, but a Sigma file-event rule would close the
  offline layer too.
- **T1566.001 macro (7118 ev)** — Office spawning script interpreters; upstream
  Sigma has rules for this — review why none fired (possible parser field
  mapping issue, worth checking before writing anything new).

**C. Medium-value rule gaps:**
T1059.003 cmd_spawns_cscript (853 ev) / powershell_spawn_cmd (496 ev);
T1218 diskshadow / eviltwin / msix_ai_stubs / bitlockertogo; T1218.001 hh.exe;
T1218.005 mshta_tasks; T1620 reflective CLR load; T1574.002 msi_module_load ×2 /
sccm_adsource_dll / wineloader; T1036 msdtc_process_param /
suspicious_process_path / write_to_recycle_bin (848 ev); T1204.002
batch_file_in_system32 / single_letter_exe; T1059 suspiciously_named_executables;
T1556 disable_lsa_protection / disable_credential_guard; T1222.001 subinacl;
T1505.003 sharepoint_webshell; T1505.004; T1547.012 print_reg; T1068
bluehammer / redsun; T1135 net_share; T1114.001 email files outside dir;
T1595 sysmon_scanning_events (64 ev); T1055 sliver (6 ev — review; harness
covers this class live); T1027 trickbot_drop; T1059.001 ART /
powershell_remotesigned.

### Recommended follow-ups (ranked)
1. Verify the T1566.001 macro and T1047 WMI-lateral misses aren't *parser/
   field-mapping* bugs before writing rules — those two have abundant upstream
   rule coverage that should have fired.
2. New Sigma rules (sigma_rules_custom/ or upstream sync): AD-discovery
   commandlines, remote schtasks, LocalAccountTokenFilterPolicy, PhysicalDrive
   raw access, ransom-note filenames.
3. Re-run the validator after adding rules; target ≥90% dataset coverage
   excluding group A.

## Atomic Red Team campaign gaps (2026-09-21)

Outcome of the 55-sample ART batch (`scripts/verify_atomic_coverage.py`):
**40/55 stored verdicts ≥ expected** (42/55 effective — the T1082 pair flips on
re-detonation, replay-confirmed), 37/55 with expected technique in MITRE
coverage, 0 no-report. Corpus gate after all fixes: precision 1.000, recall
1.000, FPR 0.000. Below are the remaining misses with triage classification.

### Class 1 — score-8 single-medium-rule (fixable: weight bump or CAPE scoring)

One medium Sigma hit scores 8; suspicious starts at 10. Deliberate scoring
policy (one medium can never reach suspicious) — fix candidates are
medium→high bumps for high-confidence rules, or the CAPE-scoring experiment.

| atomic | technique | verdict | candidate fix |
|---|---|---|---|
| Obfuscated PowerShell via Character Array (art_T1027_obfuscated_powershell_command_via_character_arra.ps1) | T1027 | clean/8 | CAPE scoring |
| WMI Execute Local Process (art_T1047_wmi_execute_local_process.bat) | T1047 | clean/8 | bump `wmic process call create` rule medium→high |
| PowerShell Cmdlet Scheduled Task (art_T1053_005_powershell_cmdlet_scheduled_task.ps1) | T1053.005 | clean/8 | CAPE scoring |
| Lolbas replace.exe UNC copy (art_T1105_lolbas_replace_exe_use_to_copy_unc_file.bat) | T1105 | clean/8 | bump `replace.exe UNC copy` rule medium→high |
| Change PowerShell Execution Policy to Bypass (art_T1112_change_powershell_execution_policy_to_bypass.ps1) | T1112 | clean/8 | CAPE scoring |
| Rundll32 via FileProtocolHandler (art_T1218_011_rundll32_execute_command_via_fileprotocolhandler.bat) | T1218.011 | clean/8 | CAPE scoring |
| Wlrmdr LOLBin (art_T1218_system_binary_proxy_execution_wlrmdr_lolbin.ps1) | T1218 | clean/8 | CAPE scoring |
| Modify Service to Run Arbitrary Binary (art_T1543_003_modify_service_to_run_arbitrary_binary_powershel.ps1) | T1543.003 | clean/8 | CAPE scoring |

### Class 2 — fixed, awaiting re-detonation (stored reports stale)

| atomic | technique | stored | replay after fixes |
|---|---|---|---|
| System Information Discovery (art_T1082_system_information_discovery.bat) | T1082 | clean/8 | suspicious/16 (recon-chain correlation stacks) |
| Windows MachineGUID Discovery (art_T1082_windows_machineguid_discovery.bat) | T1082 | clean/0 | suspicious/15 (MachineGUID rule, high) |

### Class 3 — environment-truthful (won't fix; scoring them = FP trap)

| atomic | technique | verdict | reason |
|---|---|---|---|
| Process Discovery - tasklist (art_T1057_process_discovery_tasklist.bat) | T1057 | clean/0 | bare `tasklist` is normal admin activity; scored only inside recon-chain correlation |
| Enable Proxy Settings (art_T1112_enable_proxy_settings.bat) | T1112 | clean/0 | proxy-enable alone is legitimate enterprise config |
| Add persistence via Recycle Bin (art_T1547_001_add_persistance_via_recycle_bin.bat) | T1547.001 | clean/0 | HKCR CLSID `shell\open\command` key is TrustedInstaller-owned; elevated sample cannot write it — environment-truthful failure, rule kept for writable variants |

### Class 4 — telemetry-structural (cannot be fixed via EID 1)

| atomic | technique | verdict | reason |
|---|---|---|---|
| Suspicious Execution via cmd var-slice (art_T1059_003_suspicious_execution_via_windows_command_shell.bat) | T1059.003 | clean/0 | `%VAR:~-3,1%` slicing is expanded by cmd.exe before any child ProcessCreate exists — the obfuscated text never appears in telemetry. Rule kept for literal/unexpanded cases |
| Rundll32 VBScript via ordinal (art_T1218_011_rundll32_execute_vbscript_command_using_ordinal_.bat) | T1218.011 | clean/0 | needs review — likely same class or a missing community rule at min_level medium |

### TTP-coverage-only misses (verdict OK, technique not in MITRE matrix)

12 atomics alert fine but their expected technique isn't emitted in
`mitre_coverage` — a mapping-layer gap, not a scoring gap: T1016 ×2, T1033 ×2,
T1047 ×2, T1053.005 ×2, T1083, T1105, T1119, T1543.003, T1560. Candidate:
extend `orchestrator/mitre_mapping.py` for the discovery/lateral techniques
already fired on by the new custom rules.
