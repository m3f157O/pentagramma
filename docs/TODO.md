# PENTAGRAMMA — Work Queue (2026-09-05)

## 1. ~~Commit + push all uncommitted work~~ — DONE 2026-09-05
Gate PASSED (test split 27 runs: recall 1.000, fpr 0.000, precision(mal) 1.000).
Pushed: `46194dc` (noise reduction + FP fixes + corpora tooling) and `735ca57`
(adaptive window). Docs commit for gap-tracker attack-data section pending.

## 2. ART detonation batch + coverage audit — after gate
`scripts/detonate_corpus.py --worklist out\_art_missing.txt` (55 samples, ~2.5–3h),
then `scripts/verify_atomic_coverage.py --gaps` → gap tracker.

## 3. Real goodware detonation — after ART
4 `samples/goodware_real/*.exe` (7za, curl, plink, rg) staged + labeled, not yet detonated.

## 4. ~~Splunk attack-data results → detection-gap tracker~~ — DONE 2026-09-05
Full 342-dataset run: 276/339 (81%) covered, 448 rules. 63 zero-match datasets
triaged + grouped in docs/detection-gap-tracker.md. Follow-ups (new section):
verify T1566.001/T1047 aren't parser bugs, then new Sigma rules (AD discovery,
remote schtasks, LocalAccountTokenFilterPolicy, PhysicalDrive, ransom notes),
target ≥90% excl. out-of-scope.

## 5. Adaptive detonation window — IMPLEMENTED + COMMITTED (`735ca57`), live validation pending
Track whole sample tree (WMI BFS @1Hz); exit-stop on empty tree; idle-stop when
apitrace JSONL silent past min_window (45s) + idle_grace (30s); final dump on
idle-stop; kill whole tree; StoppedEarly (exit|idle|timeout) + AdaptiveWindowActive
+ TreePidsMax in execution_info; config `analysis.adaptive_window` (enabled,
gitignored — defaults preserve legacy behavior).
Pending (VM now free — gate + attack-data runs done): canary benign_control
(clean/0, exit-stop), InjectionHarness (90), staller (idle-stop early WITH final
dump), then gate rerun.

## Deferred bugs
- multi-file zip staging (side-loading malware + Sysinternals EULA blockers)
- fc7a60ad NoneType crash
- c7bbc23f zero-export DLL
- agenttesla socket drops
- flightsim network validation
- 2 emotet signatures
- network apitrace hooks
- Office in golden image
- WMI ETW fix
- Elastic RTA subset

## Future proposals (priority order)
1. ~~adaptive window~~ → in progress (above)
2. fake-C2/inetsim (top future value — revives dead-C2 stallers like emotet)
3. multi-file zip staging
4. emotet signatures
5. staller dump+rescan (folded into adaptive window: final dump on idle-stop)
6. network apitrace hooks
7. Office golden image
8. WMI ETW fix
