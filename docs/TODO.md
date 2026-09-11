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

## 5. ~~Adaptive detonation window~~ — DONE 2026-09-11, live-validated; commit pending gate
Full doc: `docs/adaptive-detonation-window.md`. Tree exit-stop w/ 30s floor,
idle-stop on apitrace silence, injected-process adoption (collector --pids-file),
final dump on idle-stop, descendant-only kill, StoppedEarly in execution_info.
Live validation: canary clean/0 exit-stop (null-guard bug found+fixed: `$null`
left in `-ne $null` guards on possibly-empty arrays), canary2 clean/8 (baseline
class, accepted), harness 90 + TreePidsMax 19 / AdoptedPidsMax 36, staller
idle-stop at 95s/300s WITH final dump.
Remaining: corpus gate rerun (RUNNING) → commit+push.

## Deferred bugs
- InjectionHarness `mapview` Sysmon gap (2026-09-11): victim process invisible to
  Sysmon entirely (no ProcessCreate, no EID 8 for its pid; apitrace sees all).
  Pre-existing (baseline a16ecb9e fails identically, 7/9 vs today 8/9). Detection
  still covered via apitrace/behavioral (verdict 90). Suspect early-run event
  burst + guest clock jump (snapshot-resume clock skew) or creation path Sysmon
  misses. Assertion: EID 8 TargetProcessId=<victim> in harness_assertions.py.
- ~~multi-file zip staging~~ → IMPLEMENTED 2026-09-11 (roadmap #3: sample_types.build_staging_zip + Copy-SampleFolderToVM + staging report section, 15 unit tests green); live validation pending gate
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
