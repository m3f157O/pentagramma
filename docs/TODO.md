# PENTAGRAMMA — Work Queue (2026-09-05)

## 1. Commit + push all uncommitted work — BLOCKED on corpus gate
Gate (pid 27780) replaying ~152 reports with boundary-tier gates must PASS first.
Uncommitted: reporting.py, heuristics.py, yara/suspicious_strings.yar (+.bak),
tests/corpus/labels.json, detection_metrics.py, test_corpus_metrics.py,
test_tooling_attribution.py, ART tooling, goodware samples, README, this file,
noise-reduction files. (blog/ stays uncommitted per user pref.)

## 2. ART detonation batch + coverage audit — after gate
`scripts/detonate_corpus.py --worklist out\_art_missing.txt` (55 samples, ~2.5–3h),
then `scripts/verify_atomic_coverage.py --gaps` → gap tracker.

## 3. Real goodware detonation — after ART
4 `samples/goodware_real/*.exe` (7za, curl, plink, rg) staged + labeled, not yet detonated.

## 4. Splunk attack-data results → detection-gap tracker
Full 342-dataset run in progress (pid 17904); pilot was 10/10 datasets, 53 rules.

## 5. Adaptive detonation window — IMPLEMENTED, live validation pending (VM busy until gate done)
Track whole sample tree (WMI BFS @1Hz); exit-stop on empty tree; idle-stop when
apitrace JSONL silent past min_window (45s) + idle_grace (30s); final dump on
idle-stop; kill whole tree; StoppedEarly (exit|idle|timeout) + AdaptiveWindowActive
+ TreePidsMax in execution_info; config `analysis.adaptive_window` (enabled).
Done: hyperv-vm.ps1 Execute-Sample, hyperv.py params, executor.py plumbing,
config.yaml. PS1 parse OK, 121 unit tests pass.
Pending: canary benign_control (clean/0, exit-stop), InjectionHarness (90),
staller (idle-stop early WITH final dump), then gate rerun.

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
