# Detection-quality tooling reference

Offline tooling over saved reports. All run with `.venv\Scripts\python.exe` from the repo root; none need the VM. The replay uses **on-disk code + current rulesets** — divergence between a stored verdict and a replayed verdict means the running server was stale, or detection code/rules changed since the capture.

## `scripts\replay_detection.py`

Rebuilds a report's full detection (heuristics + Sigma + YARA-on-dumps + behavioral + CAPE + PID-lineage scoping + verdict) from its stored telemetry.

```
python scripts\replay_detection.py <id> [<id>...] [--json] [--changed-only]
python scripts\replay_detection.py --all [--json]
```

Use after ANY detection change: replay the canaries (and ideally a few corpus reports) before trusting a live detonation.

## `scripts\compare_reports.py`

Diffs two report JSONs: new EIDs, event-count deltas, missing expected events. Use when changing telemetry collection (monitor hooks, sysmonconfig, collectors) rather than detection logic.

## `scripts\detection_metrics.py`

Precision/recall/FPR over the labeled corpus (`tests\corpus\labels.json`; splits in `tests\corpus\splits.json`).

```
python scripts\detection_metrics.py [--json] [--markdown <path>] [--split all|train|test] [--bootstrap]
```

`--bootstrap` emits a labeling worklist without replaying. Wilson score CIs are rendered next to rates; treat wide CIs as "unknown", not "good".

## `scripts\calibrate_verdict.py`

Replays each labeled report to (label, family, score) and tunes verdict weights/thresholds. Train-split only once splits exist — never calibrate on the test split.

## `scripts\harness_assertions.py <report.json> [--save-baseline]`

Asserts an InjectionHarness run produced the per-technique expected signals (specs in `EXPECTED_TECHNIQUES`; mirror: `orchestrator\harness_validation.py` — keep in sync). Two spec kinds: Sysmon EID + pid_field (+ Type fragments), and behavioral alert (`alert_event_type` + pid-templated fragment). `--save-baseline` refreshes `tests\harness_baselines.json` after intentional telemetry changes.

## Canary contract (must hold after every detection change)

| Sample | Expected |
|---|---|
| `test-sample.bat` (benign) | `suspicious`, zero behavioral alerts; score **12**, or **37** if Defender's AMSI self-test (`Virus:Win32/MpTest!amsi`, +25) fires in-window — probabilistic, accepted noise |
| `test-tier1-crypto.ps1` (benign) | same |
| `InjectionHarness.exe` | `malicious/90`; `harness_assertions.py` 9/9 PASS |

Historical note: old benign reports may replay to a different score than stored (stored verdicts were computed by pre-FP-fix code; replay is the truth).

## Corpus gates

`tests\test_corpus_metrics.py` / `test_detection_quality.py` replay the labeled corpus (SLOW — ~19 reports × ~40k events, several minutes). Current green state: 116 runs, recall(susp+) 0.990, precision(mal) 1.000, FPR driven by the benign-pair AMSI artifact. Workstream A (real in-the-wild corpus + train/test split) is pending; today's corpus is 19 hand-curated scripts — treat the metrics as in-sample until then.
