# Ground truth: 138 real malware samples vs our sandbox

> **Series:** PENTAGRAMMA, part 11/11 · **Draft skeleton** · Sources: `out/batch_138_summary.md`, `docs/blog-series-timeline.md` §2026-09-04/05, corpus tooling (`verify_groundtruth.py`, `label_from_manifests.py`, …)

**Lede:** Two months ago we admitted our metrics were in-sample fit on 19 hand-written scripts. So we pulled 138 real malware samples from abuse.ch — six families, with community ground-truth labels — detonated them all in a 10-hour unattended batch, and counted. **Of the 107 samples that actually executed: 95 malicious, 12 suspicious, 0 clean. Zero false negatives.** And the 26 "clean" reports turned out to be the most interesting part.

## Outline

### Building a corpus you can trust
- abuse.ch (MalwareBazaar/ThreatFox) with family labels: agenttesla 17, asyncrat 24, emotet 52, qakbot 24, redline 1, remcos 20.
- Ground truth cross-checked: ThreatFox per-hash IOCs (too sparse — 3/138) + ATT&CK STIX family techniques (`family_ttps.json`).
- Zips stay passworded on disk; decrypted in memory at submit (AES-zip pyzipper fallback included).

### The batch
- `detonate_corpus.py` over all 138, ~4.7 min/sample, ~10h, one VM cycling snapshots. 5 transient infra failures over 10h, all auto-recovered.
- Headline table:
  - All matched reports (133): 95 mal / 29 susp / 9 clean, avg 61.2
  - **Runs that actually executed (107): 95 mal (89%) / 12 susp (11%) / 0 clean, avg 73.5**

### The twist: "clean" meant "never ran"
- All 26 zero-event reports: **DLLs the orchestrator never executed** — 25× `ambiguous_entry_point` (multiple exports, no `DllRegisterServer` → rundll32 skips; qakbot exports `IDMMzCC_*` junk), 1× `no_exports_found`.
- Their 5–38 "static-only" scores say nothing about detection. **Qakbot's apparent 12.5 average was an artifact — only 3 qakbot samples ever ran.**
- Fix: forced-entry-point re-run (`dll_entry_point=<first export>` — DllMain executes on load). *31-sample re-run in progress at writing.*
- Lesson: in sandbox measurement, **"did it execute?" is a metric before "did we detect it?"** — verify execution (event counts, process tree) before trusting any verdict distribution.

### Per-family scoreboard (real runs)
| family | n | mal/susp | avg |
|---|---|---|---|
| asyncrat | 24 | 24/0 | 90.4 |
| redline | 1 | 1/0 | 98 |
| remcos | 20 | 19/1 | 77.6 |
| agenttesla | 12 | 12/0 | 81.0 |
| emotet | 47 | 38/9 | 63.2 |
| qakbot | 3 | 1/2 | 27.7 |

### The genuine gap: emotet at "suspicious"
- 9/47 real emotet runs scored 15–38 — the one true detection-quality follow-up (plus one remcos outlier at 28). What does emotet do that our families of detectors weigh too lightly? **Resolved in part 14: dead-C2 starvation, not a detection gap — those samples are behaviorally inert.**

### What changes after ground truth
- Per-family C2-recall and behavior-coverage verification (`verify_c2_recall.py`, `verify_family_behavior.py`) against ATT&CK family TTPs; train/test split with Wilson CIs — the 19-script confession from part 3, properly paid off.

**Takeaway:** ground truth doesn't just validate detections — it audits your *harness*. Half of our "misses" were launch mechanics, and finding that was worth the whole batch.

---
*Status: skeleton. Update 2026-09-12: forced-entry re-run completed; corpus now 152 labels with stratified train/test splits; emotet cliffhanger resolved (part 14); gate stands at recall 1.000 / FPR 0.000. Still needs: ROC/precision-recall with CIs in final prose.*
