# Speed-running Sigma: a literal-anchor prefilter

> **Series:** PENTAGRAMMA, part 10/11 · **Draft skeleton** · Sources: `docs/handoff-2026-09-03.md` (perf pack, 2026-09-04), `orchestrator/sigma_engine.py`, `tests/test_sigma_prefilter.py`

**Lede:** A busy detonation produces 83k Sysmon events; matching 1,859 Sigma rules against every event took 88 seconds of pure CPU per report. We added a literal-anchor prefilter — decide in microseconds whether a rule *can* match before evaluating it — and got **88s → 33s** with byte-identical alerts. Here's the trick, and the proof it's safe.

## Outline

### Where the time actually goes
- Profiled a sample's analysis end-to-end (this started as "what is the time per sample?"): Sigma matching dominated the offline pipeline, not YARA, not capa.
- 1,859 rules × 83k events, mostly rules that could never match the event in front of them.

### The prefilter: Boolean-algebra anchors
- Parse each rule's selection conditions; extract **literal anchors** (the longest literal parts — "must-contain" strings) combined with the rule's boolean structure.
- At match time: lowercase-cache the event's fields once, substring-check anchors; only run the full evaluator for rules whose anchors pass.
- **1,105 of 1,859 rules anchored.** v1→v4 iterations: naive anchors → longest-part → cached → Boolean-algebra (correct handling of OR/NOT branches — the version that's actually sound).

### The part that makes it publishable: byte-identical proof
- A/B harness (`scripts/_sigma_prefilter_ab.py`): same corpus events through old engine and new engine — **alerts byte-identical** across 4 validation generations.
- A prefilter that's "probably equivalent" is a detection regression waiting to happen; we didn't ship until the outputs diffed clean.
- Result: **1.2–2.4× faster end-to-end; 88s → 33s on the 83k-event report.** Canary replay: zero verdict drift.

### Bonus: overlap the VM with the CPU work
- Static analysis (YARA/capa/.NET) doesn't need the VM — moved it to a thread that runs *during* the detonation window (`static_holder`, joined at collection).
- Wall-time per sample drops; the batch pipeline thanks you (→ part 11's ~4.7 min/sample).

**Takeaway:** the fastest rule evaluation is the one you can prove unnecessary — and "proved" means byte-identical output, not vibes.

---
*Status: skeleton. Needs: anchor extraction example (one real rule), timing chart, A/B harness excerpt.*
