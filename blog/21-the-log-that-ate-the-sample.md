# The log that ate the sample: 64MB of silent data loss

> **Series:** PENTAGRAMMA, part 21/? · **Draft skeleton** · Sources: probe reports `2a0ab731`, `6fddced4`, validation `16c2a335`, `agent/windows/sysmon_manager.py::set_log_size`

**Lede:** A two-second Atomic Red Team sample ran perfectly — stdout captured, registry queried, exit code 0 — and produced **zero** telemetry. Three times in a row. Other samples in the same batch were fine. The hunt consumed an entire day, three wrong theories, two reverted "fixes", and one accusation of clock tampering (our own) before an in-guest probe produced the number that explained everything: the Sysmon log is 64MB, a run now generates 90MB, and **the first slice of every analysis — the sample's launch chain — was being overwritten before anyone read it.**

## Outline

### The symptom that made no sense
- MachineGUID atomic: clean/0, reproducibly. Sysmon alive (60-90k events/run), rules loaded, other processes' events flowing in the same seconds. Only *loader → cmd → reg.exe* missing. The apitrace could see all three processes; Sysmon apparently couldn't.
- The selective pattern was the tell: it was never "some events" — it was exactly the sample's process chain, and exactly the *fast* samples that lost everything.

### Three wrong theories (and what each cost)
- **Clock skew, act 1:** the guest resumes from a saved-state snapshot with a 19-day-stale clock that oscillates before settling (proven: a probe's own stdout catches the clock jumping mid-run). Theory: stale-stamped events fall outside the collection window. Fix attempt: `Set-Date` at boot. Result: made things *worse* — a real-time baseline with stale-stamped samples is the worst combination.
- **Clock skew, act 2:** theory refined — filter by `EventRecordID`, monotonic, clock-immune. Correct hardening, wrong layer: the events weren't being filtered, they were *gone*.
- **The Set-Date accusation:** with the failure mode born in the first batch using clock sync, causality seemed obvious. Disabling it changed nothing. Correlation is not causation, even when it's your own change.

### The probe that ended it
- A `.bat` that runs as the sample and inspects the guest log from inside: full EID-1 dump (not a newest-5 tail — that mistake cost a theory), baseline file contents, and per-event record IDs.
- The smoking gun: chain events at record IDs **1322759/1322781** — present in the log, above the collection baseline — and the probe's canary at **1323947**, one megabyte later, the *only* one that survived into the report. The overwrite horizon fell exactly between them.
- `wevtutil gl`: `maxSize: 67108864, retention: false`. 64MB, overwrite-oldest. Run volume: 70–90MB (post-boot registry churn at ~1,600 ev/s plus a Defender signature-update storm mid-run). Yesterday's runs were ~50MB — under the line. That was the entire "why now".

### The fix and the validation
- One line at telemetry init: grow the channel to 512MB (`wevtutil sl ... /ms:`), ~5× worst case. No snapshot re-bake needed (agent is copied per run).
- MachineGUID atomic: clean/0 ×4 → **suspicious/15**, full chain visible, rule firing. sysinfo's missing half returned (8→16). Bonus: the record-ID baseline and a Sysmon EID-1 readiness gate stay as permanent hardening — cheap, and right for the wrong reasons.

**Takeaway:** a fixed-size buffer with overwrite retention is a silent data-loss machine, and its failure mode is shapeshifting: it looks like a clock bug, a driver bug, a config bug, a race — anything except "the log is full". When telemetry is selectively missing, check *capacity* before you check *logic*. And when a fast sample is invisible: the events you lose first are always the ones that happened first.

---
*Status: skeleton. Needs: the record-ID table from probe `6fddced4` as a figure; a note on why the readiness probe couldn't see this (its canary is always freshly written, always inside the horizon); follow-up on trimming the registry-noise flood that pushed runs over 64MB.*
