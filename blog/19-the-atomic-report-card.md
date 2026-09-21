# The atomic report card: 55 red-team atomics vs the sandbox, and the discipline of not fixing things

> **Series:** PENTAGRAMMA, part 19/? · **Draft skeleton** · Sources: git `d1c2761`, `0dd49b5`, `sigma_rules_custom/`, `scripts/verify_atomic_coverage.py`, `docs/detection-gap-tracker.md`

**Lede:** Atomic Red Team is the exam where every question is public — 55 little attacks, each one a known technique, each one *supposed* to be caught. We scored 36/55. The interesting part isn't the 19 misses; it's that closing them required saying "no" to most of the obvious fixes, because every one of them was a false-positive machine in disguise.

## Outline

### Running the batch (and the infrastructure fighting back)
- 55 atomics (23 techniques, `build_atomic_corpus.py` from the ART yaml) through the live queue — the batch that took three attempts: a dead CLI session killed the first run, a `UnicodeDecodeError` in a subprocess reader thread silently truncated telemetry (cp1252 vs UTF-8, Italian Windows), and the first job after every snapshot revert raced the guest boot — PSDirect lags the IP address by 2–3 minutes, so `Copy-Agent` died with "socket Hyper-V terminated" until `Invoke-AnalysisCommand` learned to retry transient transport errors for up to 4 minutes.
- The coverage audit itself was broken in two places (stale import, MITRE schema drift) and reported **0 TTP coverage that didn't exist**. Grading the grader, again: the audit tool gets audited too.

### The scoreboard
- Stored verdicts: **36 → 40/55** after fixes (42/55 counting replayed older runs under the new ruleset). TTP attribution: 37/55.
- Strong: credential dumping, PowerShell, rundll32/mshta, registry TTP 11/11, autostart persistence 7/8.
- The miss classes, honestly: read-only recon scored clean/0, quiet single registry writes scored 0–8, seven samples stuck at "one medium rule = 8 < suspicious-at-10".

### The eight rules we wrote
- Recon-**chain** correlation (≥2 discovery commands/60s per shell — the burst is the signal, not the command), MachineGUID reg-query fingerprinting, prefetch-disable, CredSSP `AllowEncryptionOracle=2`, `fsutil usn deletejournal`, TelemetryController persistence, Recycle-Bin CLSID hijack, negative-offset `%VAR:~-3,1%` obfuscation.

### The fixes we refused (the actual lesson)
- Lowering the suspicious threshold 10→8: the entire severity model exists so one medium rule ≠ verdict. Highest-FP change available; declined.
- `sigma.min_level: medium → low`: imports the whole long tail of vague community rules. Declined.
- Scoring a bare `tasklist`: fires on every admin script on Earth. The ART expectation loses to the FP budget. Declined — the chain rule is the defensible version.
- Proxy-enable, generic HKLM writes: VPN clients and installers. Declined.
- Validation that the discipline worked: labeled-corpus replay **precision 1.000 / recall 1.000 / FPR 0.000**, boundary goodware 9/9 suspicious-ok with zero malicious, canaries untouched (bat 0, tier1 8, harness malicious/90).

**Takeaway:** a recall gap is a hypothesis, not a bug list. The temptation is to turn every miss into a rule; the job is to find the misses that are *rules-shaped* — specific, unambiguous, cheap to verify — and to leave the rest as documented, deliberate blindness.

---
*Status: skeleton. Needs: link to part 20 (the environment fix that came out of this batch); final stored-verdict numbers once the T1082 pair is re-detonated under the new ruleset.*
