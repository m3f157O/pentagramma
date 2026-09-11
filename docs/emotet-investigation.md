# Emotet detection-quality investigation (2026-09-05)

**Question:** why did 10/50 real emotet runs in the 138-sample ground truth score only
"suspicious" (13–38) while the family average lagged all others (~63)?

**Answer:** the weak runs are *behaviorally inert*, not mis-scored. The payload never
performs, so there is almost nothing to detect. Root cause is environmental
(2022-era Emotet C2 infrastructure is dead/seized), not a detection-engine gap.

## Evidence

Per-run forensics: `scripts/_emotet_forensics.py` → `out/emotet_forensics.json`
(latest report per sha, 51 runs).

Weak runs split into two patterns:

| Pattern | Samples | Signature in telemetry |
|---|---|---|
| Alive but silent (TimedOut) | 8afc54bf(13), 1b87f2ef(15), 9165bc75(15), a4e1a5b0(23), a45317c3(38) | 44–830 ApiCalls (vs 3–3.5k in strong runs), apitrace stops 9–54 s in, process still alive at the 120 s timeout, ≤1 Sysmon event after last API call |

> **Follow-up (2026-09-11):** this alive-but-silent class is exactly what the
> adaptive detonation window now idle-stops — apitrace silent for 30s past the
> 45s minimum window → stop with a final memory dump (`StoppedEarly: 'idle'`).
> See `docs/adaptive-detonation-window.md`. The real unlock for stage-2
> behavior remains the fake-C2 responder (roadmap #1).
| Exits voluntarily <90 s | 396e6e07(21), 540dfbef(21), 09bdb0fb(25), f10052e1(29), 5d4ad664(34) | Exit=0, event window 26–90 s, no children, no drops |

Mechanism, confirmed on the raw events (e.g. report `2ce1e373` / 8afc54bf):
1. Stage-1 unpacks in memory — NtAllocateVirtualMemory/NtProtectVirtualMemory→EXEC
   burst (this is where most of the 8–10 static-ish points come from).
2. Sample attempts C2 over **direct-IP:443 with zero DNS lookups** (hardcoded IP
   lists; e.g. 6× `74.178.240.51`, 5× `134.33.185.96`). These 2022 Emotet C2s are
   dead → stage-2 waits for tasking that never comes → idles (alive) or gives up
   (exit 0).
3. No child processes, no dropped files, no injection chain, no Defender hit →
   none of the 15–25-pt behavioral reasons that carry strong runs (NtResumeThread
   remote resume, token theft, mass file modification, `Emotet.*!MTB`) can fire.

The earlier "weak runs beacon heavily" reading was wrong: bulk network/DNS volume
in those reports is OS noise (Default-Switch gateway `172.18.144.1`, Microsoft
telemetry domains); sample-attributable traffic is a handful of dead-C2 retries.

This is **not deliberate sandbox evasion**: the samples attempt C2 *immediately*
(no sleep/timing-loop first) and the voluntary exits happen well before the window
ends. One run (`a4e1a5b0`) carries anti-VM strings per capa, but it too made its
dead-C2 attempts. Caveat: a 120 s window cannot distinguish "idle forever" from
"slow fuse >2 min"; a single 600 s re-run of e.g. `8afc54bf` would settle it, but
the C2-retry-then-idle pattern strongly favors starvation.

## Verdict on the "gap"

- Detection engine: working as intended. Weak runs got exactly the evidence they
  produced (packed + unsigned + memprotect + a couple of generic Sigma hits).
- Realistic detection-side additions, if ever wanted: (a) "repeated direct-IP:443
  connects with no DNS lookup" (fires on ≥7/10 weak runs, ~high), (b) "unpacking
  burst then apitrace-silent while process alive" (fires on the 5 alive-but-silent
  runs). Expected effect: 3–5 of the 10 cross the malicious line; the rest are
  genuinely evidence-poor. **Deferred** — not implemented.
- The only durable fix for the stallers would be a fake-C2/inet-sim responder —
  a large feature, out of scope.

## Tooling bugs fixed along the way (this was the real yield)

- `orchestrator/jobs.py` — job failures now persist the full traceback
  (`error_traceback` job field + logger); previously only `str(exc)` survived,
  which made the `fc7a60ad` NoneType crash undebuggable. *(Needs orchestrator
  restart to take effect.)*
- `scripts/label_from_manifests.py` — was `json.loads()`-ing a truncated 200 KB
  head, which silently skipped **every** large report; only 51/185 detonated
  manifest samples were ever labeled. Fixed with a head-regex (`_report_head`);
  labels.json went 19 → 152 entries.
- `scripts/verify_family_behavior.py` — same truncated-parse bug, plus the
  ATT&CK layer read `entry["techniques"]` while reports store `entry["mitre"]`
  → TTP overlap was 0 for **every** family. Fixed: 132/133 now pass (emotet 50/51).
- `scripts/verify_c2_recall.py` — same truncated-parse fix.
- `scripts/detection_metrics.py` — latest-report-per-sha supersession: re-run
  reports (v2 fixes) now replace zero-event first attempts instead of
  double-counting the sample; superseded runs are reported in `counts`.

## Current corpus metrics (post-fix chain)

- `label_from_manifests.py` → `corpus_split.py` → `verify_family_behavior.py` →
  `verify_c2_recall.py` all run; outputs in `out/family_verify.json`,
  `out/c2_recall.json`; splits in `tests/corpus/splits.json` (emotet 41 train /
  10 test, stratified).
- Family verify: 133 samples, 119 malicious / 14 suspicious, 0 clean;
  emotet 51: 40 malicious / 11 suspicious (10 inert + `c7bbc23f` zero-export).
- YARA family-classification layer is weak for emotet (3/51) — the extended
  ruleset matches only some packer variants statically; verdict layer carries
  the load. Noted, not treated as a bug.
- C2 recall: ThreatFox ground truth only exists for asyncrat (3 samples, 0/3
  IOCs observed — dead infrastructure again); emotet has no ground-truth IOCs.
- Known remaining bugs (unchanged, documented): `fc7a60ad` launch-path NoneType
  crash (now debuggable via traceback), `c7bbc23f` zero-export DLL needs a
  LoadLibrary-runner, 4× agenttesla PSDirect drops.
