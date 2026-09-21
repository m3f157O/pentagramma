# The sandbox that flagged itself: when your instrumentation scores malicious/45

> **Series:** PENTAGRAMMA, part 22/? · **Draft skeleton** · Sources: `orchestrator/reporting.py::_monitor_injection_markers`, `orchestrator/heuristics.py` (path-less MpTest), reports `660d8cae` (rg.exe), `d798eaac` (guid)

**Lede:** We detonated four famously benign tools — 7-Zip, curl, plink, ripgrep — to strengthen the false-positive gate. The gate caught something, all right: ripgrep scored **malicious/45**, and its top "evidence" was a textbook process-injection chain — `NtWriteVirtualMemory` + `NtCreateThreadEx` + `NtResumeThread` into a remote process. The injector was us. The sandbox's own monitor loader, doing exactly what it's designed to do, scored as the most critical behavior class we track.

## Outline

### ripgrep the "process injector"
- Verdict breakdown: +25 *"Write into remote process followed by thread start/resume"* — that's the loader injecting `monitor_x64.dll` into the sample it just created suspended; +15 static YARA (`cmd.exe /e:ON /v:OFF /d /c` is a real string inside ripgrep's binary); +5 unsigned.
- Why it was invisible for months: the behavioral-signature engine correctly excluded own-tooling — but it identified the loader through its **ProcessCreate event**, and any run where that event is missing (see part 21) leaves the loader unidentified and its injection fully scoreable. Script samples mostly dodged it; EXEs that spawn children took the full +25.
- It had been silently inflating malware scores too — two of the previous day's "fixed" ART verdicts turned out to be self-injection artifacts, not rule improvements.

### Making tooling identifiable by construction
- The fix isn't a better heuristic — it's a better *identity source*. The guardian driver already announces every injection it places (`GuardianInjectionPlaced`), and the apitrace's first `__monitor_attached__` is always the loader. Alert actor == trace root **and** target == guardian-placed ⇒ instrumentation, de-scoped with `scope_reason` for forensics. Works with zero Sysmon events.
- Replays: rg 45→(live) clean/5, plink 15→0, curl 23→8, 7za 28→13. InjectionHarness — whose injections are genuine and from a *different* pid — untouched at malicious/90.

### The sequel nobody ordered: our own AMSI probe, +25
- With the log-wrap fixed (part 21), a new artifact surfaced: `Virus:Win32/MpTest!amsi` scoring on a benign atomic. That's the readiness probe's canonical test string — its detection event landed *late* (past the Defender-log clear), and the tooling filter compared its real timestamp against the sample's *stale-stamped* ProcessCreate. Comparison inverted; our own probe became "sample behavior".
- Fix: path-less MpTest detections are the probe by construction (it fires the string via a command line); samples that print the test string produce detections *with a file path* and still score. The amsi canary confirms.

### The renamed-goodware footnote
- plink/curl/7za also scored suspicious — on vendored "renamed binary" Sigma rules, because we staged them as `gw_real_*.exe`. A renamed plink *is* suspicious; the detection was honest, the filename was the artifact. Real names restored.

**Takeaway:** in a sandbox, your instrumentation is the most privileged malware on the box — it injects, hooks, and fires test malware on every run. Every piece of it must be identifiable **by construction** (explicit markers, emitted always) — never by telemetry that can go missing, and never by timestamp comparisons against a clock you don't control. The FP gate did its job; it just graded *us* first.

---
*Status: skeleton. Needs: the rg.exe verdict table as a figure; a paragraph on the YARA `suspicious_cmd_commands` PE-threshold change (2+ strings) as the third self-inflicted FP of the day.*
