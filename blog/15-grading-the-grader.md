# Grading the grader: goodware gates, attack-data validation, and quieter guests

> **Series:** PENTAGRAMMA, part 15/? · **Draft skeleton** · Sources: git `46194dc`, `5002531`, `8b38782`, `ac597a8`, `docs/TODO.md`

**Lede:** Detection quality has two axes, and recall is the flattering one. The other side — proving the sandbox stays quiet when nothing is wrong, and proving Sigma rules fire on *someone else's* attack data, not just our own samples — is where the unglamorous work went this week: −64% guest noise, a two-tier goodware contract, 339 third-party attack datasets, and a zip feature that turned out to be a report-bug hunt.

## Outline

### Quieting the guest (−64% events)
- OS-noise reduction across all three layers (Sysmon config / Guardian / golden-image provisioning, `apply_noise_reduction.py`). Canary stayed clean/0 while raw event volume dropped 64% — every surviving event is now cheaper to trust and faster to triage.
- Tooling-FP suppression: the monitor's own injection artifacts no longer alert; dump-YARA excludes interpreter-memory rules; `suspicious_powershell_download` rewritten with invocation-context regexes.

### The two-tier goodware contract
- Not all goodware is equal: a signed system binary must stay **clean**, but a Python interpreter doing Python things may legitimately look *suspicious*. Labels split into `goodware` (must stay clean) vs `goodware_boundary` (suspicious tolerated, malicious = gate failure, `MAX_BOUNDARY_MALICIOUS=0`).
- Gate floors: recall(susp+) ≥ 0.90, FPR ≤ 0.20, precision(mal) ≥ 0.90, zero boundary-malicious. Current: 27-run test split — recall 1.000, FPR 0.000, precision 1.000.
- Lesson: "aggressive scoring" and "zero false positives" aren't enemies if your gate admits the boundary class exists.

### Someone else's attacks: Splunk attack-data × Sigma
- Our Sigma rules had only ever been graded on our own telemetry. We ran **339 Splunk attack-data datasets** (independent ATT&CK-labeled telemetry) through the offline evaluator: **276/339 covered**, 448 rules exercised, and the 63 zero-match datasets triaged one by one (most: rule expects Sysmon fields the dataset doesn't emit — collector mismatch, not rule weakness).
- Plus an Atomic Red Team corpus builder + coverage verifier — 55 technique samples queued for a live detonation batch.

### Zip staging: a feature that found two bugs
- Multi-file zip submissions now extract **all** entries into the guest working dir before launch (zip-slip-proof repack by construction: traversal pop-and-clamp, drive-strip, dedup, caps, AES fallback) — sibling DLL side-loading and nested configs resolve next to the payload. Live-validated: marker strings `SIBLING_DLL_OK`, `NESTED_CONFIG_OK`.
- Bug 1 (found by live validation): the report builder's key whitelist was *silently dropping* the staging manifest — one line, one lesson in whitelist serialization.
- Bug 2: none in staging — but the validation batch's canary flagged the recycled-PID correlator bug → part 13.

**Takeaway:** precision work doesn't demo well, but it's what makes recall numbers worth publishing. And every feature you ship is an audit of something else — the zip feature's real deliverable was two bugs in code that already existed.

---
*Status: skeleton. Needs: ART batch results when the 55-sample run completes; goodware_real detonation numbers.*
