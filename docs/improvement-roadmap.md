# Improvement roadmap (as of 2026-09-11)

Prioritized list of proposed improvements, reviewed and ordered with the user.
Status legend: **doing** / proposed / done / rejected.

## Current focus

| # | Item | Value | Effort | Status |
|---|---|---|---|---|
| 2 | **Adaptive detonation window** — track the whole sample process tree (not just root); early-stop when tree is gone; idle-stop when apitrace is silent for `idle_grace` after `min_window`; ALWAYS final-dump on idle-stop (stalled process holds the payload); `StoppedEarly = exit/idle/timeout` in report; config `analysis.adaptive_window.*`. Also FIXES a detection gap: today collectors tear down when the root exits even if children live on | throughput ×1.5–2 on staller-heavy batches + child-follow fix | medium | **doing** |

## Up next (agreed order)

| # | Item | Value | Effort | Status |
|---|---|---|---|---|
| 1 | **Fake-C2 / inetsim responder** — packed families (emotet) unpack then starve retrying seized 2022-era C2 IPs; answering those connections unlocks stage-2 payload behavior. Top detection-yield improvement. Guest DNS/hosts redirect + responder service | ★★★ | high | proposed |
| 4 | **2 deferred emotet signatures** (from `docs/emotet-investigation.md`): (a) repeated direct-IP:443 C2 retries with zero DNS; (b) unpack-then-silent (stage-2 written, no follow-on). Forensics in `out/emotet_forensics.json` | ★★ | low | proposed |
| 3 | **Multi-file zip staging** — today only the chosen zip entry is staged guest-side (`main.py` → `resolve_archive_entry`); stage ALL entries in the guest working dir. Helps real droppers w/ side-by-side DLLs AND Sysinternals goodware (EULA runner bat) | ★★ | medium | proposed |
| 5 | **Staller memory-dump + YARA rescan tuning** — mostly delivered by adaptive window's idle-stop final dump; tune dump timing/count for stall-then-unpack samples | ★★ | low (after #2) | proposed |
| 6 | **Network apitrace hooks** (connect/send/recv/WSA*) — socket-level intel beyond Sysmon EID3; would also make idle-stop's activity signal cover network-only samples | ★★ | high (C++) | proposed |
| 7 | **Office in golden image** — enables document-borne families (emotet/qakbot docs) | ★★ | medium | proposed |
| 8 | **Deferred bugs**: `fc7a60ad` NoneType crash (now debuggable via traceback logging); `c7bbc23f` zero-export DLL needs LoadLibrary-runner; 4× agenttesla PSDirect socket drops; WMI ETW fix; golden-image live test of `provision_golden_image.ps1`; archive cleanup re-run | correctness | low-med | deferred |

## Validation/corpus work (done or in flight)

| Item | Status |
|---|---|
| OS-noise reduction (3 layers) | **done** — canary clean/0, events −64% |
| Goodware corpus growth: 20 synthetic (9 neutral + 11 boundary tiers) + 4 real binaries (plink/curl/7za/rg) + `MAX_BOUNDARY_MALICIOUS=0` gate | **done** |
| FP-artifact fixes: monitor-loader injection suppression, staging-extension Sigma suppression, dump-YARA interpreter-rule exclusion, `suspicious_powershell_download` tightening (backup in `backups/yara-20260911/`) | **done** |
| Atomic Red Team recall audit (55 curated atomics + `verify_atomic_coverage.py`) | **in flight** (detonation batch) |
| Splunk Attack Data offline Sigma validation (342 datasets, `validate_sigma_attack_data.py`) | **in flight** |

## Explicitly rejected (with reason)

| Item | Reason |
|---|---|
| Downweighting genuine Sigma/CAPE hits on attack-shaped behavior (class 5) | Hostile-input sandbox stays aggressive by design; boundary goodware scored "suspicious" is the detector WORKING — measured via the boundary tier instead |
| Removing baseline micro-points (class 4) wholesale | Same aggressive stance; revisit ONLY if neutral goodware shows baseline-driven FPs in gate output |

## Future validation sources (surveyed 2026-09-11)

- **Elastic RTA** (depth: injection/timestomp binary — apitrace layer)
- **Network Flight Simulator** (network-layer validation; needs VM outbound probe)
- **More MalwareBazaar families** via existing ground-truth pipeline (FormBook, Lokibot, NanoCore, njRAT, DarkGate, IcedID)
- **APTSimulator** one-shot broad smoke test
- Sysinternals goodware (blocked on multi-file staging, #3)
