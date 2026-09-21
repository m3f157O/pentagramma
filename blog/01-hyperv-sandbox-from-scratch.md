# Building a malware sandbox on Hyper-V from scratch

> **Series:** PENTAGRAMMA, part 1/11 · **Draft skeleton** · Sources: `docs/blog-series-timeline.md` §2026-06-15→07-01, `docs/etw-vs-sysmon.md`, README

**Lede:** Every malware-analysis setup guide starts with "install VirtualBox, install Cuckoo." We went the other way: Windows' own hypervisor, a hand-rolled orchestrator, and a guest agent built from spare parts. Three months later it scores real malware families 90/100. This is how the foundation was poured — and the decisions that aged well (and the one that didn't).

## Outline

### Why build one at all
- Cuckoo/CAPE: heavy, legacy pains, config sprawl — wanted a system we fully understand end-to-end.
- Goal: deterministic, snapshot-reverted detonation with *complete* telemetry ownership.
- *[placeholder: screenshot of the report list UI]*

### Why Hyper-V
- Already on the host; no third-party hypervisor attack surface; checkpoints are instant; **PSDirect** (PowerShell Direct) gives file/exec into the guest with no network.
- Cost discovered later: PSDirect sessions are **non-interactive** (→ part 9).
- VM spec: `pentagramma`, 4 GB, golden snapshot `SANDBOX_READY`, revert-before-every-run.

### Architecture in one picture
- Host: FastAPI orchestrator (:18000) → job queue → Hyper-V executor → report pipeline (Sysmon+Sigma, heuristics, YARA, capa, verdict).
- Guest: `C:\SandboxAgent` (Python 3.11), Sysmon, apitrace monitor DLL, AMSI/Defender collectors.
- *[placeholder: architecture diagram]*

### The first real decision: Sysmon vs ETW (2026-07-01)
- Picked **Sysmon as the telemetry spine**, ETW only as gap-filler — full coverage matrix in `docs/etw-vs-sysmon.md`.
- 5 ETW providers worth keeping: ETW-TI, AMSI, PS script-block, Defender, .NET runtime.
- Fun empirical find: the commonly-cited AMSI ETW provider GUID is wrong; the real one is `{2a576b87-...}`.
- Honest footnote: what both miss — kernel rootkits, encrypted C2, fileless, ETW tampering (this footnote becomes part 7's entire motivation).

### What aged well / what didn't
- ✅ Sysmon spine, snapshot discipline, "everything lands in one JSON report."
- ❌ "The config is correct because it parses" — see part 2.

**Takeaway:** you don't need a big framework to detonate malware safely — you need a snapshot you trust, one telemetry spine, and the humility to verify empirically.

---
*Status: skeleton. Needs: architecture diagram, UI screenshots, code snippets of executor/snapshot cycle.*
