# Replaying 758 CAPE signatures offline

> **Series:** PENTAGRAMMA, part 4/11 · **Draft skeleton** · Sources: `docs/cape-integration.md` (2026-07-27), `orchestrator/cape_engine.py`

**Lede:** The CAPE sandbox community has spent years writing behavioral signatures — 458 Python modules of hard-won malware knowledge. We vendored the whole corpus and replayed it over our apitrace stream: **758 unique signature classes**, zero new telemetry required. Free detection content, with two catches.

## Outline

### The idea
- CAPE signatures consume API-call streams. We have an API-call stream. Translate, don't reinvent.
- 458 modules → **758 signature classes** (many modules define multiple behaviors).
- 4 load errors; the rest compile into our replay engine.

### Reachability: the number nobody publishes
- Only **521 (69%)** are statically reachable with our 37-hook set.
- 153 need APIs we don't hook; 41 need network results; 43 need disk/YARA blocks.
- Lesson: "we support CAPE signatures" is meaningless without a reachability audit.
- *[placeholder: reachability pie chart]*

### Enrichment, not verdict (on purpose)
- `cape_signatures.score: false` — community signatures annotate the report but can't move the score until corpus-validated (→ part 11).
- Unknown FP rate + verdict weight = how you get a sandbox that cries malicious on installers.

### The two FP guards (validated on live runs)
- **Lineage-scoped summaries**: a signature only counts if the matching calls are in the sample's process tree (not the sandbox's own tooling).
- **Spawn-artifact exclusion**: files/processes the orchestrator itself creates don't feed signatures.
- Both born from real self-detection bugs — our tooling kept tripping community rules.
- 11 tests in `test_cape_engine.py`.

**Takeaway:** community detection content is a multiplier, but only if you scope it, gate it, and measure what fraction of it can even fire.

---
*Status: skeleton. Needs: example signature translation, a report screenshot showing CAPE chips, FP-guard bug story details.*
