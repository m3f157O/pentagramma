# The Sysmon config that silently never worked

> **Series:** PENTAGRAMMA, part 2/11 · **Draft skeleton** · Sources: `docs/detection-gap-tracker.md` (2026-07-21), `docs/blog-series-timeline.md`

**Lede:** For weeks, our sandbox collected registry, named-pipe, and WMI events from a Sysmon config that "looked right." It parsed. It installed. It produced **zero events** for eight entire event IDs — because the XML tag names were wrong. One detonation later, a one-word fix produced **22,840 events**.

## Outline

### The trap: parseable ≠ correct
- Sysmon validates the XML schema, not the semantics of rule-group tag names.
- Wrong tags (registry/pipe/WMI families) → rules silently inert. No error, no warning, no events.
- *"These eight event IDs had almost certainly never produced a single event."* — detection-gap-tracker, 2026-07-21

### How we found it: validation by detonation
- Noticed empty telemetry families during a detection-gap audit.
- Wrote `persistence_runkey.ps1` (hammers registry) and `c2_named_pipe.ps1` (pipe C2 sim) as live probes.
- Before fix: nothing. After `RegistryEvent`/`PipeEvent`/`WmiEvent` tags: **22,840 RegistryCreateDelete + 1,410 RegistryValueSet**; **81 PipeCreated + 81 PipeConnected**.
- *[placeholder: before/after event-count table]*

### The flood problem: fixing volume without losing signal
- 22k events per run is its own bug: ImageLoad alerts cut **1,307 → 113** via conditional alerting.
- NetworkConnect/DnsQuery were collected but invisible → wired into alerts + MITRE mapping.
- A .NET stdout-redirection deadlock turned a 300KB-output sample into a 15s false timeout → fixed (0.33s full capture).

### What stayed broken (and why that's fine)
- WMI persistence events (EID 19–21): confirmed dead on this guest build — later solved with a WMI-Activity **ETW** collector (09-04).
- **ETW-TI declared infeasible**: requires PPL with Microsoft's Antimalware-Light signer. Sometimes the answer is "you can't have it" — knowing early saves weeks.

**Takeaway:** never trust a detection you haven't triggered yourself. One deliberate detonation is worth a hundred config reviews.

---
*Status: skeleton. Needs: the actual wrong/right XML diff, probe scripts as gist links.*
