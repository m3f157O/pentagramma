# Watching the paint dry: live telemetry streaming and a console for every VM

> **Series:** PENTAGRAMMA, part 18/? · **Draft skeleton** · Sources: live-tail + fleet-console work (post-`b7093c2`), `docs/interactive-console-streaming.md`

**Lede:** The sandbox answered questions like a batch job from 1975: submit, wait four minutes, read the report. Two small features changed the feel of the whole tool — a live tail of the guest's telemetry stream while the run is still executing, and the interactive console decoupled from "the" analysis VM to any fleet member. Neither needed new infrastructure: one is a file read with a byte offset, the other was a singleton that wanted to be a dictionary.

## Outline

### The offset trick
- Telemetry already lands in a JSONL the collector appends to. Live view = read from byte N, return new offset, repeat every 2s. The only sharp edges: `FileShare.ReadWrite` (the collector holds the file), capping reads at 256KB, and rewinding the offset past a trailing partial line (collector mid-write) so nothing is silently dropped.
- The same verb serves both transports through the `-LocalMode` seam: PSDirect into the VM, or an in-process read on the host in local mode. Zero guest changes.
- Dashboard gets a "Live telemetry" panel that exists only while a job runs. Sysmon events scrolling by as the sample executes — the sandbox finally *feels* observable.

### The console was a singleton
- `ConsoleManager` was bound to the one configured analysis VM. Fleet-ifying it was embarrassingly small: constructor takes a VM name, singleton becomes a dict keyed by name, endpoints grow `?vm=`.
- The important precision: report tainting (`interactive_console: true`) now only applies when the console attached to the *run's own* VM — watching another fleet VM no longer poisons a corpus-comparable report.
- Every fleet VM with creds gets a console; the picker lists running ones and greys out the rest.

### What we deliberately didn't build
- WebSockets (polling at this scale is free), parallel sessions, live-trace-on-VM (declined — the detonation path already traces), mid-run apitrace tail (v2 if anyone asks).

**Takeaway:** the best streaming architecture is the one your existing file formats and seams already give you. An append-only JSONL plus a byte offset is ninety percent of Kafka.

---
*Status: skeleton. Assets: live-tail panel mid-run screenshot, console picker dropdown, the partial-line rewind logic.*
