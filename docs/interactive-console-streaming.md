# Evaluation: Streaming the Guest Console to the Browser (Interactive)

**Status:** Evaluated 2026-07-27 — **not implemented**. Recommendation: do
Option 1 (better passive view) when convenient; Option 2 (RDP + Guacamole)
only as an explicitly opt-in per-job "interactive session" mode.

**Scope:** streaming the **guest analysis VM's** console into the dashboard
for live interaction. Streaming the *host's* desktop was considered and
rejected: browser-RDP to the machine that fetches/handles live malware is a
security risk and doesn't help sandbox interaction.

---

## Current state (what exists today)

- Host↔guest IP connectivity via the configured vSwitch (`Default Switch`,
  NAT); guest agent deployed per-run via PowerShell Direct.
- Passive console view: **Hyper-V WMI thumbnail API** (`Get-Thumbnail`,
  host-side, `orchestrator/hyperv.py:319`, `scripts/hyperv-vm.ps1::Get-SandboxVMThumbnail`)
  → 320×240 snapshots on a timer (`config.yaml → screenshots:`). No guest
  footprint, no interaction.

## Options (ranked by effort)

### 1. Bigger/faster passive view — HOURS (no interaction)
The WMI thumbnail API accepts arbitrary dimensions (up to console res) and
can be polled ~1–2 fps. Same zero-footprint mechanism: raise resolution
(e.g. 1024×768) + refresh the header `<img>` on an interval.
Cheap, safe, no guest changes. No input.

### 2. RDP + Apache Guacamole — ~2–4 days — RECOMMENDED for interaction
Guacamole's `guacd` speaks RDP and serves an HTML5 canvas + keyboard/mouse
to the browser. The mature, standard solution for this exact use case.
- Enable RDP (TermService + firewall) → requires a **new SANDBOX_READY
  snapshot** via the verify-gated provisioning flow — deliberate step.
- Hurdle: `guacd` is Linux-native → run it in **WSL2 or Docker** on the
  Windows host; iframe/link the Guacamole client from the FastAPI UI (or run
  as a sibling webapp next to the orchestrator).
- Alternatives, same effort class, no WSL: **MeshCentral** (Node.js, runs
  on Windows) or **noVNC + TightVNC/UltraVNC in guest** (+websockify).

### 3. Console via the existing guest agent (MJPEG/WebSocket + SendInput) — ~3–5 days
Guest-side capture (DXGI Desktop Duplication / `mss`), stream JPEG frames
over a WebSocket on the agent's existing port, POST input events back,
inject with `SendInput`. Self-contained, no new guest services, integrates
with the current UI. 5–10 fps is easy; feels laggier than RDP.

### 4. WebRTC / H.264 low-latency — 1–2+ weeks
Not worth it for this use case.

### 5. Hyper-V VMConnect passthrough — research-grade, REJECTED
VMConnect is RDP-with-extensions (host port 2179, VM-GUID auth). FreeRDP
supports `/vmconnect`, but Guacamole does not (no mainline support). Dead end.

## ⚠️ The trade-off that matters here (sandbox context)

Any interactive channel is **guest-visible** and **behavior-altering**:

- Listening RDP/VNC ports, a VNC service, or an interactive logon session
  are **sandbox-evasion artifacts** malware can fingerprint.
- An RDP session changes session state (console locks, session-0 vs
  interactive) — can alter sample behavior and the telemetry baseline.
- An analyst clicking around **changes the detonation itself**.

**Mitigations (required if Option 2/3 is ever built):**
- Enable the channel **on demand** (opt-in per job, or post-detonation
  "open console" action) — never baked into the golden image by default.
- Non-standard ports; keep the service stopped in SANDBOX_READY.
- Document that interactive-mode reports are not comparable to the default
  corpus runs (baseline shift).

## Recommendation

1. **Option 1** (resolution/rate bump of the existing thumbnail view) —
   do it whenever; zero risk.
2. **Option 2** (RDP + Guacamole via WSL2/Docker) — only as an **explicit
   opt-in per-job interactive mode**, RDP enabled at job start, off by
   default. Deferred until actually needed.
