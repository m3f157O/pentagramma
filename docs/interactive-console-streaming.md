# Evaluation: Streaming the Guest Console to the Browser (Interactive)

**Status:** **IMPLEMENTED (2026-09-03)** — minimal-interaction variant:
host-side WMI thumbnail frames + input bridged into the interactive session
via a named pipe, plus an opt-in per-job *interactive launch* mode. No RDP,
no VNC, no guacd, no guest network listener, nothing baked into the golden
image. See "Implementation" below. The option analysis is kept for the
record.

**Scope:** streaming the **guest analysis VM's** console into the dashboard
for live interaction. Streaming the *host's* desktop was considered and
rejected: browser-RDP to the machine that fetches/handles live malware is a
security risk and doesn't help sandbox interaction.

---

## Key empirical finding (2026-09-03)

**PowerShell Direct sessions are non-interactive.** A sample that blocked on
a modal MessageBox for its full 90 s run never appeared in ANY console
thumbnail (analysis `13f0d8cd-0c74-4ebf-83e6-a86f5fb1d54b`): the sample
renders in the PSRP session's invisible window station. Consequences:

- `SendInput` from a PSDirect session cannot reach the visible desktop.
- Clicking a sample's dialogs requires launching the sample **into the
  interactive session** (scheduled task, interactive token as the logged-on
  user `gigi`) — an opt-in per-job mode, since it changes the detonation
  baseline (parent chain, window station; same user/integrity).

## Implementation (what exists now)

**Video OUT (passive, zero guest footprint):** the Hyper-V WMI thumbnail API
(`Get-Thumbnail`, `orchestrator/hyperv.py::capture_screenshot`) polled by the
ConsoleManager frame loop at `console.fps` (default 0.7) at
`console.width`x`console.height` (default 1280x800), served as
`GET /api/console/frame` (PNG, no-store).

**Input IN (bridged to the interactive session):**
`agent/windows/console_input_server.ps1` runs in the interactive session via
a scheduled task (`SandboxConsoleInput`, logged-on user, interactive token,
RunLevel Highest) and listens on the named pipe `\\.\pipe\sandbox_console_in`
(pipes are session-independent kernel objects — no network listener). The
orchestrator holds a persistent helper process
(`scripts/console_session.ps1`, one PSDirect PSSession) that relays browser
events onto the pipe. The task is registered on console open and stopped +
unregistered on close; nothing persists across a snapshot revert anyway.

**Interactive launch mode (per-job opt-in):** `interactive=true` on
`POST /api/jobs` or `/api/analyze` (dashboard checkbox) makes the executor
use `Execute-Sample-Interactive` (`scripts/hyperv-vm.ps1`): a scheduled task
(`SandboxInteractiveRun`, interactive token) runs
`agent/windows/interactive_launcher.ps1`, which reads a JSON spec file (no
command-line quoting issues), launches via monitor_loader (behavioral tracing
and guardian placement unchanged), captures stdout/stderr to files, enforces
the timeout, and writes `launch_result.json`. **Process dumps are not taken
in interactive mode** (noted in the report's process_dumps section).

**API:** `POST /api/console/open|close`, `GET /api/console/status`,
`GET /api/console/frame`, `POST /api/console/input`
({action: click|rightclick|dblclick|move|wheel|key|text}; x/y relative 0..1,
scaled to the guest's real resolution queried via `screeninfo`).

**UI:** centralized page `orchestrator/static/console.html` (`/ui/console.html`)
— frame viewer + input + active-job panel; linked from every page's nav and
from the dashboard's active-job card ("Live console ->").

**Report tagging:** `report.interactive_launch` (sample ran on the console
session) and `report.interactive_console` (console was open during the run
window; `ConsoleManager.used_between`). Either flag = not comparable to
corpus baselines.

**Tests:** `tests/test_console.py` (10 tests, offline: scaling, validation,
lifecycle with mocked Hyper-V, tagging windows).

⚠️ Still true: the console and interactive launch are analyst-visible
behavior changes. They stay opt-in per job / per console-open, never in the
golden image.

---

## Historical evaluation (kept for the record)


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
