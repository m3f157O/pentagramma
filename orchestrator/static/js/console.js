// Interactive VM console: ~1 fps frame viewer + mouse/keyboard input.
// Frames come from the host-side WMI thumbnail API; input is bridged into
// the guest's interactive session (see docs/interactive-console-streaming.md).
// Everything here is on-demand: the backend does nothing until Open is clicked.

const viewer = document.getElementById("viewer");
const viewerEmpty = document.getElementById("viewer-empty");
const frameInfo = document.getElementById("frame-info");
const statusEl = document.getElementById("console-status");
const badgeEl = document.getElementById("console-badge");
const btnOpen = document.getElementById("btn-open");
const btnClose = document.getElementById("btn-close");

let consoleOpen = false;
let frameTimer = null;

// --- Api surface (defined here, not api.js: console endpoints only) ---
const ConsoleApi = {
  open: () => apiRequest("/api/console/open", { method: "POST" }),
  close: () => apiRequest("/api/console/close", { method: "POST" }),
  status: () => apiRequest("/api/console/status"),
  input: (evt) => apiRequest("/api/console/input", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(evt),
  }),
  frameUrl: () => `/api/console/frame?ts=${Date.now()}`,
};

// --- frames ---------------------------------------------------------------
function scheduleFrame() {
  if (!consoleOpen) return;
  if (frameTimer) clearTimeout(frameTimer);
  frameTimer = setTimeout(() => {
    viewer.style.display = "block";
    viewerEmpty.style.display = "none";
    viewer.src = ConsoleApi.frameUrl();
  }, 1200);
}

viewer.addEventListener("load", () => { frameInfo.textContent = ""; scheduleFrame(); });
viewer.addEventListener("error", () => {
  frameInfo.textContent = "frame unavailable";
  scheduleFrame();
});

// --- input ----------------------------------------------------------------
function relativeCoords(e) {
  const r = viewer.getBoundingClientRect();
  return {
    x: Math.min(Math.max((e.clientX - r.left) / r.width, 0), 1),
    y: Math.min(Math.max((e.clientY - r.top) / r.height, 0), 1),
  };
}

function sendInput(evt) {
  if (!consoleOpen) return;
  ConsoleApi.input(evt).catch((err) => { statusEl.textContent = `input failed: ${err.message}`; });
}

viewer.addEventListener("click", (e) => { e.preventDefault(); sendInput({ action: "click", ...relativeCoords(e) }); });
viewer.addEventListener("dblclick", (e) => { e.preventDefault(); sendInput({ action: "dblclick", ...relativeCoords(e) }); });
viewer.addEventListener("contextmenu", (e) => { e.preventDefault(); sendInput({ action: "rightclick", ...relativeCoords(e) }); });
viewer.addEventListener("wheel", (e) => {
  e.preventDefault();
  sendInput({ action: "wheel", delta: e.deltaY < 0 ? 120 : -120 });
}, { passive: false });

const KEY_MAP = {
  Enter: "ENTER", Escape: "ESC", Tab: "TAB", Backspace: "BACKSPACE", Delete: "DELETE",
  ArrowUp: "UP", ArrowDown: "DOWN", ArrowLeft: "LEFT", ArrowRight: "RIGHT",
  Home: "HOME", End: "END", PageUp: "PAGEUP", PageDown: "PAGEDOWN",
  F1: "F1", F2: "F2", F3: "F3", F4: "F4", F5: "F5", F6: "F6",
  F7: "F7", F8: "F8", F9: "F9", F10: "F10", F11: "F11", F12: "F12",
};

viewer.addEventListener("keydown", (e) => {
  const named = KEY_MAP[e.key];
  if (named) {
    e.preventDefault();
    let combo = named;
    if (e.ctrlKey) combo = "CTRL+" + combo;
    if (e.shiftKey) combo = "SHIFT+" + combo;
    if (e.altKey) combo = "ALT+" + combo;
    sendInput({ action: "key", key: combo });
  } else if (e.key && e.key.length === 1 && !e.ctrlKey && !e.altKey) {
    e.preventDefault();
    sendInput({ action: "text", text: e.key });
  }
});

document.getElementById("btn-type").addEventListener("click", () => {
  const el = document.getElementById("type-text");
  if (el.value) { sendInput({ action: "text", text: el.value }); el.value = ""; }
});
document.getElementById("btn-enter").addEventListener("click", () => sendInput({ action: "key", key: "ENTER" }));
document.getElementById("btn-esc").addEventListener("click", () => sendInput({ action: "key", key: "ESC" }));

// --- open/close + status ----------------------------------------------------
async function refreshStatus() {
  try {
    const s = await ConsoleApi.status();
    consoleOpen = s.open;
    badgeEl.textContent = s.open ? "open" : "closed";
    badgeEl.className = "badge " + (s.open ? "ok" : "neutral");
    btnOpen.disabled = s.open;
    btnClose.disabled = !s.open;
    if (s.last_error) statusEl.textContent = s.last_error;
    if (!s.open && viewer.style.display === "block") {
      viewer.style.display = "none";
      viewerEmpty.style.display = "block";
      viewerEmpty.textContent = "Console closed.";
    }
    if (s.open) scheduleFrame();
  } catch (e) {
    statusEl.textContent = `status: ${e.message}`;
  }
}

btnOpen.addEventListener("click", async () => {
  statusEl.textContent = "opening…";
  try {
    await ConsoleApi.open();
    consoleOpen = true;
    statusEl.textContent = "";
    viewerEmpty.textContent = "Waiting for first frame…";
    scheduleFrame();
    refreshStatus();
  } catch (e) {
    statusEl.textContent = `open failed: ${e.message}`;
  }
});

btnClose.addEventListener("click", async () => {
  try { await ConsoleApi.close(); } catch (e) { statusEl.textContent = e.message; }
  consoleOpen = false;
  refreshStatus();
});

// --- active job panel -------------------------------------------------------
async function refreshJob() {
  const body = document.getElementById("console-job-body");
  try {
    const data = await Api.listJobs();
    if (!data.active_job_id) {
      body.innerHTML = `<span class="muted">No job running. Submit one from the <a href="index.html">dashboard</a> (tick <i>interactive</i> to see its UI here).</span>`;
      return;
    }
    const job = await Api.getJob(data.active_job_id);
    const steps = (job.step_history || []).map((s) => `<li>${escapeHtml(s.step)}</li>`).join("");
    body.innerHTML = `
      <div><span class="mono">${escapeHtml(job.sample_filename || "")}</span>
      <span class="badge warn">${escapeHtml(job.status)}</span></div>
      <ul class="steps">${steps}</ul>`;
  } catch (e) {
    body.innerHTML = `<span class="error-text small">${escapeHtml(e.message)}</span>`;
  }
}

refreshStatus();
startPoll(refreshStatus, 4000);
startPoll(refreshJob, 4000);
