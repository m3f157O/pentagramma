// Live Trace page: 1s poll of the local host-side trace session.
// Cursor semantics: the server returns next_offset (raw lines consumed), so
// q-filtering never re-reads or skips new events.
let cursor = 0;
let sessionId = null;
let shownCount = 0;

function fmtTs(ts) {
  if (ts == null) return "";
  try {
    return new Date(ts * 1000).toLocaleTimeString(undefined, { hour12: false });
  } catch (e) {
    return String(ts);
  }
}

function setStatus(s) {
  const badge = document.getElementById("live-badge");
  const statusEl = document.getElementById("trace-status");
  const btnStart = document.getElementById("btn-start");
  const btnStop = document.getElementById("btn-stop");

  if (!s.active) {
    badge.textContent = "idle";
    badge.className = "badge neutral";
    statusEl.textContent = "No session.";
    btnStart.disabled = false;
    btnStop.disabled = true;
    return;
  }

  const running = s.status === "running";
  badge.textContent = running ? "live" : s.status;
  badge.className = "badge " + (running ? "ok" : "neutral");
  statusEl.innerHTML =
    `<span class="mono">${escapeHtml(s.target)}</span> ` +
    `${s.arguments ? `<span class="mono muted">${escapeHtml(s.arguments)}</span> ` : ""}` +
    `<span class="badge neutral">${escapeHtml(s.bitness)}</span> ` +
    `elapsed ${fmtDuration(s.elapsed_seconds)}` +
    (s.exit_code !== null ? ` · exit code ${s.exit_code}` : "");
  btnStart.disabled = running;
  btnStop.disabled = !running;
}

function appendRows(events) {
  if (!events.length) return;
  const tbody = document.getElementById("trace-body");
  if (shownCount === 0) tbody.innerHTML = "";
  const rows = events
    .map((e) => {
      return `<tr><td class="small">${escapeHtml(fmtTs(e.ts))}</td>` +
        `<td class="mono small">${escapeHtml(e.api || "")}</td>` +
        `<td class="small">${escapeHtml(e.category || "")}</td>` +
        `<td class="small">${escapeHtml(String(e.pid ?? ""))}</td>` +
        `<td class="small">${escapeHtml(String(e.tid ?? ""))}</td>` +
        `<td class="mono small">${escapeHtml((e.arg0 || "").length > 250 ? e.arg0.slice(0, 250) + "…" : e.arg0 || "")}</td></tr>`;
    })
    .join("");
  tbody.insertAdjacentHTML("beforeend", rows);
  shownCount += events.length;
  if (document.getElementById("trace-autoscroll").checked) {
    window.scrollTo(0, document.body.scrollHeight);
  }
}

async function tick() {
  const status = await Api.localTraceStatus();

  // A new session id (someone restarted the trace) -> reset the view.
  if (status.active && sessionId && status.id !== sessionId) {
    cursor = 0;
    shownCount = 0;
    document.getElementById("trace-body").innerHTML = "";
  }
  sessionId = status.active ? status.id : sessionId;

  setStatus(status);

  if (status.active && !document.getElementById("trace-pause").checked) {
    const q = document.getElementById("trace-filter").value.trim();
    const d = await Api.localTraceEvents(cursor, q);
    cursor = d.next_offset;
    appendRows(d.events);
    document.getElementById("trace-count").textContent =
      `${d.total} captured · ${shownCount} shown`;
  }
}

document.getElementById("trace-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = document.getElementById("trace-target").value.trim();
  const args = document.getElementById("trace-args").value;
  if (!target) return;
  const statusEl = document.getElementById("trace-status");
  statusEl.textContent = "Starting…";
  try {
    const s = await Api.localTraceStart(target, args);
    cursor = 0;
    shownCount = 0;
    sessionId = s.id;
    document.getElementById("trace-body").innerHTML = "";
    setStatus(s);
  } catch (err) {
    statusEl.innerHTML = `<span class="error-text">${escapeHtml(err.message)}</span>`;
  }
});

document.getElementById("btn-stop").addEventListener("click", async () => {
  try {
    await Api.localTraceStop();
  } catch (err) {
    console.error(err);
  }
});

document.getElementById("btn-clear-view").addEventListener("click", () => {
  document.getElementById("trace-body").innerHTML = "";
  shownCount = 0;
});

// Hookset inventory (same source as the report page's API-trace tab: the
// server-curated /api/hookset endpoint backed by coverage_map.yaml).
async function renderLiveHookset() {
  const el = document.getElementById("live-hooks-inventory");
  try {
    const data = await Api.getHookset();
    document.getElementById("live-hooks-count").textContent = data.total_hooks;
    el.innerHTML =
      `<table><thead><tr><th>Family</th><th>Hooked APIs</th><th>Sysmon counterpart</th><th>What it sees</th></tr></thead><tbody>` +
      data.categories
        .map((c) =>
          `<tr><td class="small">${escapeHtml(c.name)}</td>` +
          `<td class="mono small">${c.hooks.map((h) => escapeHtml(h.api)).join("<br>")}</td>` +
          `<td class="small muted">${c.hooks.map((h) => (h.sysmon_counterparts && h.sysmon_counterparts.length ? `EID ${h.sysmon_counterparts.join("/")}` : "—")).join("<br>")}</td>` +
          `<td class="small muted">${escapeHtml(c.description || "")}</td></tr>`
        )
        .join("") +
      `</tbody></table>`;
  } catch (e) {
    el.innerHTML = `<div class="error-text small">Failed to load hookset: ${escapeHtml(e.message)}</div>`;
  }
}

renderLiveHookset();
startPoll(tick, 1000);
