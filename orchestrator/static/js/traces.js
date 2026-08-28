// Traces page: archived local-trace sessions (read-only history browser).
const state = { id: null, offset: 0, limit: 500, total: 0 };

function fmtEpoch(ts) {
  if (ts == null) return "-";
  try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return "-"; }
}

function fmtTs(ts) {
  if (ts == null) return "";
  try { return new Date(ts * 1000).toLocaleTimeString(undefined, { hour12: false }); } catch (e) { return String(ts); }
}

async function loadHistory() {
  const tbody = document.getElementById("traces-body");
  try {
    const data = await Api.localTraceHistory();
    if (!data.sessions.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No archived traces yet. Ended Live Trace sessions appear here.</td></tr>`;
      return;
    }
    tbody.innerHTML = data.sessions
      .map((s) => `
        <tr class="rule-row trace-session-row" data-id="${escapeHtml(s.id)}">
          <td class="small">${escapeHtml(fmtEpoch(s.started_at))}</td>
          <td class="mono small">${escapeHtml(s.target || "?")}</td>
          <td class="mono small muted">${escapeHtml(s.arguments || "")}</td>
          <td class="small">${escapeHtml(s.bitness || "?")}</td>
          <td><span class="badge ${s.status === "stopped" ? "warn" : "ok"}">${escapeHtml(s.status || "finished")}</span></td>
          <td class="small">${s.exit_code ?? "-"}</td>
          <td class="small">${s.total_events ?? "-"}</td>
          <td class="small">${fmtBytes(s.size_bytes)}</td>
        </tr>`)
      .join("");
    tbody.querySelectorAll("tr.trace-session-row").forEach((row) => {
      row.addEventListener("click", () => {
        tbody.querySelectorAll("tr.trace-session-row").forEach((r) => r.classList.remove("expanded"));
        row.classList.add("expanded");
        selectSession(row.dataset.id);
      });
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="error-text">${escapeHtml(e.message)}</td></tr>`;
  }
}

async function loadEvents() {
  const tbody = document.getElementById("trace-detail-body");
  if (!state.id) return;
  tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Loading…</td></tr>`;
  const q = document.getElementById("trace-q").value.trim();
  try {
    const d = await Api.localTraceHistoryEvents(state.id, state.offset, q);
    state.total = d.total;
    document.getElementById("trace-detail-label").textContent =
      `offset ${d.offset} · ${d.total} events`;
    document.getElementById("btn-td-prev").disabled = state.offset <= 0;
    document.getElementById("btn-td-next").disabled = d.next_offset >= d.total;
    if (!d.events.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No matching events.</td></tr>`;
      return;
    }
    tbody.innerHTML = d.events
      .map((e) =>
        `<tr><td class="small">${escapeHtml(fmtTs(e.ts))}</td>` +
        `<td class="mono small">${escapeHtml(e.api || "")}</td>` +
        `<td class="small">${escapeHtml(e.category || "")}</td>` +
        `<td class="small">${escapeHtml(String(e.pid ?? ""))}</td>` +
        `<td class="small">${escapeHtml(String(e.tid ?? ""))}</td>` +
        `<td class="mono small">${escapeHtml((e.arg0 || "").length > 250 ? e.arg0.slice(0, 250) + "…" : e.arg0 || "")}</td></tr>`
      )
      .join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="error-text">${escapeHtml(e.message)}</td></tr>`;
  }
}

function selectSession(id) {
  state.id = id;
  state.offset = 0;
  document.getElementById("trace-detail-id").textContent = id;
  loadEvents();
}

document.getElementById("btn-td-prev").addEventListener("click", () => {
  state.offset = Math.max(0, state.offset - state.limit);
  loadEvents();
});
document.getElementById("btn-td-next").addEventListener("click", () => {
  state.offset += state.limit;
  loadEvents();
});
document.getElementById("trace-q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { state.offset = 0; loadEvents(); }
});

loadHistory();
