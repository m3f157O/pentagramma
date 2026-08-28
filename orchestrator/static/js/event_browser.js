// Shared server-paginated telemetry browser -- one instance per telemetry
// tab (Injection, Scripts/AMSI, Processes, Filesystem, Registry). Backed by
// GET /api/reports/{id}/events with source/event_type/q filters; event_type
// accepts a comma-separated list server-side so an EID family stays ONE
// paginated stream instead of N client-merged ones.
//
// Usage:
//   const eb = createEventBrowser(document.getElementById("x"), {
//     analysisId,
//     source: "sysmon",
//     eventTypes: ["ProcessCreate", "ProcessTerminate"],
//     columns: [
//       { label: "Time", render: (e, d) => escapeHtml(d.UtcTime || e.timestamp || "") },
//       ...
//     ],
//     note: "optional explanatory line above the controls",
//     emptyText: "optional custom empty-state text",
//     pageSize: 200,
//   });
//   eb.load(); // or wire to first tab-open via lazy loaders
//
// opts.endpoint: "events" (default, raw telemetry stream) or "alerts"
// (synthesized alerts -- MITRE coverage rows with source=alert only exist
// there, not in the raw stream).
function createEventBrowser(container, opts) {
  const state = { offset: 0, limit: opts.pageSize || 200, q: "" };
  const colCount = opts.columns.length;
  let filteredTotal = null;

  container.innerHTML = `
    ${opts.note ? `<div class="small muted module-note">${escapeHtml(opts.note)}</div>` : ""}
    <div class="controls">
      <input type="text" class="eb-search" placeholder="${escapeHtml(opts.searchPlaceholder || "filter (substring over full event JSON)…")}" style="min-width:260px" />
      <button class="eb-load">Load</button>
      <button class="eb-prev secondary">◀ prev</button>
      <button class="eb-next secondary">next ▶</button>
      <span class="eb-page small muted"></span>
    </div>
    <table>
      <thead><tr>${opts.columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join("")}</tr></thead>
      <tbody class="eb-body"><tr><td colspan="${colCount}" class="empty-state">${escapeHtml(opts.emptyText || 'Click "Load" to browse this stream.')}</td></tr></tbody>
    </table>`;

  const tbody = container.querySelector(".eb-body");
  const pageLabel = container.querySelector(".eb-page");

  async function load() {
    state.q = container.querySelector(".eb-search").value.trim();
    tbody.innerHTML = `<tr><td colspan="${colCount}" class="empty-state">Loading…</td></tr>`;
    try {
      const fetchPage = opts.endpoint === "alerts" ? Api.getReportAlerts : Api.getReportEvents;
      const data = await fetchPage(opts.analysisId, {
        offset: state.offset,
        limit: state.limit,
        source: Array.isArray(opts.source) ? opts.source.join(",") : (opts.source || ""),
        eventType: (opts.eventTypes || []).join(","),
        q: state.q,
      });
      const rows = data.events || data.alerts || [];
      filteredTotal = data.filtered_total;
      if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="${colCount}" class="empty-state">No matching events.</td></tr>`;
      } else {
        tbody.innerHTML = rows
          .map((e) => {
            const d = e.data || {};
            return `<tr>${opts.columns.map((c) => `<td class="${c.cls || "small"}">${c.render(e, d)}</td>`).join("")}</tr>`;
          })
          .join("");
      }
      pageLabel.textContent = `offset ${state.offset} · ${data.filtered_total} matching`;
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="${colCount}" class="error-text">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  container.querySelector(".eb-load").addEventListener("click", () => { state.offset = 0; load(); });
  container.querySelector(".eb-prev").addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - state.limit);
    load();
  });
  container.querySelector(".eb-next").addEventListener("click", () => {
    if (filteredTotal === null || state.offset + state.limit < filteredTotal) {
      state.offset += state.limit;
      load();
    }
  });
  container.querySelector(".eb-search").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { state.offset = 0; load(); }
  });

  return { load };
}
