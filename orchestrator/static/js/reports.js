let allReports = [];
let sortKey = "timestamp";
let sortDir = -1; // -1 = desc, 1 = asc
let page = 0;
const PAGE_SIZE = 25;

const COLUMNS = [
  { key: "timestamp", label: "Time" },
  { key: "filename", label: "Sample" },
  { key: "sha256_short", label: "SHA256" },
  { key: "status", label: "Status" },
  { key: "verdict_level", label: "Verdict" },
  { key: "alert_count", label: "Alerts" },
  { key: "eid25_count", label: "EID25" },
  { key: "total_events", label: "Events" },
  { key: "runtime_seconds", label: "Runtime" },
];

function verdictCell(r) {
  if (!r.verdict_level) return `<td class="muted small">-</td>`;
  const cls = r.verdict_level === "malicious" ? "bad" : r.verdict_level === "suspicious" ? "warn" : "ok";
  const score = r.verdict_score != null ? ` <span class="small muted">${r.verdict_score}</span>` : "";
  return `<td><span class="badge ${cls}">${escapeHtml(r.verdict_level)}</span>${score}</td>`;
}

function matchesFilters(r) {
  const q = document.getElementById("filter-text").value.trim().toLowerCase();
  const status = document.getElementById("filter-status").value;
  const verdict = document.getElementById("filter-verdict").value;
  const harnessOnly = document.getElementById("filter-harness").checked;

  if (status && r.status !== status) return false;
  if (verdict && (r.verdict_level || "") !== verdict) return false;
  if (harnessOnly && !r.is_injection_harness) return false;
  if (q) {
    const haystack = `${r.filename} ${r.sha256_short} ${r.analysis_id}`.toLowerCase();
    if (!haystack.includes(q)) return false;
  }
  return true;
}

function render() {
  const filtered = allReports.filter(matchesFilters);
  filtered.sort((a, b) => {
    const av = a[sortKey];
    const bv = b[sortKey];
    if (av == null && bv == null) return 0;
    if (av == null) return 1;
    if (bv == null) return -1;
    if (av < bv) return -1 * sortDir;
    if (av > bv) return 1 * sortDir;
    return 0;
  });

  document.getElementById("result-count").textContent = `${filtered.length} / ${allReports.length}`;

  const tbody = document.getElementById("reports-body");
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-state">No matching reports.</td></tr>`;
    updatePager(0, 0);
    return;
  }
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  if (page >= totalPages) page = totalPages - 1;
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  updatePager(totalPages, filtered.length);
  tbody.innerHTML = pageRows
    .map(
      (r) => `
    <tr>
      <td>${fmtDate(r.timestamp)}</td>
      <td class="mono"><a href="report.html?id=${encodeURIComponent(r.analysis_id)}">${escapeHtml(r.filename)}</a></td>
      <td class="mono small">${escapeHtml(r.sha256_short)}</td>
      <td><span class="badge ${r.status === "completed" ? "ok" : "bad"}">${escapeHtml(r.status)}</span>${r.is_injection_harness ? ' <span class="badge neutral">harness</span>' : ""}</td>
      ${verdictCell(r)}
      <td>${r.alert_count}</td>
      <td>${r.eid25_count}</td>
      <td>${r.total_events}</td>
      <td>${fmtDuration(r.runtime_seconds)}</td>
    </tr>`
    )
    .join("");
}

function updatePager(totalPages, filteredCount) {
  document.getElementById("page-label").textContent = totalPages
    ? `page ${page + 1} / ${totalPages}`
    : "";
  document.getElementById("btn-page-prev").disabled = page <= 0;
  document.getElementById("btn-page-next").disabled = page >= totalPages - 1;
}

function renderHeader() {
  const thead = document.getElementById("reports-head");
  thead.innerHTML = COLUMNS.map((c) => {
    const sorted = c.key === sortKey ? "sorted" : "";
    return `<th data-key="${c.key}" class="${sorted}">${c.label}</th>`;
  }).join("");
  thead.querySelectorAll("th").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      if (sortKey === key) {
        sortDir *= -1;
      } else {
        sortKey = key;
        sortDir = -1;
      }
      renderHeader();
      render();
    });
  });
}

async function load() {
  document.getElementById("reports-body").innerHTML = `<tr><td colspan="9" class="empty-state">Loading…</td></tr>`;
  try {
    // Default view is the last 24h only -- months of old runs stay on disk
    // but out of the page (switch the range selector for full history).
    const sinceHours = Number(document.getElementById("filter-timerange").value || 0);
    const data = await Api.listReports(500, sinceHours);
    allReports = data.reports;
    page = 0;
    render();
  } catch (e) {
    document.getElementById("reports-body").innerHTML = `<tr><td colspan="9" class="error-text">${escapeHtml(e.message)}</td></tr>`;
  }
}

renderHeader();
load();
document.getElementById("filter-text").addEventListener("input", () => { page = 0; render(); });
document.getElementById("filter-status").addEventListener("change", () => { page = 0; render(); });
document.getElementById("filter-verdict").addEventListener("change", () => { page = 0; render(); });
document.getElementById("filter-harness").addEventListener("change", () => { page = 0; render(); });
document.getElementById("filter-timerange").addEventListener("change", load);
document.getElementById("btn-refresh").addEventListener("click", load);
document.getElementById("btn-page-prev").addEventListener("click", () => { if (page > 0) { page--; render(); } });
document.getElementById("btn-page-next").addEventListener("click", () => { page++; render(); });
