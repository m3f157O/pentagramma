const params = new URLSearchParams(location.search);
const analysisId = params.get("id");

let report = null;
let eventsState = { offset: 0, limit: 100, eventType: "", q: "", source: "" };
let hooksState = { offset: 0, limit: 200, q: "" };

// The monitor's active hookset (mirrors kHooks[] in
// agent/windows/monitor_src/monitor/monitor.cpp) -- shown in the Hooks
// section so the analyst can see what the API trace can and cannot see.
const HOOKSET = [
  { family: "file", apis: ["CreateFileW", "NtCreateFile"], desc: "File open/create at the Win32 wrapper AND the ntdll choke point (wrapper bypass still caught)." },
  { family: "process", apis: ["CreateProcessW", "NtCreateUserProcess"], desc: "Process creation; every non-WoW64 child is injected with the same monitor (child-following)." },
  { family: "memory", apis: ["NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx", "NtProtectVirtualMemory", "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtMapViewOfSection", "NtMapViewOfSectionEx", "NtUnmapViewOfSection", "NtUnmapViewOfSectionEx"], desc: "Alloc/protect/read/write/map/unmap + Ex variants (no Ex bypass). Unmap = hollowing gut; cross-read = secret theft; cross-write = injection." },
  { family: "injection", apis: ["NtCreateThreadEx", "NtResumeThread", "NtSuspendThread", "NtQueueApcThread", "NtQueueApcThreadEx", "NtGetContextThread", "NtSetContextThread"], desc: "Thread start/resume/suspend, APC queueing, context get/set -- every injection finisher incl. the ones Sysmon cannot see (APC, context hijack)." },
  { family: "registry", apis: ["NtSetValueKey"], desc: "Registry value writes (persistence)." },
  { family: "loader", apis: ["LdrLoadDll"], desc: "Module loads that bypass the kernel32 LoadLibrary wrapper. Manual mapping never calls this; covered by the memory hooks instead." },
  { family: "timing", apis: ["NtDelayExecution", "GetTickCount64", "NtQuerySystemTime", "NtCreateTimer", "NtSetTimer"], desc: "Sleeps, time-source polling, and timer-APC execution -- anti-sandbox checks and sleep-obfuscation (Ekko/Foliage)." },
  { family: "crypto", apis: ["BCryptEncrypt", "BCryptDecrypt", "BCryptHashData"], desc: "Bulk encryption/hashing (ransomware-style bursts; hashing itself is noise-filtered signature-side)." },
  { family: "token", apis: ["NtOpenProcessToken", "NtDuplicateToken", "NtAdjustPrivilegesToken"], desc: "Privilege escalation / token theft (SeDebug/SeImpersonate enables; cross-process token open + duplicate)." },
  { family: "evasion", apis: ["NtSetInformationThread", "NtSetInformationProcess", "NtCreateTransaction", "NtRollbackTransaction"], desc: "Anti-debugging (ThreadHideFromDebugger, debug-class tampering) and NTFS transactions (doppelganging). Memory events also carry base addresses and flag writes/protects inside ntdll/amsi (unhooking, ETW-AMSI blinding); process events decode PPID spoofing." },
];
// Server-curated hookset (GET /api/hookset, backed by the drift-guarded
// orchestrator/data/coverage_map.yaml). When available it replaces the
// hand-mirrored HOOKSET constant above -- the constant stays as the
// fallback for older servers / offline use.
let hooksetData = null;

function hooksetTotal() {
  return hooksetData ? hooksetData.total_hooks : HOOKSET.reduce((n, f) => n + f.apis.length, 0);
}

// Blind-spots tab header: how much of the hookset participates in the
// apitrace<->Sysmon correlation (only "both"-class hooks can produce
// blind-spot alerts; hook_only hooks have no Sysmon counterpart to miss).
function renderBlindspotCoverage() {
  const el = document.getElementById("blindspots-coverage");
  if (!el || !hooksetData || !Array.isArray(hooksetData.categories)) return;
  const byClass = {};
  hooksetData.categories.forEach((c) =>
    c.hooks.forEach((h) => { const k = h.coverage || "?"; byClass[k] = (byClass[k] || 0) + 1; })
  );
  const parts = Object.entries(byClass)
    .map(([k, n]) => `<span class="badge ${k === "both" ? "ok" : "neutral"}">${escapeHtml(k)}</span> ${n}`)
    .join(" · ");
  el.innerHTML = `<div class="small muted">Correlation basis: ${parts} of ${hooksetData.total_hooks} hooks &mdash; only <b>both</b>-class hooks can miss a counterpart.</div>`;
}

// key -> alert object, so a clicked row can look up its full alert to expand
// (lazy: detail HTML is built on first expand, not for every row upfront).
const alertRegistry = new Map();

function verdictLevelClass(level) {
  if (level === "malicious") return "bad";
  if (level === "suspicious") return "warn";
  return "ok"; // clean
}

function renderVerdict() {
  const el = document.getElementById("verdict-card");
  const verdict = report.verdict;
  if (!verdict) {
    // Reports generated before the verdict feature existed have no
    // "verdict" key at all -- omit the card rather than show a fake 0.
    el.innerHTML = "";
    return;
  }
  const reasons = (verdict.top_reasons || [])
    .map((r) => `<li class="small">${escapeHtml(r.reason)} <span class="muted">(+${r.weight})</span></li>`)
    .join("");
  el.innerHTML = `
    <div class="card">
      <div class="card-title">Verdict</div>
      <div style="display:flex; align-items:baseline; gap:12px; margin-top:4px">
        <span class="badge ${verdictLevelClass(verdict.level)}" style="font-size:14px; padding:4px 12px">${escapeHtml(verdict.level)}</span>
        <span class="card-value" style="font-size:20px">${verdict.score} / 100</span>
      </div>
      ${reasons ? `<ul class="ioc-list" style="margin-top:8px">${reasons}</ul>` : '<div class="small muted" style="margin-top:8px">No contributing findings.</div>'}
    </div>
  `;
}

function renderHeader() {
  const sample = report.sample || {};
  const env = report.environment || {};
  const sa = report.static_analysis || {};
  document.getElementById("report-title").textContent = sample.filename || analysisId;
  document.getElementById("report-json-link").href = Api.reportJsonUrl(analysisId);

  const statusClass = report.status === "completed" ? "ok" : "bad";
  const sig = sa.signature || {};
  document.getElementById("report-meta").innerHTML = `
    <span class="badge ${statusClass}">${escapeHtml(report.status)}</span>
    ${sample.sample_type ? `<span class="badge neutral">${escapeHtml(sample.sample_type)}</span>` : ""}
    <span class="small muted">${fmtDate(report.timestamp)}</span>
    <span class="small muted">VM ${escapeHtml(env.vm_name || "-")} (${escapeHtml(env.vm_ip || "no ip")})</span>
    ${report.error ? `<div class="error-text small">${escapeHtml(report.error)}</div>` : ""}
  `;

  if (sample.sample_type === "url") {
    // No local file exists at submission time -- hashes/entropy/signature
    // don't apply. For fetch-mode, the downloaded payload's identity is
    // under Dropped Files instead, not here.
    document.getElementById("sample-meta").innerHTML = `
      <table class="compact">
        <tr><td class="muted">URL</td><td class="mono small">${escapeHtml(sample.url || "-")}</td></tr>
        <tr><td class="muted">Mode</td><td>${escapeHtml(sample.url_mode || "-")}</td></tr>
        ${sample.url_mode === "fetch" ? `<tr><td colspan="2" class="small muted">Downloaded payload's hash/YARA verdict is under Dropped Files, not here.</td></tr>` : ""}
      </table>
    `;
    return;
  }

  const hashes = sample.hashes || {};
  document.getElementById("sample-meta").innerHTML = `
    <table class="compact">
      <tr><td class="muted">Size</td><td>${fmtBytes(sample.size)}</td></tr>
      <tr><td class="muted">MD5</td><td class="mono small">${escapeHtml(hashes.md5)}</td></tr>
      <tr><td class="muted">SHA1</td><td class="mono small">${escapeHtml(hashes.sha1)}</td></tr>
      <tr><td class="muted">SHA256</td><td class="mono small">${escapeHtml(hashes.sha256)}</td></tr>
      <tr><td class="muted">Entropy</td><td>${sa.entropy != null ? sa.entropy.toFixed(2) : "-"}</td></tr>
      <tr><td class="muted">Signature</td><td>${sig.signed ? '<span class="badge ok">signed</span>' : `<span class="badge warn">${escapeHtml(sig.status || "unsigned")}</span>`}</td></tr>
      <tr><td class="muted">File type</td><td>${escapeHtml((sa.file_type || {}).name || "-")}</td></tr>
    </table>
  `;
}

// Header screen viewer: the VM screen below the title, with a selector to
// flip through the screenshots captured during the analysis. Defaults to the
// LAST capture (usually the most interesting -- the detonation's end state).
let screenItems = [];
let screenIndex = 0;

function renderScreenView() {
  const wrap = document.getElementById("screen-view");
  const sc = report.screenshots || {};
  screenItems = (sc.items || []).filter((i) => !i.error);
  if (!screenItems.length) {
    wrap.classList.add("hidden");
    return;
  }
  wrap.classList.remove("hidden");

  const show = (i) => {
    screenIndex = (i + screenItems.length) % screenItems.length;
    document.getElementById("screen-img").src = Api.screenshotUrl(analysisId, screenItems[screenIndex].index);
    document.querySelectorAll("#screen-thumbs .screen-thumb").forEach((el, j) => {
      el.classList.toggle("active", j === screenIndex);
    });
  };

  // Clickable thumbnail strip: every capture rendered small; click to make
  // it the main view. Lazy-loaded so a long run doesn't fetch everything
  // up front (the main view starts on the LAST capture -- usually the
  // detonation's most interesting end state).
  document.getElementById("screen-thumbs").innerHTML = screenItems
    .map(
      (item, i) => `
      <div class="screen-thumb" data-i="${i}" title="#${item.index} · ${escapeHtml(fmtDate(item.timestamp))}">
        <img loading="lazy" src="${Api.screenshotUrl(analysisId, item.index)}" alt="Screen #${item.index}" />
        <span class="screen-thumb-label">#${item.index}</span>
      </div>`
    )
    .join("");
  document.querySelectorAll("#screen-thumbs .screen-thumb").forEach((el) => {
    el.addEventListener("click", () => show(parseInt(el.dataset.i, 10)));
  });

  show(screenItems.length - 1);
}

function renderSummaryCards() {
  const env = report.environment || {};
  // Compact stat row at the bottom of the right-hand side rail.
  document.getElementById("side-stats").innerHTML = `
    <div class="stat"><span class="stat-label">Runtime</span><span class="stat-value">${fmtDuration(env.runtime_seconds)}</span></div>
  `;
}

let eventChart = null;
function renderEventChart() {
  const counts = (report.summary || {}).event_counts || {};
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const ctx = document.getElementById("event-chart").getContext("2d");
  if (eventChart) eventChart.destroy();
  eventChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: entries.map((e) => e[0]),
      datasets: [{ label: "Events", data: entries.map((e) => e[1]), backgroundColor: "#9b8bd4" }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#a294c4" }, grid: { color: "#31224f" } },
        y: { ticks: { color: "#a294c4" }, grid: { color: "#31224f" } },
      },
    },
  });

  // populate the event-type filter for the raw browser from the same counts
  const select = document.getElementById("events-type-filter");
  select.innerHTML = '<option value="">all types</option>' + entries.map((e) => `<option value="${escapeHtml(e[0])}">${escapeHtml(e[0])} (${e[1]})</option>`).join("");
}

function mitreChips(mitreObj) {
  if (!mitreObj) return "";
  const chips = [];
  if (mitreObj.primary) chips.push(mitreObj.primary);
  (mitreObj.candidates || []).forEach((c) => chips.push(c));
  return chips.map((m) => `<span class="mitre-chip" title="${escapeHtml(m.tactic)}">${escapeHtml(m.technique_id)}</span>`).join("");
}

function sigmaLevelBadgeClass(level) {
  if (level === "critical" || level === "high") return "bad";
  if (level === "medium") return "warn";
  return "neutral"; // low | informational
}

// Coarse severity for visual scanning: dot color on each alert row and the
// group ordering in the grouped view. Mirrors detectors.py's weight model
// (client-side approximation -- no new data needed).
function alertSeverityClass(a) {
  if (a.event_id === 25 || a.event_type === "ApitraceInjectionChain") return "crit";
  if (a.event_type === "DefenderThreatDetected") return "crit";
  // Behavioral-signature alerts carry their catalog severity (attached
  // server-side by enrich_alert from detectors.py's map -- single source of
  // truth, so every Apitrace* signature colors correctly without being
  // named here).
  const sev = (a.severity || "").toLowerCase();
  if (sev === "critical") return "crit";
  if (sev === "high") return "high";
  if (sev === "medium") return "med";
  if (sev === "low") return "low";
  const sigmaLevel = (a.sigma && (a.sigma.level || "").toLowerCase()) || "";
  if (sigmaLevel === "critical") return "crit";
  if (sigmaLevel === "high" || a.priority === "high" ||
      a.event_type === "ApitraceCrossProcessWrite" || a.event_type === "ApitraceRemoteThread" ||
      a.event_type === "DmpYaraMatch" || a.event_type === "DroppedFileYaraMatch") return "high";
  if (sigmaLevel === "medium" || a.event_type === "ApitraceExecProtection") return "med";
  return "low";
}

function alertRow(a, key) {
  alertRegistry.set(key, a);
  const data = a.data || {};
  const sevDot = `<span class="sev-dot sev-${alertSeverityClass(a)}" title="${alertSeverityClass(a)}"></span>`;
  const sigmaBadge = a.sigma
    ? ` <span class="badge ${sigmaLevelBadgeClass(a.sigma.level)}" title="${escapeHtml(a.sigma.id)}">Sigma: ${escapeHtml(a.sigma.title)}</span>`
    : "";
  // Source badge for the non-Sysmon producers (apitrace / heuristic /
  // windefend / ...) -- with three alert sources coexisting, "which engine
  // said this" is the first triage question. Sigma alerts already carry
  // their own badge; plain Sysmon events are the default and stay unbadged.
  const src = a.source || "";
  const sourceBadge = !a.sigma && src && src !== "sysmon"
    ? ` <span class="badge neutral" title="alert source">${escapeHtml(src)}</span>`
    : "";
  return `<tr class="alert-row" data-key="${escapeHtml(key)}">
    <td class="small"><span class="alert-caret">▸</span> ${escapeHtml(data.UtcTime || a.timestamp)}</td>
    <td>${sevDot}${a.event_id ?? ""} ${escapeHtml(a.event_type || "")}${sigmaBadge}${sourceBadge}</td>
    <td class="mono small">${escapeHtml(data.ProcessId || data.SourceProcessId || "")}</td>
    <td class="small">${escapeHtml(data.Image || data.TargetImage || data.Type || "")}</td>
    <td>${mitreChips(a.mitre)}</td>
  </tr>`;
}

// Type-aware expansion: Sigma alert -> the rule; YARA alert -> the match;
// anything else (Windows event / heuristic) -> the raw event. Every kind
// also gets its MITRE techniques and the full raw record.
function renderAlertDetail(a) {
  const data = a.data || {};
  const parts = [];

  if (a.sigma) {
    const s = a.sigma;
    const ls = s.logsource || {};
    parts.push(`<div class="alert-detail-block">
      <h4>Sigma rule</h4>
      <table class="compact">
        <tr><td class="muted">Title</td><td>${escapeHtml(s.title || "-")}</td></tr>
        <tr><td class="muted">Rule id</td><td class="mono small">${escapeHtml(s.id || "-")}</td></tr>
        <tr><td class="muted">Level</td><td><span class="badge ${sigmaLevelBadgeClass(s.level)}">${escapeHtml(s.level || "-")}</span></td></tr>
        <tr><td class="muted">Log source</td><td class="small">${escapeHtml(ls.category || ls.product || "-")}</td></tr>
        ${s.tags && s.tags.length ? `<tr><td class="muted">Tags</td><td class="small">${s.tags.map(escapeHtml).join(", ")}</td></tr>` : ""}
        ${s.falsepositives && s.falsepositives.length ? `<tr><td class="muted">False positives</td><td class="small">${s.falsepositives.map(escapeHtml).join("; ")}</td></tr>` : ""}
      </table>
    </div>`);
  } else if (a.event_type === "DmpYaraMatch" || a.event_type === "DroppedFileYaraMatch") {
    const target = a.event_type === "DmpYaraMatch" ? "process/memory dump" : "dropped file";
    parts.push(`<div class="alert-detail-block">
      <h4>YARA match</h4>
      <table class="compact">
        <tr><td class="muted">Rule</td><td class="mono">${escapeHtml(data.Rule || "-")}</td></tr>
        <tr><td class="muted">Target</td><td class="small">${escapeHtml(target)}</td></tr>
        ${data.File ? `<tr><td class="muted">File</td><td class="mono small">${escapeHtml(data.File)}</td></tr>` : ""}
        ${data.Type ? `<tr><td class="muted">Detail</td><td class="small">${escapeHtml(data.Type)}</td></tr>` : ""}
      </table>
    </div>`);
  } else if (a.provider_name === "BehavioralSignatures") {
    // API-trace behavioral signature: show the actor->target pair, the APIs
    // that matched, and the raw argument evidence as first-class content
    // (instead of burying it in the raw JSON dump).
    const apis = Array.isArray(data.EvidenceApis) ? data.EvidenceApis : [];
    const evidence = Array.isArray(data.Evidence) ? data.Evidence : [];
    parts.push(`<div class="alert-detail-block">
      <h4>Behavioral signature (API trace)</h4>
      <table class="compact">
        <tr><td class="muted">Signature</td><td class="small">${escapeHtml(a.event_type || "-")}</td></tr>
        <tr><td class="muted">Detail</td><td class="small">${escapeHtml(data.Type || "-")}</td></tr>
        <tr><td class="muted">Actor PID</td><td class="mono small">${escapeHtml(data.ProcessId ?? "-")}</td></tr>
        ${data.TargetProcessId != null ? `<tr><td class="muted">Target PID</td><td class="mono small">${escapeHtml(data.TargetProcessId)}</td></tr>` : ""}
        <tr><td class="muted">Time</td><td class="small">${escapeHtml(data.UtcTime || a.timestamp || "-")}</td></tr>
        ${apis.length ? `<tr><td class="muted">Matched APIs</td><td>${apis.map((x) => `<span class="mitre-chip">${escapeHtml(x)}</span>`).join(" ")}</td></tr>` : ""}
      </table>
      ${evidence.length ? `<h4 style="margin-top:8px">Evidence</h4><ul class="ioc-list">${evidence.map((x) => `<li class="mono small">${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
    </div>`);
  } else if (a.source === "cape" || a.provider_name === "CapeSignatures") {
    // CAPE community signature: metadata + match evidence up front, then the
    // full rule source (lazily fetched by toggleAlertDetail, same endpoint
    // the Rules page uses for row expansion).
    const evidence = Array.isArray(data.Evidence) ? data.Evidence : [];
    const cats = Array.isArray(data.Categories) ? data.Categories : [];
    const fams = Array.isArray(data.Families) ? data.Families : [];
    parts.push(`<div class="alert-detail-block">
      <h4>CAPE community signature</h4>
      <table class="compact">
        <tr><td class="muted">Signature</td><td class="mono small">${escapeHtml(data.Name || "-")}</td></tr>
        <tr><td class="muted">Description</td><td class="small">${escapeHtml(data.Description || "-")}</td></tr>
        <tr><td class="muted">Severity</td><td><span class="badge ${sigmaLevelBadgeClass(data.SeverityStr)}">${escapeHtml(data.SeverityStr || "-")}</span></td></tr>
        ${data.ProcessId != null ? `<tr><td class="muted">Actor PID</td><td class="mono small">${escapeHtml(data.ProcessId)}</td></tr>` : ""}
        ${cats.length ? `<tr><td class="muted">Categories</td><td class="small">${cats.map(escapeHtml).join(", ")}</td></tr>` : ""}
        ${fams.length ? `<tr><td class="muted">Families</td><td class="small">${fams.map(escapeHtml).join(", ")}</td></tr>` : ""}
      </table>
      ${evidence.length ? `<h4 style="margin-top:8px">Evidence</h4><ul class="ioc-list">${evidence.map((x) => `<li class="mono small">${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
      <h4 style="margin-top:8px">Rule source</h4><div class="cape-rule-src"><div class="muted small">Loading…</div></div>
    </div>`);
  } else {
    parts.push(`<div class="alert-detail-block">
      <h4>Event</h4>
      <table class="compact">
        <tr><td class="muted">Source</td><td class="small">${escapeHtml(a.source || "-")}</td></tr>
        <tr><td class="muted">Event id</td><td class="small">${a.event_id ?? "-"}</td></tr>
        <tr><td class="muted">Event type</td><td class="small">${escapeHtml(a.event_type || "-")}</td></tr>
        <tr><td class="muted">Time</td><td class="small">${escapeHtml(data.UtcTime || a.timestamp || "-")}</td></tr>
        ${a.priority_reason ? `<tr><td class="muted">Priority</td><td class="small"><span class="badge warn">high</span> ${escapeHtml(a.priority_reason)}</td></tr>` : ""}
      </table>
    </div>`);
  }

  const mitre = a.mitre || {};
  const techs = [mitre.primary, ...(mitre.candidates || [])].filter(Boolean);
  if (techs.length) {
    parts.push(`<div class="alert-detail-block">
      <h4>MITRE ATT&CK</h4>
      <ul class="ioc-list">${techs
        .map(
          (t) =>
            `<li class="small"><span class="mitre-chip">${escapeHtml(t.technique_id)}</span> ${escapeHtml(t.technique_name || "")}${t.tactic ? ` <span class="muted">(${escapeHtml(t.tactic)})</span>` : ""}</li>`
        )
        .join("")}</ul>
    </div>`);
  }

  // The faithful raw record -- "show the raw event" for Windows-event alerts,
  // and the matched event for Sigma. Scrolls inside pre.log.
  parts.push(`<div class="alert-detail-block"><h4>Raw</h4><pre class="log">${escapeHtml(JSON.stringify(a, null, 2))}</pre></div>`);

  return parts.join("");
}

function toggleAlertDetail(row) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("alert-detail")) {
    next.remove();
    row.classList.remove("expanded");
    return;
  }
  const a = alertRegistry.get(row.dataset.key);
  if (!a) return;
  const tr = document.createElement("tr");
  tr.className = "alert-detail";
  tr.innerHTML = `<td colspan="5">${renderAlertDetail(a)}</td>`;
  row.after(tr);
  row.classList.add("expanded");

  // CAPE alerts: fill the rule-source slot lazily (endpoint shared with the
  // Rules page; degrades gracefully while an older server lacks it).
  if (a.source === "cape" || a.provider_name === "CapeSignatures") {
    const slot = tr.querySelector(".cape-rule-src");
    const sigName = (a.data || {}).Name || "";
    if (slot && sigName) {
      Api.getCapeRuleRaw(sigName)
        .then((d) => { slot.innerHTML = `<pre class="log">${escapeHtml(d.source || "")}</pre>`; })
        .catch((err) => { slot.innerHTML = `<div class="muted small">Rule source unavailable: ${escapeHtml(err.message)}</div>`; });
    }
  }
}

function wireAlertExpansion() {
  // Delegated: the alert tables (sample + environment) are re-rendered
  // wholesale, so bind once on a stable ancestor rather than per row.
  document.addEventListener("click", (e) => {
    const row = e.target.closest("tr.alert-row");
    if (row) toggleAlertDetail(row);
  });
}

let sampleAlertsPage = 0;
const SAMPLE_ALERTS_PAGE_SIZE = 100;
const alertsView = { groupByType: true, q: "", source: "" };

function alertMatchesView(a) {
  if (alertsView.source && (a.source || "") !== alertsView.source) return false;
  if (alertsView.q) {
    const needle = alertsView.q.toLowerCase();
    if (!JSON.stringify(a).toLowerCase().includes(needle)) return false;
  }
  return true;
}

function renderAlerts() {
  // report.alerts (from GET /api/reports/{id}/summary) is already
  // sample-scoped only -- report_view.py::trim_report() drops
  // environment-scoped alerts server-side now (they can number in the tens
  // of thousands with Sigma enabled), replacing them with
  // environment_alerts_total. Old reports (predating alert-scope
  // classification) are untouched by that trim, so this still renders
  // every alert exactly as before for them.
  const sampleAlerts = report.alerts || [];
  document.getElementById("alerts-count").textContent = sampleAlerts.length;
  document.getElementById("environment-alerts-count").textContent = report.environment_alerts_total ?? 0;

  const filtered = sampleAlerts.filter(alertMatchesView);

  const groupsEl = document.getElementById("alerts-groups");
  const tableEl = document.getElementById("alerts-table");
  const pagerEl = document.getElementById("alerts-pager");

  if (alertsView.groupByType) {
    // Grouped view: collapsible type groups, worst severity first, then by
    // count. First 10 rows per group + "show all N" so a noisy type can't
    // flood the page.
    tableEl.classList.add("hidden");
    pagerEl.classList.add("hidden");
    const groups = new Map();
    filtered.forEach((a) => {
      const t = a.event_type || "(unknown)";
      if (!groups.has(t)) groups.set(t, []);
      groups.get(t).push(a);
    });
    const sevRank = { crit: 0, high: 1, med: 2, low: 3 };
    const entries = [...groups.entries()].sort((x, y) => {
      const sx = Math.min(...x[1].map((a) => sevRank[alertSeverityClass(a)]));
      const sy = Math.min(...y[1].map((a) => sevRank[alertSeverityClass(a)]));
      return sx - sy || y[1].length - x[1].length;
    });
    if (!entries.length) {
      groupsEl.innerHTML = `<div class="empty-state">No matching alerts.</div>`;
      return;
    }
    groupsEl.innerHTML = entries
      .map(([type, alerts], gi) => {
        const worst = alerts.reduce((w, a) =>
          sevRank[alertSeverityClass(a)] < sevRank[alertSeverityClass(w)] ? a : w, alerts[0]);
        const preview = alerts.slice(0, 10);
        const rows = preview.map((a, i) => alertRow(a, `g${gi}-${i}`)).join("");
        const more = alerts.length > 10
          ? `<tr class="alert-show-more" data-group="${gi}"><td colspan="5" class="small">… show all ${alerts.length}</td></tr>`
          : "";
        const hiddenRows = alerts.length > 10
          ? alerts.slice(10).map((a, i) => alertRow(a, `g${gi}-${i + 10}`)).join("")
          : "";
        return `<div class="alert-group">
          <div class="alert-group-head" data-gid="${gi}">
            <span class="tree-toggle">▾</span>
            <span class="sev-dot sev-${alertSeverityClass(worst)}"></span>
            <strong>${escapeHtml(type)}</strong>
            <span class="badge neutral">${alerts.length}</span>
            ${mitreChips(worst.mitre)}
          </div>
          <table class="alert-group-table" data-gtable="${gi}">
            <tbody class="grp-preview">${rows}${more}</tbody>
            <tbody class="grp-rest hidden" data-grest="${gi}">${hiddenRows}</tbody>
          </table>
        </div>`;
      })
      .join("");
    return;
  }

  // Flat view (paginated).
  groupsEl.innerHTML = "";
  tableEl.classList.remove("hidden");
  pagerEl.classList.remove("hidden");
  const tbody = document.getElementById("alerts-body");
  const totalPages = Math.max(1, Math.ceil(filtered.length / SAMPLE_ALERTS_PAGE_SIZE));
  if (sampleAlertsPage >= totalPages) sampleAlertsPage = totalPages - 1;
  const pageRows = filtered.slice(sampleAlertsPage * SAMPLE_ALERTS_PAGE_SIZE, (sampleAlertsPage + 1) * SAMPLE_ALERTS_PAGE_SIZE);
  tbody.innerHTML = pageRows.length
    ? pageRows.map((a, i) => alertRow(a, "s" + (sampleAlertsPage * SAMPLE_ALERTS_PAGE_SIZE + i))).join("")
    : `<tr><td colspan="5" class="empty-state">No matching alerts.</td></tr>`;
  const label = document.getElementById("alerts-page-label");
  if (label) label.textContent = filtered.length > SAMPLE_ALERTS_PAGE_SIZE ? `page ${sampleAlertsPage + 1} / ${totalPages} · ${filtered.length} matching` : `${filtered.length} matching`;
  const prev = document.getElementById("btn-alerts-prev");
  const next = document.getElementById("btn-alerts-next");
  if (prev) prev.disabled = sampleAlertsPage <= 0;
  if (next) next.disabled = sampleAlertsPage >= totalPages - 1;
}

function wireSampleAlertsPager() {
  document.getElementById("btn-alerts-prev").addEventListener("click", () => {
    if (sampleAlertsPage > 0) { sampleAlertsPage--; renderAlerts(); }
  });
  document.getElementById("btn-alerts-next").addEventListener("click", () => {
    sampleAlertsPage++; renderAlerts();
  });
}

function wireAlertsToolbar() {
  // Null-guarded: if the page HTML is stale (cached) and lacks these
  // elements, bail out WITHOUT throwing -- a throw here would kill every
  // wire* call after it in main() (tree expand/collapse buttons etc.).
  const sel = document.getElementById("alerts-source-filter");
  const groupToggle = document.getElementById("alerts-group-toggle");
  const search = document.getElementById("alerts-search");
  const groupsEl = document.getElementById("alerts-groups");
  if (!sel || !groupToggle || !search || !groupsEl) return;

  // Source filter options from the sources actually present in the alerts.
  const sources = [...new Set((report.alerts || []).map((a) => a.source).filter(Boolean))].sort();
  sel.innerHTML = '<option value="">all sources</option>' +
    sources.map((s) => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join("");

  groupToggle.addEventListener("change", (e) => {
    alertsView.groupByType = e.target.checked;
    renderAlerts();
  });
  sel.addEventListener("change", () => {
    alertsView.source = sel.value;
    sampleAlertsPage = 0;
    renderAlerts();
  });
  search.addEventListener("input", (e) => {
    alertsView.q = e.target.value.trim();
    sampleAlertsPage = 0;
    renderAlerts();
  });

  // Group collapse/expand + "show all N" (delegated -- groups re-render).
  groupsEl.addEventListener("click", (e) => {
    const head = e.target.closest(".alert-group-head");
    if (head) {
      const table = document.querySelector(`[data-gtable="${head.dataset.gid}"]`);
      const toggle = head.querySelector(".tree-toggle");
      if (table) {
        const collapsed = table.classList.toggle("collapsed");
        if (toggle) toggle.textContent = collapsed ? "▸" : "▾";
      }
      return;
    }
    const more = e.target.closest(".alert-show-more");
    if (more) {
      const rest = document.querySelector(`[data-grest="${more.dataset.group}"]`);
      if (rest) rest.classList.remove("hidden");
      more.remove();
    }
  });
}

let environmentAlertsLoaded = false;
let envAlertsState = { offset: 0, limit: 200 };
async function loadEnvironmentAlerts(reset) {
  if (environmentAlertsLoaded && !reset) return;
  if (reset) envAlertsState.offset = 0;
  environmentAlertsLoaded = true;
  const envTbody = document.getElementById("environment-alerts-body");
  envTbody.innerHTML = `<tr><td colspan="5" class="empty-state">Loading…</td></tr>`;
  try {
    const data = await Api.getReportAlerts(analysisId, { scope: "environment", offset: envAlertsState.offset, limit: envAlertsState.limit });
    document.getElementById("environment-alerts-count").textContent = data.filtered_total;
    const totalPages = Math.max(1, Math.ceil(data.filtered_total / envAlertsState.limit));
    const curPage = Math.floor(envAlertsState.offset / envAlertsState.limit);
    envTbody.innerHTML = data.alerts.length
      ? data.alerts.map((a, i) => alertRow(a, "e" + (envAlertsState.offset + i))).join("")
      : `<tr><td colspan="5" class="empty-state">None.</td></tr>`;
    const label = document.getElementById("env-alerts-page-label");
    if (label) label.textContent = data.filtered_total > envAlertsState.limit ? `page ${curPage + 1} / ${totalPages}` : "";
    const prev = document.getElementById("btn-env-alerts-prev");
    const next = document.getElementById("btn-env-alerts-next");
    if (prev) prev.disabled = envAlertsState.offset <= 0;
    if (next) next.disabled = envAlertsState.offset + envAlertsState.limit >= data.filtered_total;
  } catch (e) {
    environmentAlertsLoaded = false; // allow retry on next expand
    envTbody.innerHTML = `<tr><td colspan="5" class="error-text">${escapeHtml(e.message)}</td></tr>`;
  }
}

function wireEnvironmentAlerts() {
  const section = document.getElementById("environment-alerts-section");
  section.addEventListener("toggle", () => {
    if (section.open) loadEnvironmentAlerts(true);
  });
  document.getElementById("btn-env-alerts-prev").addEventListener("click", () => {
    envAlertsState.offset = Math.max(0, envAlertsState.offset - envAlertsState.limit);
    loadEnvironmentAlerts();
  });
  document.getElementById("btn-env-alerts-next").addEventListener("click", () => {
    envAlertsState.offset += envAlertsState.limit;
    loadEnvironmentAlerts();
  });
}

function renderMitreCoverage() {
  const coverage = report.mitre_coverage || {};
  const rows = Object.entries(coverage).sort((a, b) => b[1].count - a[1].count);
  const tbody = document.getElementById("mitre-body");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty-state">No coverage data.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map(([type, info]) => {
      // Chips are clickable when the row has events to show: click loads the
      // matching event list below the table (see wireMitreEvents).
      const clickable = info.count > 0;
      const chips = (info.mitre || []).map((m) => {
        const cls = clickable ? "mitre-chip mitre-chip-link" : "mitre-chip";
        const attrs = clickable
          ? ` data-etype="${escapeHtml(type)}" data-src="${escapeHtml(info.source || "")}" data-tech="${escapeHtml(m.technique_id)}" title="show the ${info.count} ${escapeHtml(type)} event(s) behind this mapping"`
          : "";
        return `<span class="${cls}"${attrs}>${escapeHtml(m.technique_id)} ${escapeHtml(m.technique_name)}</span>`;
      }).join(" ");
      const srcTag = info.source === "alert" ? ` <span class="badge neutral" title="synthesized alert, not a raw telemetry event">alert</span>` : "";
      return `<tr><td>${escapeHtml(type)}${srcTag}</td><td>${info.count}</td><td>${chips || '<span class="muted">—</span>'}</td></tr>`;
    })
    .join("");
}

// Click a technique chip in the coverage table -> the events/alerts behind
// that event-type<->technique mapping load below the table.
function showMitreEvents(eventType, techId, source) {
  const mount = document.getElementById("mitre-events");
  if (!mount) return;
  const browser = createEventBrowser(mount, {
    analysisId,
    endpoint: source === "alert" ? "alerts" : "events",
    eventTypes: [eventType],
    note: `Events behind ${eventType} → ${techId} (${source === "alert" ? "synthesized alerts" : "raw telemetry"}; the mapping is per event-type, so every row here contributed to this technique's coverage).`,
    pageSize: 100,
    columns: telemetryColumns("generic"),
  });
  browser.load();
}

function wireMitreEvents() {
  const sec = document.getElementById("sec-mitre");
  if (!sec) return;
  sec.addEventListener("click", (e) => {
    const chip = e.target.closest(".mitre-chip-link");
    if (!chip) return;
    sec.querySelectorAll(".mitre-chip-link.active").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    showMitreEvents(chip.dataset.etype, chip.dataset.tech, chip.dataset.src);
  });
}

function procBaseName(p) {
  if (!p) return "?";
  const parts = String(p).split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function fmtClock(iso) {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleTimeString(undefined, { hour12: false });
  } catch (e) {
    return "";
  }
}

function processNode(node, alertsByPid, tracedByPid) {
  const children = (node.children || []).map((c) => processNode(c, alertsByPid, tracedByPid)).join("");
  const pid = Number(node.pid);
  const alertCount = alertsByPid.get(pid) || 0;
  const alertBadge = alertCount ? `<span class="badge bad tree-alert-badge">⚠ ${alertCount}</span>` : "";
  // Monitor attachment badge (Track 3 child-following): this process had the
  // API-tracing monitor injected -- N hooked calls captured.
  const traced = tracedByPid.get(pid);
  const tracedBadge = traced != null
    ? `<span class="badge traced" title="API-tracing monitor attached (${traced} hooked calls captured)">📡 ${traced}</span>`
    : "";
  const toggle = children ? `<span class="tree-toggle">▾</span>` : `<span class="tree-toggle-spacer"></span>`;

  const life = node.start_time
    ? `${fmtClock(node.start_time)}${node.end_time ? " → " + fmtClock(node.end_time) : " → …"}`
    : "";
  const cls = ["proc-line"];
  if (alertCount) cls.push("has-alert");
  else if (traced != null) cls.push("has-trace");
  const title = `${node.image || ""}${node.user ? " · " + node.user : ""}`;

  return `<li>
    <div class="${cls.join(" ")}" data-pid="${escapeHtml(node.pid)}" title="${escapeHtml(title)}">
      <div class="proc-head">${toggle}<span class="proc-name">${escapeHtml(procBaseName(node.image))}</span> <span class="pid">[${node.pid}]</span>${alertBadge}${tracedBadge}<span class="proc-life muted small">${escapeHtml(life)}</span></div>
      ${node.command_line ? `<div class="proc-cmd muted">${escapeHtml(node.command_line)}</div>` : ""}
    </div>
    ${children ? `<ul class="tree-children">${children}</ul>` : ""}
  </li>`;
}

// Interesting-only filter state (default ON): hide OS background noise and
// the sandbox's own tooling, keep the sample's lineage + anything with
// alerts or an API-tracing monitor attached (+ ancestors for context).
let treeInterestingOnly = true;
let treeRawNodes = [];
let treeInterestingPids = new Set();

function computeInterestingPids(tree, alertsByPid, tracedByPid) {
  const parentOf = new Map();
  const nodeOf = new Map();
  const index = (nodes, parentPid) =>
    nodes.forEach((n) => {
      const pid = Number(n.pid);
      nodeOf.set(pid, n);
      if (parentPid != null) parentOf.set(pid, parentPid);
      index(n.children || [], pid);
    });
  index(tree, null);

  const interesting = new Set();
  const markWithAncestors = (pid) => {
    let cur = pid;
    while (cur != null && !interesting.has(cur)) {
      interesting.add(cur);
      cur = parentOf.get(cur);
    }
  };

  // Seed 1: the sample root (execution_info.ProcessId) + its whole subtree.
  const rootPid = Number((report.execution_info || {}).ProcessId);
  const rootNode = nodeOf.get(rootPid);
  if (rootNode) {
    markWithAncestors(rootPid);
    const markSubtree = (n) => {
      interesting.add(Number(n.pid));
      (n.children || []).forEach(markSubtree);
    };
    markSubtree(rootNode);
  }
  // Seed 2: anything with an alert. Seed 3: anything monitor-traced.
  alertsByPid.forEach((_, pid) => markWithAncestors(pid));
  tracedByPid.forEach((_, pid) => markWithAncestors(pid));
  return interesting;
}

function pruneUninteresting(nodes, interesting) {
  return nodes
    .filter((n) => interesting.has(Number(n.pid)))
    .map((n) => ({ ...n, children: pruneUninteresting(n.children || [], interesting) }));
}

function renderProcessTree() {
  const tree = report.process_tree || [];
  const el = document.getElementById("process-tree");
  if (!tree.length) {
    el.innerHTML = `<div class="empty-state">No process data.</div>`;
    return;
  }

  // Cross-reference alerts to PIDs so suspicious processes stand out
  // without having to cross-check the Alerts table by hand.
  const alertsByPid = new Map();
  (report.alerts || []).forEach((a) => {
    const data = a.data || {};
    const pid = Number(data.ProcessId ?? data.SourceProcessId);
    if (Number.isNaN(pid)) return;
    alertsByPid.set(pid, (alertsByPid.get(pid) || 0) + 1);
  });

  // Which pids had the API-tracing monitor attached (reports predating the
  // apitrace summary field simply have no badges).
  const at = report.apitrace || {};
  const tracedByPid = new Map();
  if (at.enabled) {
    (at.attached_pids || []).forEach((pid) => tracedByPid.set(Number(pid), (at.calls_per_pid || {})[pid] ?? 0));
  }

  treeRawNodes = tree;
  treeInterestingPids = computeInterestingPids(tree, alertsByPid, tracedByPid);

  let shown = tree;
  // If the filter would empty the tree (no sample pid, no alerts, no trace),
  // showing everything is less confusing than showing nothing.
  if (treeInterestingOnly && treeInterestingPids.size > 0) {
    shown = pruneUninteresting(tree, treeInterestingPids);
  }

  el.innerHTML = `<div class="tree"><ul>${shown.map((n) => processNode(n, alertsByPid, tracedByPid)).join("")}</ul></div>`;

  // Header stats: shown/total · M with alerts · K traced · H hidden.
  let total = 0, shownCount = 0;
  const countNodes = (nodes, acc) => nodes.forEach((n) => { acc.count++; countNodes(n.children || [], acc); });
  const t = { count: 0 }; countNodes(tree, t); total = t.count;
  const s = { count: 0 }; countNodes(shown, s); shownCount = s.count;
  const hidden = total - shownCount;
  const alertPids = [...alertsByPid.keys()].filter((p) => alertsByPid.get(p) > 0).length;
  const stats = document.getElementById("proctree-stats");
  if (stats) {
    stats.textContent =
      `${shownCount} of ${total} processes · ${alertPids} with alerts` +
      (at.enabled ? ` · ${(at.attached_pids || []).length} traced` : "") +
      (hidden > 0 ? ` · ${hidden} hidden` : "");
  }
  wireProcessTreeInteractions(el);
}

function wireTreeInterestingFilter() {
  const cb = document.getElementById("filter-interesting");
  if (!cb) return;
  cb.addEventListener("change", (e) => {
    treeInterestingOnly = e.target.checked;
    renderProcessTree();
  });
}

function wireTreeExpandCollapse() {
  const expandBtn = document.getElementById("btn-tree-expand");
  const collapseBtn = document.getElementById("btn-tree-collapse");
  if (!expandBtn || !collapseBtn) return; // stale cached HTML -- degrade, don't kill main()
  expandBtn.addEventListener("click", () => {
    document.querySelectorAll("#process-tree ul.tree-children").forEach((ul) => ul.classList.remove("collapsed"));
    document.querySelectorAll("#process-tree .tree-toggle").forEach((t) => { if (t.textContent.trim()) t.textContent = "▾"; });
  });
  collapseBtn.addEventListener("click", () => {
    document.querySelectorAll("#process-tree ul.tree-children").forEach((ul) => ul.classList.add("collapsed"));
    document.querySelectorAll("#process-tree .tree-toggle").forEach((t) => { if (t.textContent.trim()) t.textContent = "▸"; });
  });
}

function wireProcessTreeInteractions(container) {
  // Delegated listener -- innerHTML is rebuilt wholesale on every
  // renderProcessTree() call, so binding here (once, on the stable
  // container) avoids re-attaching per-node listeners each time.
  if (container.dataset.wired) return;
  container.dataset.wired = "1";
  container.addEventListener("click", (e) => {
    const toggle = e.target.closest(".tree-toggle");
    if (toggle) {
      const childUl = toggle.closest("li").querySelector(":scope > ul.tree-children");
      if (childUl) {
        const collapsed = childUl.classList.toggle("collapsed");
        toggle.textContent = collapsed ? "▸" : "▾";
      }
      return;
    }
    const line = e.target.closest(".proc-line");
    if (!line) return;
    // Reuses the raw event browser's free-text search (a substring match
    // against each event's JSON) rather than adding a separate PID filter
    // path -- "processid": <pid> matches json.dumps()'s default key:value
    // spacing, same trick the search box already relies on for any query.
    document.getElementById("events-search").value = `"processid": ${line.dataset.pid}`;
    eventsState.offset = 0;
    loadEvents();
    // Route through the tab selector so the raw-events section is un-hidden
    // (tab display is exclusive) before scrolling to it.
    selectSection("events-browser", true);
  });
}

function renderStaticAnalysis() {
  const sa = report.static_analysis || {};
  const pe = sa.pe;
  const el = document.getElementById("static-analysis-body");

  let peHtml = `<div class="muted small">Not a PE file.</div>`;
  if (pe) {
    const sectionRows = (pe.sections || [])
      .map((s) => {
        const hot = s.entropy >= 7.0 ? ' style="color:var(--bad)"' : "";
        return `<tr><td class="mono">${escapeHtml(s.name)}</td><td>${s.virtual_size}</td><td>${s.raw_size}</td><td${hot}>${s.entropy}</td></tr>`;
      })
      .join("");
    peHtml = `
      <table class="compact">
        <thead><tr><th>Section</th><th>Virtual size</th><th>Raw size</th><th>Entropy</th></tr></thead>
        <tbody>${sectionRows || '<tr><td colspan="4" class="empty-state">No sections</td></tr>'}</tbody>
      </table>
      <div class="small muted" style="margin-top:8px">${(pe.imports || []).length} imported DLLs · ${(pe.exports || []).length} exports</div>
    `;
  }

  const strings = sa.strings || {};
  const interesting = strings.interesting || [];
  const yaraMatches = sa.yara || [];

  // capa capability analysis (high-signal capabilities highlighted first).
  const capa = sa.capa || {};
  let capaHtml;
  if (capa.available) {
    const caps = capa.capabilities || [];
    const rows = caps
      .map(
        (c) => `<tr>
          <td>${c.high_signal ? '<span class="badge warn">high-signal</span> ' : ""}${escapeHtml(c.name)}${
          c.lib ? ' <span class="badge neutral">lib</span>' : ""
        }</td>
          <td class="mono small muted">${escapeHtml(c.namespace || "-")}</td>
          <td class="small">${(c.attack || []).map(escapeHtml).join(", ") || "-"}</td>
        </tr>`
      )
      .join("");
    capaHtml = `
      <div class="small muted">${capa.capability_count} capabilities · ${capa.high_signal_count} high-signal · ${
      (capa.attack || []).length
    } ATT&CK techniques · capa ${escapeHtml(capa.capa_version || "?")}${capa.format === "dotnet" ? ' · <span class="badge neutral">.NET</span>' : ""}</div>
      <table class="compact">
        <thead><tr><th>Capability</th><th>Namespace</th><th>ATT&CK</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="3" class="empty-state">No capabilities matched</td></tr>'}</tbody>
      </table>`;
  } else {
    const why = capa.detail || capa.reason || "not run";
    capaHtml = `<div class="muted small">capa: ${escapeHtml(why)}.</div>`;
  }

  // .NET / CLR metadata subsection (dnfile); absent for native PEs.
  let dotnetHtml = "";
  const dn = (pe && pe.dotnet) || null;
  if (dn) {
    const obf = dn.obfuscator_suspected
      ? ` <span class="badge bad">obfuscator: ${escapeHtml((dn.obfuscator_markers || []).join(", "))}</span>`
      : ' <span class="badge ok">no obfuscator markers</span>';
    const trs = (dn.type_refs || []).slice(0, 25).map(escapeHtml).join("\n");
    const uss = (dn.user_strings || []).slice(0, 25).map(escapeHtml).join("\n");
    dotnetHtml = `
      <h3>.NET assembly</h3>
      <div class="small">${escapeHtml(dn.assembly_name || "(unnamed)")} · runtime ${escapeHtml(dn.runtime_version || "?")} · ${
      dn.mixed_mode ? "mixed-mode (native+IL)" : "pure IL"
    }${obf}</div>
      <div class="small muted">streams: ${(dn.metadata_streams || []).map(escapeHtml).join(" ") || "-"} · ${
      (dn.type_refs || []).length
    } typerefs shown (${(dn.type_defs || []).length} typedefs) · ${(dn.user_strings || []).length} user strings</div>
      <details class="aux-details" style="margin-top:6px"><summary>TypeRefs</summary><pre class="log">${trs || "(none)"}</pre></details>
      <details class="aux-details" style="margin-top:6px"><summary>#US user strings</summary><pre class="log">${uss || "(none)"}</pre></details>
    `;
  }

  el.innerHTML = `
    <h3>PE structure</h3>
    ${peHtml}
    ${dotnetHtml}
    <h3>Interesting strings (${interesting.length})</h3>
    <pre class="log">${interesting.map(escapeHtml).join("\n") || "(none)"}</pre>
    <div class="small muted">ascii: ${strings.ascii_count ?? "-"} · unicode: ${strings.unicode_count ?? "-"}</div>
    <h3>YARA matches (${yaraMatches.length})</h3>
    ${yaraMatches.length ? yaraMatches.map((m) => `<span class="badge warn">${escapeHtml(m.rule)}</span>`).join(" ") : '<div class="muted small">No matches.</div>'}
    <h3>capa capabilities${capa.available ? ` (${capa.capability_count})` : ""}</h3>
    ${capaHtml}
  `;
}

function renderExecution() {
  const info = report.execution_info || {};

  if (info.execution_error) {
    // sample_types.py already determined dynamic execution couldn't
    // proceed (e.g. an ambiguous-entry-point DLL) -- no process ever ran,
    // so there's no stdout/stderr/exit code to show.
    const detail = info.execution_error_detail;
    const detailHtml = Array.isArray(detail)
      ? `<div class="small">Exports: ${detail.map((d) => `<span class="badge neutral">${escapeHtml(d)}</span>`).join(" ")}</div>`
      : detail
      ? `<div class="small">${escapeHtml(detail)}</div>`
      : "";
    document.getElementById("execution-body").innerHTML = `
      <div class="error-text small" style="margin-bottom:8px">Dynamic execution skipped: ${escapeHtml(info.execution_error)}</div>
      ${detailHtml}
    `;
    return;
  }

  const launcherLine =
    info.LauncherPath && info.LauncherPath !== info.Path
      ? `<div class="small muted">Launched: <span class="mono">${escapeHtml(info.LauncherPath)}</span></div>`
      : "";

  document.getElementById("execution-body").innerHTML = `
    ${launcherLine}
    <div class="small muted">Exit code: ${info.ExitCode ?? "-"} · Timed out: ${info.TimedOut ? "yes" : "no"}</div>
    <h3>stdout</h3>
    <pre class="log">${escapeHtml(info.Stdout) || "(empty)"}</pre>
    <h3>stderr</h3>
    <pre class="log">${escapeHtml(info.Stderr) || "(empty)"}</pre>
  `;
}

function renderProcessDumps() {
  const pd = report.process_dumps || {};
  const container = document.getElementById("process-dumps-body");
  document.getElementById("process-dumps-count").textContent = pd.count || 0;
  if (!pd.enabled) {
    container.innerHTML = `<div class="empty-state small">Process dumps were not enabled for this run.</div>`;
    return;
  }
  const items = pd.items || [];
  if (!items.length) {
    container.innerHTML = `<div class="empty-state small">No process dumps captured (sample likely exited before the first snapshot interval).</div>`;
    return;
  }
  container.innerHTML = `
    ${pd.error ? `<div class="small error-text" style="margin-bottom:8px">${escapeHtml(pd.error)}</div>` : ""}
    <table>
      <thead><tr><th>#</th><th>Filename</th><th>Size</th><th>YARA matches</th><th></th></tr></thead>
      <tbody>
        ${items
          .map((item, i) => {
            const matches = item.yara_matches || [];
            const badges = matches.length
              ? matches.map((m) => `<span class="badge bad">${escapeHtml(m.rule)}</span>`).join(" ")
              : `<span class="muted small">none</span>`;
            return `<tr>
              <td>${i}</td>
              <td class="mono small">${escapeHtml(item.filename)}</td>
              <td>${fmtBytes(item.size_bytes)}</td>
              <td>${badges}</td>
              <td><a href="${Api.processDumpDownloadUrl(analysisId, i)}" download>download</a></td>
            </tr>`;
          })
          .join("")}
      </tbody>
    </table>
  `;
}

function renderDroppedFiles() {
  const df = report.dropped_files || {};
  const container = document.getElementById("dropped-files-body");
  document.getElementById("dropped-files-count").textContent = df.count || 0;
  if (!df.enabled) {
    container.innerHTML = `<div class="empty-state small">Dropped-file retrieval was not enabled for this run.</div>`;
    return;
  }
  const items = df.items || [];
  if (!items.length) {
    container.innerHTML = `<div class="empty-state small">No files created by the sample's own process tree were observed.</div>`;
    return;
  }
  container.innerHTML = `
    ${df.error ? `<div class="small error-text" style="margin-bottom:8px">${escapeHtml(df.error)}</div>` : ""}
    <table>
      <thead><tr><th>#</th><th>Filename</th><th>Original path</th><th>Origin</th><th>Size</th><th>SHA256</th><th>Static</th><th>YARA matches</th><th>Status</th><th></th></tr></thead>
      <tbody>
        ${items
          .map((item, i) => {
            const retrieved = item.status === "retrieved";
            const matches = item.yara_matches || [];
            const badges = matches.length
              ? matches.map((m) => `<span class="badge bad">${escapeHtml(m.rule)}</span>`).join(" ")
              : `<span class="muted small">none</span>`;
            const statusClass = retrieved ? "ok" : "warn";
            const origin = item.origin === "sysmon_archive"
              ? '<span class="badge warn" title="content recovered from Sysmon\'s deleted-file archive">deleted</span>'
              : '<span class="badge neutral">created</span>';
            // Static deep-analysis chips: packed / .NET obfuscator / capa.
            const st = item.static || {};
            const chips = [];
            if (st.packed_suspected) chips.push('<span class="badge warn">packed</span>');
            if (st.dotnet && st.dotnet.obfuscator_suspected) chips.push(`<span class="badge bad">.NET obf: ${escapeHtml((st.dotnet.obfuscator_markers || []).join(", "))}</span>`);
            else if (st.dotnet) chips.push('<span class="badge neutral">.NET</span>');
            const capa = item.capa || {};
            if (capa.available && capa.high_signal_count) chips.push(`<span class="badge bad">capa ×${capa.high_signal_count}</span>`);
            const staticCell = retrieved ? (chips.join(" ") || `<span class="muted small">${escapeHtml(st.file_type || "clean")}</span>`) : "-";
            return `<tr>
              <td>${i}</td>
              <td class="mono small">${escapeHtml(item.filename)}</td>
              <td class="mono small">${escapeHtml(item.original_path)}</td>
              <td>${origin}</td>
              <td>${retrieved ? fmtBytes(item.size_bytes) : "-"}</td>
              <td class="mono small">${retrieved ? escapeHtml(item.sha256 || "") : "-"}</td>
              <td>${staticCell}</td>
              <td>${retrieved ? badges : "-"}</td>
              <td><span class="badge ${statusClass}">${escapeHtml(item.status)}</span></td>
              <td>${retrieved ? `<a href="${Api.droppedFileDownloadUrl(analysisId, i)}" download>download</a>` : ""}</td>
            </tr>`;
          })
          .join("")}
      </tbody>
    </table>
  `;
}

function renderIocSummary() {
  const ioc = report.ioc_summary || {};

  const connections = ioc.network_connections || [];
  const domains = ioc.domains || [];
  const httpRequests = ioc.http_requests || [];
  const registryPersistence = ioc.registry_persistence || [];

  // The four indicator lists each get their own nav section (same level as
  // MITRE / Static / Execution). Sample hashes live in the Sample rail panel;
  // dropped-file hashes live in the Dropped section -- not duplicated here.
  const list = (items, render, emptyText) =>
    items.length ? `<ul class="ioc-list">${items.map(render).join("")}</ul>` : `<div class="muted small">${emptyText}</div>`;

  document.getElementById("ioc-connections-count").textContent = connections.length;
  document.getElementById("ioc-connections-body").innerHTML = list(
    connections,
    (c) => `<li class="mono small">${escapeHtml(c.destination_ip)}${c.destination_port ? ":" + escapeHtml(c.destination_port) : ""}</li>`,
    "none observed"
  );

  document.getElementById("ioc-domains-count").textContent = domains.length;
  document.getElementById("ioc-domains-body").innerHTML = list(
    domains,
    (d) => `<li class="mono small">${escapeHtml(d)}</li>`,
    "none observed"
  );

  document.getElementById("ioc-http-count").textContent = httpRequests.length;
  document.getElementById("ioc-http-body").innerHTML = list(
    httpRequests,
    (h) => `<li class="mono small">${escapeHtml(h.method)} ${escapeHtml(h.host)}${escapeHtml(h.path)} <span class="muted">(${h.count})</span></li>`,
    "none observed (plaintext HTTP only -- TLS traffic is invisible at this layer)"
  );

  document.getElementById("ioc-registry-count").textContent = registryPersistence.length;
  document.getElementById("ioc-registry-body").innerHTML = list(
    registryPersistence,
    (r) => `<li class="mono small">${escapeHtml(r.target_object)} <span class="muted">(${escapeHtml(r.priority_reason)})</span></li>`,
    "none flagged"
  );
}

// --- Detections applied (which rules/detectors fired in THIS report) ---

// Split the report's (sample-scoped) alerts into the detection family that
// produced each, so "Detections applied" mirrors the rules catalog: Sigma
// rules, YARA matches, and hardcoded heuristics.
function classifyDetections() {
  const alerts = report.alerts || [];
  const sigma = new Map(); // rule id -> {title, level, count}
  const yara = new Map(); // rule -> {rule, target, count}
  const behavioral = new Map(); // event_type -> {label, count}
  const cape = new Map(); // sig name -> {label, severity, count}
  const heur = new Map(); // key -> {label, count}

  alerts.forEach((a) => {
    if (a.sigma) {
      const id = a.sigma.id || a.sigma.title;
      const e = sigma.get(id) || { title: a.sigma.title, level: a.sigma.level, id, count: 0 };
      e.count++;
      sigma.set(id, e);
      return;
    }
    if (a.event_type === "DmpYaraMatch" || a.event_type === "DroppedFileYaraMatch") {
      const data = a.data || {};
      const rule = data.Rule || "unknown";
      const target = a.event_type === "DmpYaraMatch" ? "process dump" : "dropped file";
      const key = `${rule}@${target}`;
      const e = yara.get(key) || { rule, target, count: 0 };
      e.count++;
      yara.set(key, e);
      return;
    }
    // CAPE community signatures over the API trace -- their own family,
    // mirrors the rules catalog's CAPE tab.
    if (a.source === "cape" || a.provider_name === "CapeSignatures") {
      const data = a.data || {};
      const label = data.Name || a.event_type || "(unknown)";
      const e = cape.get(label) || { label, severity: data.SeverityStr, count: 0 };
      e.count++;
      cape.set(label, e);
      return;
    }
    // API-trace behavioral signatures are their own family (not generic
    // heuristics) -- mirrors the rules catalog's Behavioral tab.
    if (a.source === "apitrace" || a.provider_name === "BehavioralSignatures") {
      const label = a.event_type || "(unknown)";
      const e = behavioral.get(label) || { label, count: 0 };
      e.count++;
      behavioral.set(label, e);
      return;
    }
    // everything else is a heuristic alert; group by its priority reason or type
    const label = a.priority_reason || a.event_type || "(unknown)";
    const e = heur.get(label) || { label, count: 0, priority: a.priority };
    e.count++;
    heur.set(label, e);
  });

  // static-analysis YARA matches on the submitted sample itself
  const staticYara = ((report.static_analysis || {}).yara || []).filter((m) => !m.error);
  staticYara.forEach((m) => {
    const key = `${m.rule}@sample`;
    yara.set(key, { rule: m.rule, target: "submitted sample", count: 1 });
  });

  return { sigma: [...sigma.values()], yara: [...yara.values()], behavioral: [...behavioral.values()], cape: [...cape.values()], heur: [...heur.values()] };
}

function firedDetectionCount() {
  const d = classifyDetections();
  const staticSignals = staticSignalsFired().length;
  return d.sigma.length + d.yara.length + d.behavioral.length + d.cape.length + d.heur.length + staticSignals;
}

function staticSignalsFired() {
  const sa = report.static_analysis || {};
  const out = [];
  if (sa.packed_suspected) out.push({ name: "High-entropy / packing", detail: (sa.packing_reasons || []).join("; ") });
  const sig = sa.signature || {};
  if (sig && sig.signed === false) out.push({ name: "Unsigned binary", detail: sig.status || "" });
  const sy = (sa.yara || []).filter((m) => !m.error);
  if (sy.length) out.push({ name: "Static YARA match", detail: sy.map((m) => m.rule).join(", ") });
  return out;
}

function renderDetectionsInto(elId, spanPrefix) {
  const el = document.getElementById(elId);
  if (!el) return;
  const d = classifyDetections();
  const staticSignals = staticSignalsFired();

  const sigmaLevelBadge = (lvl) => `<span class="badge ${sigmaLevelBadgeClass(lvl)}">${escapeHtml(lvl || "-")}</span>`;

  const familyBlock = (title, firedCount, inner) => `
    <div class="det-family">
      <div class="det-family-head">
        <strong>${escapeHtml(title)}</strong>
        <span class="small muted"><span class="det-fired">${firedCount}</span> fired<span id="${spanPrefix}-${title.toLowerCase().replace(/[^a-z]+/g, "")}-loaded"></span></span>
      </div>
      ${inner}
    </div>`;

  const sigmaInner = d.sigma.length
    ? `<table class="compact"><thead><tr><th>Level</th><th>Rule</th><th>Hits</th></tr></thead><tbody>${d.sigma
        .sort((a, b) => b.count - a.count)
        .map((r) => `<tr title="${escapeHtml(r.id || "")}"><td>${sigmaLevelBadge(r.level)}</td><td>${escapeHtml(r.title || "(untitled)")}</td><td>${r.count}</td></tr>`)
        .join("")}</tbody></table>`
    : `<div class="muted small">No Sigma rules fired.</div>`;

  const yaraInner = d.yara.length
    ? `<ul class="ioc-list">${d.yara
        .map((y) => `<li class="small"><span class="badge bad">${escapeHtml(y.rule)}</span> <span class="muted">${escapeHtml(y.target)}</span></li>`)
        .join("")}</ul>`
    : `<div class="muted small">No YARA matches.</div>`;

  const behavioralInner = d.behavioral.length
    ? `<ul class="ioc-list">${d.behavioral
        .sort((a, b) => b.count - a.count)
        .map(
          (b) =>
            `<li class="small"><span class="badge neutral">apitrace</span> ${escapeHtml(b.label)} <span class="muted">(${b.count})</span></li>`
        )
        .join("")}</ul>`
    : `<div class="muted small">No behavioral signatures fired.</div>`;

  const capeInner = d.cape.length
    ? `<ul class="ioc-list">${d.cape
        .sort((a, b) => b.count - a.count)
        .map(
          (c) =>
            `<li class="small"><span class="badge neutral">cape</span> ${escapeHtml(c.label)}${c.severity ? ` <span class="muted">(${escapeHtml(c.severity)}, ${c.count}x)</span>` : ` <span class="muted">(${c.count}x)</span>`}</li>`
        )
        .join("")}</ul>`
    : `<div class="muted small">No CAPE community signatures fired.</div>`;

  const heurInner = d.heur.length
    ? `<ul class="ioc-list">${d.heur
        .sort((a, b) => b.count - a.count)
        .map(
          (h) =>
            `<li class="small">${h.priority === "high" ? '<span class="badge warn">high</span> ' : ""}${escapeHtml(h.label)} <span class="muted">(${h.count})</span></li>`
        )
        .join("")}</ul>`
    : `<div class="muted small">No heuristic detectors fired.</div>`;

  const staticInner = staticSignals.length
    ? `<ul class="ioc-list">${staticSignals
        .map((s) => `<li class="small"><strong>${escapeHtml(s.name)}</strong>${s.detail ? ` <span class="muted">${escapeHtml(s.detail)}</span>` : ""}</li>`)
        .join("")}</ul>`
    : `<div class="muted small">No static-analysis signals triggered.</div>`;

  el.innerHTML = `
    <div class="small muted" style="margin-bottom:10px">What fired for this sample, grouped by detection family. Browse the full catalog under <a href="rules.html">Rules</a>.</div>
    ${familyBlock("Sigma", d.sigma.length, sigmaInner)}
    ${familyBlock("YARA", d.yara.length, yaraInner)}
    ${familyBlock("Behavioral signatures", d.behavioral.length, behavioralInner)}
    ${familyBlock("CAPE community", d.cape.length, capeInner)}
    ${familyBlock("Heuristics", d.heur.length, heurInner)}
    ${familyBlock("Static-analysis signals", staticSignals.length, staticInner)}
  `;

  // Fill in "of N loaded" annotations from the catalog summary, async so a
  // cold ~5s Sigma parse never blocks rendering what already fired.
  Api.getRulesSummary()
    .then((cat) => {
      const set = (suffix, n) => {
        const node = document.getElementById(`${spanPrefix}-${suffix}-loaded`);
        if (node) node.textContent = ` of ${n} loaded`;
      };
      set("sigma", cat.counts.sigma);
      set("yara", cat.counts.yara);
      set("behavioralsignatures", cat.counts.behavioral ?? 0);
      set("capecommunity", cat.counts.cape ?? 0);
      set("heuristics", cat.counts.heuristics);
      set("staticanalysissignals", cat.counts.static);
    })
    .catch(() => {});
}

function renderDetections() {
  // Right-rail summary + the full-width "Detections" tab share one renderer.
  renderDetectionsInto("detections-body", "det");
  renderDetectionsInto("detections-wide-body", "detw");
}

function iocListCount(key) {
  return () => ((report.ioc_summary || {})[key] || []).length;
}

// --- Telemetry tab model --------------------------------------------------
// Sysmon event_type families (names from agent/windows/sysmon_parser.py) --
// each telemetry tab is one createEventBrowser over one of these families.
const INJECTION_EVENT_TYPES = ["ImageLoad", "CreateRemoteThread", "ProcessAccess", "ProcessTampering", "RawAccessRead"];
const SCRIPT_EVENT_TYPES = ["AmsiScanDetected", "ScriptBlockLogged"];
const FILE_EVENT_TYPES = ["FileCreateTime", "FileCreate", "FileCreateStreamHash", "FileDelete", "FileDeleteDetected"];
const REGISTRY_EVENT_TYPES = ["RegistryCreateDelete", "RegistryValueSet", "RegistryKeyValueRename"];
const PROCESS_EVENT_TYPES = ["ProcessCreate", "ProcessTerminate"];
const NETWORK_EVENT_TYPES = ["NetworkConnect", "DnsQuery"];
const OTHER_SYSMON_EVENT_TYPES = [
  "DriverLoad", "PipeCreated", "PipeConnected",
  "WmiEventFilter", "WmiEventConsumer", "WmiEventConsumerToFilter",
  "ClipboardChange", "FileBlockExecutable", "FileBlockShredding", "FileExecutableDetected",
  "SysmonEvent255",
];
const EVENTLOG_SOURCES = ["security", "system", "windefend"];
const BLINDSPOT_ALERT_TYPES = ["ApitraceBlindSpot", "ApitraceSilence"];
const GUARDIAN_ALERT_TYPES = ["GuardianProtectedAccess", "GuardianProtectedRegistry", "GuardianModuleRemap", "GuardianInjectionFailed"];
function guardianAlertCount() {
  return (report.alerts || []).filter((a) => GUARDIAN_ALERT_TYPES.includes(a.event_type)).length;
}

function eventTypeCounts() {
  return (((report || {}).summary || {}).event_counts) || {};
}
function typeCount(types) {
  const counts = eventTypeCounts();
  return types.reduce((n, t) => n + (counts[t] || 0), 0);
}
// Security/System/Defender event-log volume: type vocabulary is open-ended
// (SecurityEvent4673, SystemEvent16, DefenderThreatDetected, ...), so count
// by prefix over the event-type histogram.
function eventlogCount() {
  const counts = eventTypeCounts();
  return Object.entries(counts)
    .filter(([t]) => /^(Security|System|Defender)/.test(t))
    .reduce((n, [, c]) => n + c, 0);
}

// Each section becomes one chip in the sticky section selector, grouped by
// conceptual level (findings vs telemetry modules vs artifacts vs analysis).
// The selector shows ONE section at a time (the rest are hidden, not just
// collapsed) so the page isn't an overwhelming wall of every list at once.
// `count` is read live from the already-loaded report so the tab shows how
// much is inside before you open it; a 0 dims the tab. `count: null` means
// "no meaningful count". Network and Screenshots are intentionally
// count-less: their totals are filled in asynchronously by
// NetworkView/ScreenshotView, so a synchronous count would race.
const NAV_GROUPS = [
  { label: "Findings", sections: [
    { target: "sec-alerts", label: "Alerts", count: () => (report.alerts || []).length, alerty: true },
    { target: "sec-mitre", label: "MITRE", count: () => Object.keys(report.mitre_coverage || {}).length },
    { target: "sec-detections-wide", label: "Detections", count: () => firedDetectionCount() },
  ]},
  { label: "Telemetry", sections: [
    { target: "sec-injection", label: "Injection", count: () => typeCount(INJECTION_EVENT_TYPES) },
    { target: "sec-hooks", label: "API trace", count: () => Object.values(((report || {}).apitrace || {}).calls_per_pid || {}).reduce((a, b) => a + b, 0) },
    { target: "sec-blindspots", label: "Blind spots", count: () => (report.alerts || []).filter((a) => BLINDSPOT_ALERT_TYPES.includes(a.event_type)).length, alerty: true },
    { target: "sec-guardian", label: "Guardian", count: guardianAlertCount, alerty: true },
    { target: "sec-scripts", label: "Scripts", count: () => typeCount(SCRIPT_EVENT_TYPES) },
    { target: "sec-processes", label: "Processes", count: () => typeCount(PROCESS_EVENT_TYPES) },
    { target: "sec-filesystem", label: "Filesystem", count: () => typeCount(FILE_EVENT_TYPES) + ((report.dropped_files || {}).count || 0) },
    { target: "sec-registry", label: "Registry", count: () => typeCount(REGISTRY_EVENT_TYPES) + iocListCount("registry_persistence")() },
    { target: "sec-eventlogs", label: "Event logs", count: () => eventlogCount() },
    { target: "sec-sysmon-other", label: "Sysmon other", count: () => typeCount(OTHER_SYSMON_EVENT_TYPES) },
  ]},
  { label: "Network", sections: [
    { target: "sec-network", label: "Network", count: null },
  ]},
  { label: "Artifacts", sections: [
    { target: "sec-dumps", label: "Dumps", count: () => (report.process_dumps || {}).count || 0 },
    { target: "sec-screenshots", label: "Screens", count: null },
  ]},
  { label: "Analysis", sections: [
    { target: "sec-static", label: "Static", count: null },
    { target: "environment-alerts-section", label: "Env noise", count: () => report.environment_alerts_total || 0 },
    { target: "events-browser", label: "Raw events", count: () => (report.summary || {}).total_events ?? report.events_total ?? 0 },
  ]},
];

const ALL_SECTIONS_TARGET = "__all__";

// Telemetry tabs fetch their stream on FIRST open, not on page load (each
// load is a filtered scan over the full event stream).
const lazyLoaders = {}; // target -> fn, deleted after first call
function registerLazy(target, fn) { lazyLoaders[target] = fn; }

// Show only the selected section (or all of them). `scroll` is true for
// user clicks so the section clears the sticky bars, false on initial load
// so the page opens at the top.
function selectSection(target, scroll) {
  const showAll = target === ALL_SECTIONS_TARGET;
  // Only top-level sections are tab-managed; sec-detections lives in the
  // right-hand rail (nested under .report-side) and stays always visible.
  document.querySelectorAll("main > details.section").forEach((section) => {
    const show = showAll || section.id === target;
    section.classList.toggle("tab-hidden", !show);
    // Force the visible tab open (also fires the `toggle` event that
    // lazy-loads the environment-alerts table on demand).
    if (show && !showAll) section.open = true;
  });

  document.querySelectorAll("#section-nav .nav-chip").forEach((chip) => {
    chip.classList.toggle("active", chip.dataset.target === target);
  });

  // First-open fetch for telemetry tabs.
  if (!showAll && lazyLoaders[target]) {
    const fn = lazyLoaders[target];
    delete lazyLoaders[target];
    fn();
  }

  // Deep-link support: #tab=<section-id> survives a reload/share.
  if (scroll) {
    try {
      history.replaceState(null, "", showAll
        ? location.pathname + location.search
        : `${location.pathname}${location.search}#tab=${target}`);
    } catch (e) { /* file:// or sandboxed contexts */ }
  }

  if (scroll && !showAll) {
    const el = document.getElementById(target);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function buildSectionNav() {
  const nav = document.getElementById("section-nav");
  if (!nav) return;

  const groups = NAV_GROUPS
    .map((g) => ({ label: g.label, sections: g.sections.filter((s) => document.getElementById(s.target)) }))
    .filter((g) => g.sections.length);
  const allSections = groups.flatMap((g) => g.sections);

  const chipHtml = (s) => {
    const c = s.count ? s.count() : null;
    const empty = c === 0;
    const cls = ["nav-chip", empty ? "is-empty" : "", s.alerty && c > 0 ? "has-alerts" : ""].filter(Boolean).join(" ");
    const countHtml = c === null ? "" : `<span class="nav-count">${c}</span>`;
    return `<span class="${cls}" data-target="${s.target}">${escapeHtml(s.label)}${countHtml}</span>`;
  };

  // Group selector -> only that group's subcategory chips render. Keeps the
  // bar to one row even as the telemetry tab count grows.
  nav.innerHTML =
    `<select id="nav-group-select" class="nav-group-select" title="Section group">` +
    groups.map((g, i) => `<option value="${i}">${escapeHtml(g.label)} (${g.sections.length})</option>`).join("") +
    `<option value="${ALL_SECTIONS_TARGET}">Show all sections</option>` +
    `</select><span id="nav-chips" class="nav-chips"></span>`;

  const select = document.getElementById("nav-group-select");
  const chipsEl = document.getElementById("nav-chips");

  const renderGroup = (gi) => {
    chipsEl.innerHTML = groups[gi].sections.map(chipHtml).join("");
  };

  select.addEventListener("change", () => {
    if (select.value === ALL_SECTIONS_TARGET) {
      chipsEl.innerHTML = "";
      selectSection(ALL_SECTIONS_TARGET, true);
      return;
    }
    const gi = Number(select.value);
    renderGroup(gi);
    // Activate the group's first section unless the currently visible one
    // already belongs to this group.
    const current = chipsEl.querySelector(".nav-chip.active");
    if (!current) selectSection(groups[gi].sections[0].target, true);
  });

  chipsEl.addEventListener("click", (e) => {
    const chip = e.target.closest(".nav-chip");
    if (chip) selectSection(chip.dataset.target, true);
  });

  // Initial tab: #tab=<id> deep link wins, otherwise the first section of
  // the first group (Findings -> Alerts).
  const hashTarget = (location.hash || "").replace(/^#tab=/, "");
  const initial = allSections.find((s) => s.target === hashTarget) || allSections[0];
  const gi = Math.max(0, groups.findIndex((g) => g.sections.includes(initial)));
  select.value = String(gi);
  renderGroup(gi);
  if (initial) selectSection(initial.target, false);

  // Pin the nav just under the sticky topbar, and give sections a
  // scroll-margin so a switched-to section clears both bars. Measured (not
  // hardcoded) because the header height isn't fixed across viewport widths.
  const header = document.querySelector("header.topbar");
  const headerH = header ? header.offsetHeight : 46;
  document.documentElement.style.setProperty("--nav-top", `${headerH}px`);
  requestAnimationFrame(() => {
    document.documentElement.style.setProperty("--sticky-offset", `${headerH + nav.offsetHeight + 12}px`);
  });
}

let eventsSourcesPopulated = false;
function populateEventSources(sources) {
  if (eventsSourcesPopulated || !Array.isArray(sources)) return;
  eventsSourcesPopulated = true;
  const sel = document.getElementById("events-source-filter");
  if (!sel) return;
  sources.forEach((s) => {
    const opt = document.createElement("option");
    opt.value = s;
    opt.textContent = s;
    sel.appendChild(opt);
  });
}

// --- Hooks / API trace section --------------------------------------------

function renderHooks() {
  const summaryEl = document.getElementById("hooks-summary");
  if (!summaryEl) return;
  const apitrace = (report && report.apitrace) || { enabled: false };

  if (!apitrace.enabled) {
    summaryEl.innerHTML = `<div class="muted small">Behavioral monitor was not attached for this run (older report or injection failed) -- no API trace captured.</div>`;
    const inv = document.getElementById("hooks-inventory");
    if (inv) inv.innerHTML = renderHooksetInventory();
    const ac = document.getElementById("hooks-active-count");
    if (ac) ac.textContent = hooksetTotal();
    return;
  }

  const pids = apitrace.attached_pids || [];
  const calls = apitrace.calls_per_pid || {};
  const totalCalls = Object.values(calls).reduce((a, b) => a + b, 0);
  const trunc = apitrace.truncated || [];
  const pidRows = pids
    .map((pid) => `<span class="badge">pid ${pid}</span> <span class="small muted">${calls[pid] ?? 0} calls</span>`)
    .join(" &nbsp;·&nbsp; ");
  summaryEl.innerHTML =
    `<div style="margin-bottom:6px"><b>${pids.length}</b> monitored process(es), <b>${totalCalls}</b> hooked calls</div>` +
    `<div style="margin-bottom:6px">${pidRows}</div>` +
    (trunc.length
      ? `<div class="small" style="color:var(--warn,#c90)">⚠ trace truncated: ${escapeHtml(JSON.stringify(trunc))}</div>`
      : `<div class="small muted">trace complete (no volume caps hit)</div>`);

  const countEl = document.getElementById("hooks-count");
  if (countEl) countEl.textContent = totalCalls;
  const inv = document.getElementById("hooks-inventory");
  if (inv) inv.innerHTML = renderHooksetInventory();
  const ac = document.getElementById("hooks-active-count");
  if (ac) ac.textContent = hooksetTotal();
}

function renderHooksetInventory() {
  if (hooksetData && Array.isArray(hooksetData.categories)) {
    return (
      `<table><thead><tr><th>Family</th><th>Hooked APIs</th><th>Sysmon counterpart</th><th>What it sees</th></tr></thead><tbody>` +
      hooksetData.categories
        .map(
          (c) =>
            `<tr><td class="small">${escapeHtml(c.name)}</td>` +
            `<td class="mono small">${c.hooks
              .map((h) => {
                const cls = h.coverage && h.coverage !== "both" ? ` <span class="badge neutral" title="coverage class">${escapeHtml(h.coverage)}</span>` : "";
                return `${escapeHtml(h.api)}${cls}`;
              })
              .join("<br>")}</td>` +
            `<td class="small muted">${c.hooks
              .map((h) => (h.sysmon_counterparts && h.sysmon_counterparts.length ? `EID ${h.sysmon_counterparts.join("/")}` : "&mdash;"))
              .join("<br>")}</td>` +
            `<td class="small muted">${escapeHtml(c.description || "")}</td></tr>`
        )
        .join("") +
      `</tbody></table>`
    );
  }
  return (
    `<table><thead><tr><th>Family</th><th>Hooked APIs</th><th>What it sees</th></tr></thead><tbody>` +
    HOOKSET.map(
      (f) =>
        `<tr><td class="small">${escapeHtml(f.family)}</td>` +
        `<td class="mono small">${f.apis.map(escapeHtml).join("<br>")}</td>` +
        `<td class="small muted">${escapeHtml(f.desc)}</td></tr>`
    ).join("") +
    `</tbody></table>`
  );
}

async function loadHooks() {
  const tbody = document.getElementById("hooks-body");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Loading…</td></tr>`;
  hooksState.q = document.getElementById("hooks-search").value;
  try {
    const data = await Api.getReportEvents(analysisId, {
      offset: hooksState.offset,
      limit: hooksState.limit,
      source: "apitrace",
      q: hooksState.q,
    });
    const countEl = document.getElementById("hooks-count");
    if (countEl) countEl.textContent = `${data.filtered_total} / ${data.total}`;
    if (!data.events.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No matching hooked calls.</td></tr>`;
    } else {
      tbody.innerHTML = data.events
        .map((e) => {
          const ts = e.timestamp || (e.data || {}).UtcTime || "";
          const d = e.data || {};
          return (
            `<tr><td class="small">${escapeHtml(ts)}</td>` +
            `<td class="mono small">${escapeHtml(d.Api || "")}</td>` +
            `<td class="small">${escapeHtml(d.Category || "")}</td>` +
            `<td class="small">${escapeHtml(String(d.ProcessId ?? ""))}</td>` +
            `<td class="small">${escapeHtml(String(d.ThreadId ?? ""))}</td>` +
            `<td class="mono small">${escapeHtml((d.Arg0 || "").length > 250 ? d.Arg0.slice(0, 250) + "…" : d.Arg0 || "")}</td></tr>`
          );
        })
        .join("");
    }
    document.getElementById("hooks-page-label").textContent = `offset ${hooksState.offset}`;
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="error-text">${escapeHtml(e.message)}</td></tr>`;
  }
}

function wireHooks() {
  const on = (id, fn) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("click", fn);
  };
  on("btn-load-hooks", () => { hooksState.offset = 0; loadHooks(); });
  on("btn-hooks-prev", () => { hooksState.offset = Math.max(0, hooksState.offset - hooksState.limit); loadHooks(); });
  on("btn-hooks-next", () => { hooksState.offset += hooksState.limit; loadHooks(); });
}

async function loadEvents() {
  const tbody = document.getElementById("events-body");
  tbody.innerHTML = `<tr><td colspan="3" class="empty-state">Loading…</td></tr>`;
  eventsState.eventType = document.getElementById("events-type-filter").value;
  eventsState.source = (document.getElementById("events-source-filter") || {}).value || "";
  eventsState.q = document.getElementById("events-search").value;
  try {
    const data = await Api.getReportEvents(analysisId, eventsState);
    populateEventSources(data.sources);
    document.getElementById("events-count").textContent = `${data.filtered_total} / ${data.total}`;
    if (!data.events.length) {
      tbody.innerHTML = `<tr><td colspan="3" class="empty-state">No matching events.</td></tr>`;
      return;
    }
    tbody.innerHTML = data.events
      .map((e) => {
        const ts = e.timestamp || (e.data || {}).UtcTime || "";
        const evType = e.event_type || e.EventType || "";
        const d = e.data || {};
        // ApiCall rows read far better as "Api pid/tid: arg0" than raw JSON.
        let dataStr;
        if (evType === "ApiCall" && d.Api) {
          dataStr = `${d.Api} [pid ${d.ProcessId ?? "?"}/tid ${d.ThreadId ?? "?"}] ${d.Arg0 || ""}`;
        } else {
          dataStr = JSON.stringify(d);
        }
        return `<tr><td class="small">${escapeHtml(ts)}</td><td class="small">${escapeHtml(evType)}</td><td class="mono small">${escapeHtml(dataStr.length > 300 ? dataStr.slice(0, 300) + "…" : dataStr)}</td></tr>`;
      })
      .join("");
    document.getElementById("events-page-label").textContent = `offset ${eventsState.offset}`;
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="3" class="error-text">${escapeHtml(e.message)}</td></tr>`;
  }
}

function wireEventsBrowser() {
  document.getElementById("btn-load-events").addEventListener("click", () => {
    eventsState.offset = 0;
    loadEvents();
  });
  document.getElementById("btn-events-prev").addEventListener("click", () => {
    eventsState.offset = Math.max(0, eventsState.offset - eventsState.limit);
    loadEvents();
  });
  document.getElementById("btn-events-next").addEventListener("click", () => {
    eventsState.offset += eventsState.limit;
    loadEvents();
  });
}

// --- Telemetry tabs (one createEventBrowser per Sysmon EID family) -------

function telemetryColumns(kind) {
  const timeCol = { label: "Time", render: (e, d) => escapeHtml(d.UtcTime || e.timestamp || "") };
  const typeCol = { label: "Type", render: (e) => escapeHtml(`EID${e.event_id} ${e.event_type || ""}`) };
  const actorCol = { label: "Actor", render: (e, d) => escapeHtml(`${d.ProcessId ?? ""} ${procBaseName(d.Image)}`) };
  switch (kind) {
    case "injection":
      return [timeCol, typeCol, actorCol,
        { label: "Target", render: (e, d) => escapeHtml(d.TargetProcessId != null ? `${d.TargetProcessId} ${procBaseName(d.TargetImage || "")}` : procBaseName(d.ImageLoaded || d.TargetObject || "")) },
        { label: "Detail", cls: "mono small", render: (e, d) => escapeHtml(d.GrantedAccess || d.Type || d.ImageLoaded || d.NewThreadId || "") }];
    case "processes":
      return [timeCol, typeCol, actorCol,
        { label: "Command line", cls: "mono small", render: (e, d) => escapeHtml((d.CommandLine || "").length > 220 ? d.CommandLine.slice(0, 220) + "…" : d.CommandLine || "") }];
    case "files":
      return [timeCol, typeCol, actorCol,
        { label: "Target", cls: "mono small", render: (e, d) => escapeHtml(d.TargetFilename || "") }];
    case "registry":
      return [timeCol, typeCol, actorCol,
        { label: "Key / value", cls: "mono small", render: (e, d) => escapeHtml(d.TargetObject || "") },
        { label: "Detail", cls: "mono small", render: (e, d) => escapeHtml((d.Details || d.EventType || "").toString().slice(0, 160)) }];
    case "amsi":
      return [timeCol,
        { label: "App", render: (e, d) => escapeHtml(d.AppName || "") },
        { label: "PID", render: (e, d) => escapeHtml(String(d.ProcessId ?? "")) },
        { label: "Scan result", render: (e, d) => {
          const r = Number(d.ScanResult || 0);
          return r ? `<span class="badge bad">${escapeHtml(String(d.ScanResult))}</span>` : escapeHtml(String(d.ScanResult ?? "0"));
        } },
        { label: "Content (preview)", cls: "mono small", render: (e, d) => escapeHtml((d.Content || "").slice(0, 250)) }];
    case "network":
      return [timeCol, typeCol, actorCol,
        { label: "Destination / query", cls: "mono small", render: (e, d) => escapeHtml(
          d.DestinationIp ? `${d.DestinationIp}${d.DestinationPort ? ":" + d.DestinationPort : ""}` : (d.QueryName || d.Image || "")
        ) },
        { label: "Detail", cls: "mono small", render: (e, d) => escapeHtml((d.QueryResults || d.QueryStatus || d.Protocol || "").toString().slice(0, 120)) }];
    default:
      return [timeCol,
        { label: "Type", render: (e) => escapeHtml(e.event_type || e.EventType || "") },
        { label: "PID", render: (e, d) => escapeHtml(String(d.ProcessId ?? d.SourceProcessId ?? "")) },
        { label: "Summary", cls: "mono small", render: (e, d) => escapeHtml((d.Image || d.TargetImage || d.Type || JSON.stringify(d)).toString().slice(0, 180)) }];
  }
}

function wireTelemetryTabs() {
  const mk = (mountId, kind, cfg) => {
    const el = document.getElementById(mountId);
    if (!el) return null;
    return createEventBrowser(el, { analysisId, columns: telemetryColumns(kind), ...cfg });
  };

  const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setText("injection-count", typeCount(INJECTION_EVENT_TYPES));
  setText("scripts-count", typeCount(SCRIPT_EVENT_TYPES));
  setText("processes-count", typeCount(PROCESS_EVENT_TYPES));
  setText("filesystem-count", typeCount(FILE_EVENT_TYPES));
  setText("registry-count", typeCount(REGISTRY_EVENT_TYPES));

  const injection = mk("injection-body", "injection", {
    source: "sysmon", eventTypes: INJECTION_EVENT_TYPES,
    note: "Kernel-backed injection & memory telemetry: image loads (EID 7), remote threads (8), raw memory reads (9), cross-process access (10), process tampering (25). Cross-reference with the API trace tab -- a Sysmon event here with no hooked-call counterpart is exactly what ApitraceBlindSpot alerts on (unhooking / direct syscalls).",
    searchPlaceholder: "filter image / target / access mask…",
  });
  if (injection) registerLazy("sec-injection", injection.load);

  const processes = mk("processes-browser", "processes", {
    source: "sysmon", eventTypes: PROCESS_EVENT_TYPES,
    searchPlaceholder: "filter image / command line…",
  });
  if (processes) registerLazy("sec-processes", processes.load);

  const files = mk("files-browser", "files", {
    source: "sysmon", eventTypes: FILE_EVENT_TYPES,
    searchPlaceholder: "filter filename / image…",
  });
  if (files) registerLazy("sec-filesystem", files.load);

  const registry = mk("registry-browser", "registry", {
    source: "sysmon", eventTypes: REGISTRY_EVENT_TYPES,
    searchPlaceholder: "filter key path / image…",
  });
  if (registry) registerLazy("sec-registry", registry.load);

  const netEvents = mk("network-events-browser", "network", {
    source: "sysmon", eventTypes: NETWORK_EVENT_TYPES,
    searchPlaceholder: "filter ip / domain / image…",
  });
  if (netEvents) registerLazy("sec-network", netEvents.load);

  const eventlogs = mk("eventlogs-browser", "generic", {
    source: EVENTLOG_SOURCES, eventTypes: [],
    searchPlaceholder: "filter user / object / threat name…",
  });
  if (eventlogs) registerLazy("sec-eventlogs", eventlogs.load);

  const sysmonOther = mk("sysmon-other-browser", "generic", {
    source: "sysmon", eventTypes: OTHER_SYSMON_EVENT_TYPES,
    searchPlaceholder: "filter driver / pipe / target…",
  });
  if (sysmonOther) registerLazy("sec-sysmon-other", sysmonOther.load);

  const blindspots = mk("blindspots-browser", "blindspot", {
    endpoint: "alerts", eventTypes: BLINDSPOT_ALERT_TYPES,
    searchPlaceholder: "filter hook / pid…",
    emptyText: "No blind-spot or silence alerts for this run.",
  });
  if (blindspots) registerLazy("sec-blindspots", blindspots.load);

  const guardianAlerts = mk("guardian-alerts-browser", "guardian", {
    endpoint: "alerts", eventTypes: GUARDIAN_ALERT_TYPES,
    searchPlaceholder: "filter target / pid…",
    emptyText: "No guardian driver alerts for this run.",
  });
  const guardianEvents = mk("guardian-events-browser", "guardian", {
    source: "guardian", eventTypes: [],
    searchPlaceholder: "filter driver event detail…",
    emptyText: "No guardian driver events captured for this run.",
  });
  if (guardianAlerts || guardianEvents) registerLazy("sec-guardian", () => {
    if (guardianAlerts) guardianAlerts.load();
    if (guardianEvents) guardianEvents.load();
  });
  setText("guardian-count", guardianAlertCount());
  renderBlindspotCoverage();
  setText("blindspots-count", (report.alerts || []).filter((a) => BLINDSPOT_ALERT_TYPES.includes(a.event_type)).length);
  setText("eventlogs-count", eventlogCount());
  setText("sysmon-other-count", typeCount(OTHER_SYSMON_EVENT_TYPES));

  const amsi = mk("amsi-browser", "amsi", {
    source: "amsi", eventTypes: [],
    searchPlaceholder: "filter AMSI content…",
    emptyText: "Open this tab to load AMSI scans.",
  });
  registerLazy("sec-scripts", () => {
    loadScriptBlocks();
    if (amsi) amsi.load();
  });
}

// PowerShell script blocks: EID 4104 fragments grouped back into whole
// scripts (ScriptBlockId + MessageNumber/MessageTotal reassembly).
async function loadScriptBlocks() {
  const body = document.getElementById("ps-blocks-body");
  if (!body) return;
  body.innerHTML = `<div class="empty-state small">Loading…</div>`;
  try {
    const data = await Api.getReportEvents(analysisId, { source: "powershell", limit: 5000 });
    const blocks = new Map();
    (data.events || []).forEach((e) => {
      const d = e.data || {};
      const id = d.ScriptBlockId || `unknown-${blocks.size}`;
      const b = blocks.get(id) || { id, path: "", fragments: [] };
      b.fragments.push({ n: d.MessageNumber ?? b.fragments.length + 1, text: d.ScriptBlockText || "" });
      if (d.Path && !b.path) b.path = d.Path;
      blocks.set(id, b);
    });
    const countEl = document.getElementById("ps-blocks-count");
    if (countEl) countEl.textContent = blocks.size;
    if (!blocks.size) {
      body.innerHTML = `<div class="muted small">No PowerShell script blocks logged for this run.</div>`;
      return;
    }
    body.innerHTML = [...blocks.values()]
      .map((b) => {
        b.fragments.sort((x, y) => x.n - y.n);
        const text = b.fragments.map((f) => f.text).join("");
        return `<details class="aux-details script-card">
          <summary><span class="mono small">${escapeHtml(b.id.slice(0, 24))}${b.id.length > 24 ? "…" : ""}</span> <span class="muted small">${b.fragments.length} fragment(s) &middot; ${escapeHtml(b.path || "interactive / in-memory")}</span></summary>
          <div class="aux-body"><pre class="log script-text">${escapeHtml(text)}</pre></div>
        </details>`;
      })
      .join("");
  } catch (e) {
    body.innerHTML = `<div class="error-text small">${escapeHtml(e.message)}</div>`;
  }
}

async function main() {
  if (!analysisId) {
    document.body.innerHTML = '<main><div class="empty-state">No report id given. <a href="reports.html">Back to reports</a></div></main>';
    return;
  }
  try {
    report = await Api.getReportSummary(analysisId);
  } catch (e) {
    document.body.innerHTML = `<main><div class="empty-state error-text">Failed to load report: ${escapeHtml(e.message)}</div></main>`;
    return;
  }
  renderHeader();
  renderVerdict();
  renderScreenView();
  renderSummaryCards();
  renderEventChart();
  // The chart lives inside a collapsed <details>: it renders at 0 size until
  // first expanded, so re-render on first open (renderEventChart destroys
  // and recreates the chart, safe to call repeatedly).
  const auxChartPanel = document.getElementById("aux-event-counts");
  if (auxChartPanel) {
    auxChartPanel.addEventListener("toggle", () => {
      if (auxChartPanel.open) renderEventChart();
    });
  }
  renderDetections();
  renderAlerts();
  renderMitreCoverage();
  wireMitreEvents();
  renderProcessTree();
  renderStaticAnalysis();
  renderExecution();
  renderProcessDumps();
  renderDroppedFiles();
  renderIocSummary();
  renderHooks();
  wireHooks();
  // Server-curated hookset for the API-trace inventory; re-render once it
  // arrives (fallback = the embedded HOOKSET constant on failure).
  Api.getHookset()
    .then((h) => { hooksetData = h; renderHooks(); renderBlindspotCoverage(); })
    .catch(() => {});
  wireTelemetryTabs();
  // Not awaited: a slow/large capture must never block the rest of the page
  // (alerts, process tree, etc. are already rendered by the time this resolves).
  NetworkView.render(report, analysisId);
  ScreenshotView.render(report, analysisId);
  wireEventsBrowser();
  wireEnvironmentAlerts();
  wireAlertExpansion();
  wireSampleAlertsPager();
  wireAlertsToolbar();
  wireTreeExpandCollapse();
  wireTreeInterestingFilter();
  // Built last: reads the counts the render* calls above just populated,
  // and its empty-section auto-collapse must run after those set defaults.
  buildSectionNav();
}

main();
