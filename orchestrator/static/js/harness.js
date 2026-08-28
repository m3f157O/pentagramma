// Injection-harness coverage page. Techniques are rendered DYNAMICALLY from
// the validation payload (orchestrator/harness_validation.py TECHNIQUE_SPECS)
// -- adding a technique server-side requires no UI change. Per-technique
// shape differs by spec kind:
//   behavioral specs: { pid, expected_alert, matched_events, status }
//   event specs:      { pid, expected_event_id, expected_type_fragments,
//                       pid_field, matched_events, status }
const TECHNIQUE_LABELS = {
  hollowing: "Process hollowing",
  pe_replacement: "PE replacement",
  herpaderping: "Herpaderping",
  ghosting: "Ghosting",
  atombombing: "AtomBombing",
  module_overloading: "Module overloading",
  setwindowshookex: "SetWindowsHookEx",
  apc_ex: "APC-Ex injection",
  mapview: "MapView injection",
};

let activeJobId = null;

function techniqueLabel(name) {
  return TECHNIQUE_LABELS[name] || name;
}

function statusBadgeClass(status) {
  if (status === "PASS") return "pass";
  if (status === "FAIL") return "fail";
  return "missing_pid";
}

function expectedSignal(t) {
  if (t.expected_alert) return escapeHtml(t.expected_alert);
  const eid = t.expected_event_id != null ? `EID ${t.expected_event_id}` : "?";
  const frags = Array.isArray(t.expected_type_fragments) && t.expected_type_fragments.length
    ? ` / "${escapeHtml(t.expected_type_fragments.join('", "'))}"`
    : "";
  const pidField = t.pid_field ? ` · ${escapeHtml(t.pid_field)}` : "";
  return `${eid}${frags}${pidField}`;
}

function renderLatest(report, validation) {
  const el = document.getElementById("latest-body");
  const rows = Object.entries(validation.techniques)
    .map(([name, t]) => {
      return `<tr>
        <td>${escapeHtml(techniqueLabel(name))}</td>
        <td><span class="badge ${statusBadgeClass(t.status)}">${escapeHtml(t.status)}</span></td>
        <td class="mono small">${t.pid ?? "-"}</td>
        <td class="small">${expectedSignal(t)} — matched ${t.matched_events ?? 0}</td>
        <td class="small error-text">${escapeHtml(t.error || "")}</td>
      </tr>`;
    })
    .join("");

  el.innerHTML = `
    <div class="small muted" style="margin-bottom:8px">
      Run ${fmtDate(report.timestamp)} · <a href="report.html?id=${encodeURIComponent(report.analysis_id)}">view report →</a>
      · <span class="badge ok">${validation.summary.passed} passed</span>
      <span class="badge bad">${validation.summary.failed} failed</span>
    </div>
    <table>
      <thead><tr><th>Technique</th><th>Status</th><th>PID</th><th>Expected signal</th><th>Error</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function renderTrend(rows) {
  const headEl = document.getElementById("trend-head");
  const el = document.getElementById("trend-body");
  if (!rows.length) {
    headEl.innerHTML = "";
    el.innerHTML = `<tr><td class="empty-state">No injection-harness runs yet.</td></tr>`;
    return;
  }
  // Columns = union of techniques across the shown runs, in the order the
  // server reports them (TECHNIQUE_SPECS order).
  const techniques = [];
  rows.forEach(({ validation }) => {
    Object.keys(validation.techniques).forEach((name) => {
      if (!techniques.includes(name)) techniques.push(name);
    });
  });
  headEl.innerHTML = `<tr><th>Time</th>${techniques.map((n) => `<th>${escapeHtml(techniqueLabel(n))}</th>`).join("")}<th>Passed</th></tr>`;
  el.innerHTML = rows
    .map(({ report, validation }) => {
      const cells = techniques
        .map((name) => {
          const t = validation.techniques[name];
          return t
            ? `<td><span class="badge ${statusBadgeClass(t.status)}">${escapeHtml(t.status)}</span></td>`
            : `<td class="muted small">n/a</td>`;
        })
        .join("");
      return `<tr>
        <td class="small"><a href="report.html?id=${encodeURIComponent(report.analysis_id)}">${fmtDate(report.timestamp)}</a></td>
        ${cells}
        <td>${validation.summary.passed}/${Object.keys(validation.techniques).length}</td>
      </tr>`;
    })
    .join("");
}

function setRunStatus(msg, isError) {
  const el = document.getElementById("run-status");
  el.textContent = msg;
  el.className = "small " + (isError ? "error-text" : "muted");
}

async function loadCoverage() {
  document.getElementById("latest-body").innerHTML = `<div class="muted small">Loading…</div>`;
  document.getElementById("trend-body").innerHTML = `<tr><td class="empty-state">Loading…</td></tr>`;

  const data = await Api.listReports(200);
  const harnessReports = data.reports
    .filter((r) => r.is_injection_harness)
    .sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1))
    .slice(0, 10);

  if (!harnessReports.length) {
    document.getElementById("latest-body").innerHTML = `<div class="empty-state">No injection-harness runs found. Filenames must exactly match "InjectionHarness.exe".</div>`;
    document.getElementById("trend-body").innerHTML = `<tr><td class="empty-state">No injection-harness runs yet.</td></tr>`;
    return;
  }

  const withValidation = await Promise.all(
    harnessReports.map(async (report) => ({
      report,
      validation: await Api.harnessValidation(report.analysis_id),
    }))
  );

  renderLatest(withValidation[0].report, withValidation[0].validation);
  renderTrend(withValidation);
}

async function refreshActiveJob() {
  const data = await Api.listJobs();
  const btn = document.getElementById("btn-run-harness");
  if (data.active_job_id) {
    activeJobId = data.active_job_id;
    const job = await Api.getJob(activeJobId);
    btn.disabled = true;
    if (job.job_type === "harness") {
      setRunStatus(`Running (${job.status})…`);
    } else {
      setRunStatus("A different job is currently running.");
    }
    if (job.status === "completed" || job.status === "failed") {
      activeJobId = null;
      btn.disabled = false;
      setRunStatus(job.status === "completed" ? "Last run completed." : `Last run failed: ${job.error || ""}`, job.status === "failed");
      await loadCoverage();
    }
  } else {
    if (activeJobId) {
      // just finished since our last poll
      activeJobId = null;
      await loadCoverage();
    }
    btn.disabled = false;
  }
}

document.getElementById("btn-run-harness").addEventListener("click", async () => {
  const btn = document.getElementById("btn-run-harness");
  btn.disabled = true;
  setRunStatus("Submitting (rebuilds InjectionHarness.exe, requires .NET SDK)…");
  try {
    const job = await Api.runHarness();
    activeJobId = job.job_id;
    setRunStatus(`Job ${job.job_id} queued.`);
  } catch (err) {
    btn.disabled = false;
    if (err.status === 409) {
      setRunStatus("A job is already running — try again once it finishes.", true);
    } else {
      setRunStatus("Failed to start: " + err.message, true);
    }
  }
});

loadCoverage();
startPoll(refreshActiveJob, 3000);
