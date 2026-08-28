const STEP_LABELS = {
  started: "Started",
  ensure_snapshot: "Ensure clean snapshot",
  restore_snapshot: "Restore snapshot",
  start_vm: "Start VM",
  copy_agent: "Copy telemetry agent",
  telemetry_init: "Initialize telemetry",
  copy_sample: "Copy sample into VM",
  network_capture_start: "Start network capture",
  execute_sample: "Execute sample",
  telemetry_collect: "Collect telemetry",
  network_capture_stop: "Stop network capture",
  stop_vm: "Stop VM",
};

const state = { activeJobId: null };

function setHealthBadge(ok) {
  const el = document.getElementById("health-badge");
  el.textContent = ok ? "online" : "unreachable";
  el.className = "badge " + (ok ? "ok" : "bad");
}

function renderVmStatus(status, err) {
  const el = document.getElementById("vm-card-body");
  if (err) {
    el.innerHTML = `<div class="error-text small">Unable to reach VM status: ${escapeHtml(err.message)}</div>`;
    return;
  }
  if (!status) {
    el.innerHTML = `<div class="muted small">Paused while a job is running (it owns the VM).</div>`;
    return;
  }
  const stateBadge = status.State === "Running" ? "ok" : "neutral";
  el.innerHTML = `
    <div class="card-value">${escapeHtml(status.VMName || "-")}</div>
    <div class="card-sub">
      <span class="badge ${stateBadge}">${escapeHtml(status.State || "unknown")}</span>
      ${status.IPAddress ? `<span class="mono">${escapeHtml(status.IPAddress)}</span>` : ""}
      ${status.Uptime ? `<span> · uptime ${escapeHtml(status.Uptime)}</span>` : ""}
    </div>`;
}

function renderJobPanel(job) {
  const el = document.getElementById("job-card-body");

  if (!job) {
    el.innerHTML = `<div class="muted small">No analysis currently running.</div>`;
    return;
  }

  const stepNames = (job.step_history || []).map((s) => s.step);
  const isTerminal = job.status === "completed" || job.status === "failed";
  const stepsHtml = stepNames
    .map((name, i) => {
      const isCurrent = !isTerminal && i === stepNames.length - 1;
      const cls = isCurrent ? "current" : "done";
      return `<li class="${cls}">${escapeHtml(STEP_LABELS[name] || name)}</li>`;
    })
    .join("");

  let statusBadgeClass = "warn";
  if (job.status === "completed") statusBadgeClass = job.report_status === "failed" ? "warn" : "ok";
  if (job.status === "failed") statusBadgeClass = "bad";

  let footer = "";
  if (job.status === "completed" && job.analysis_id) {
    footer = `<div class="small" style="margin-top:8px"><a href="report.html?id=${encodeURIComponent(job.analysis_id)}">View report →</a></div>`;
  } else if (job.error) {
    footer = `<div class="error-text small" style="margin-top:8px">${escapeHtml(job.error)}</div>`;
  }

  el.innerHTML = `
    <div class="card-sub" style="margin-bottom:6px">
      <span class="mono">${escapeHtml(job.sample_filename || "")}</span>
      <span class="badge ${statusBadgeClass}">${escapeHtml(job.status)}</span>
    </div>
    <ul class="steps">${stepsHtml}</ul>
    ${footer}
  `;
}

function renderQueueList(jobs) {
  const cardEl = document.getElementById("queue-card");
  const bodyEl = document.getElementById("queue-card-body");
  const pending = (jobs || [])
    .filter((j) => j.status === "queued" && j.queue_position)
    .sort((a, b) => a.queue_position - b.queue_position);

  if (!pending.length) {
    cardEl.style.display = "none";
    bodyEl.innerHTML = "";
    return;
  }

  cardEl.style.display = "";
  bodyEl.innerHTML = `
    <ul class="steps">
      ${pending
        .map((j) => `<li>#${j.queue_position} <span class="mono">${escapeHtml(j.sample_filename || "")}</span></li>`)
        .join("")}
    </ul>
  `;
}

function verdictBadgeHtml(r) {
  if (!r.verdict_level) return `<span class="muted small">-</span>`;
  const cls = r.verdict_level === "malicious" ? "bad" : r.verdict_level === "suspicious" ? "warn" : "ok";
  const score = r.verdict_score != null ? ` <span class="small muted">${r.verdict_score}</span>` : "";
  return `<span class="badge ${cls}">${escapeHtml(r.verdict_level)}</span>${score}`;
}

function renderRecentReports(reports) {
  const tbody = document.getElementById("recent-reports-body");
  if (!reports.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No analyses yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = reports
    .map(
      (r) => `
    <tr>
      <td>${fmtDate(r.timestamp)}</td>
      <td class="mono"><a href="report.html?id=${encodeURIComponent(r.analysis_id)}">${escapeHtml(r.filename)}</a>${r.is_injection_harness ? ' <span class="badge neutral">harness</span>' : ""}</td>
      <td><span class="badge ${r.status === "completed" ? "ok" : "bad"}">${escapeHtml(r.status)}</span></td>
      <td>${verdictBadgeHtml(r)}</td>
      <td>${r.alert_count}</td>
      <td>${r.eid25_count}</td>
      <td>${fmtDuration(r.runtime_seconds)}</td>
    </tr>`
    )
    .join("");
}

async function refreshHealth() {
  try {
    await Api.health();
    setHealthBadge(true);
  } catch (e) {
    setHealthBadge(false);
  }
}

async function refreshVm() {
  if (state.activeJobId) {
    renderVmStatus(null, null);
    return;
  }
  try {
    const status = await Api.vmStatus();
    renderVmStatus(status);
  } catch (e) {
    renderVmStatus(null, e);
  }
}

async function refreshRecentReports() {
  try {
    const data = await Api.listReports(10);
    renderRecentReports(data.reports);
  } catch (e) {
    console.error(e);
  }
}

async function refreshJobsList() {
  const data = await Api.listJobs();
  const wasActive = state.activeJobId;
  state.activeJobId = data.active_job_id;

  renderQueueList(data.jobs);

  if (state.activeJobId) {
    const job = await Api.getJob(state.activeJobId);
    renderJobPanel(job);
  } else {
    renderJobPanel(null);
  }

  if (wasActive && !state.activeJobId) {
    await refreshRecentReports();
  }
}

async function refreshActiveJobDetail() {
  if (!state.activeJobId) return;
  try {
    const job = await Api.getJob(state.activeJobId);
    renderJobPanel(job);
  } catch (e) {
    console.error(e);
  }
}

function setSubmitStatus(msg, isError) {
  const el = document.getElementById("submit-status");
  el.textContent = msg;
  el.className = "small " + (isError ? "error-text" : "muted");
}

// DLL/ZIP extra fields only matter for file submissions of that type --
// guessed from the chosen filename's extension unless the user explicitly
// overrides sample-type, so the common EXE case never shows them.
const EXTENSION_TO_GUESSED_TYPE = { dll: "dll", zip: "zip" };

function isUrlMode() {
  return document.getElementById("mode-url").checked;
}

function guessedSampleType() {
  const override = document.getElementById("sample-type").value;
  if (override) return override;
  const files = document.getElementById("sample-file").files;
  if (!files.length) return "";
  const ext = files[0].name.split(".").pop().toLowerCase();
  return EXTENSION_TO_GUESSED_TYPE[ext] || "";
}

function updateSubmitVisibility() {
  const urlMode = isUrlMode();
  document.getElementById("sample-file").classList.toggle("hidden", urlMode);
  document.getElementById("submit-url").classList.toggle("hidden", !urlMode);
  document.getElementById("url-mode").classList.toggle("hidden", !urlMode);

  const guessed = urlMode ? "" : guessedSampleType();
  document.getElementById("dll-entry-point").classList.toggle("hidden", guessed !== "dll");
  document.getElementById("archive-entry").classList.toggle("hidden", guessed !== "zip");
  document.getElementById("archive-password").classList.toggle("hidden", guessed !== "zip");
}

function wireSubmitForm() {
  const form = document.getElementById("submit-form");

  document.getElementById("mode-file").addEventListener("change", updateSubmitVisibility);
  document.getElementById("mode-url").addEventListener("change", updateSubmitVisibility);
  document.getElementById("sample-type").addEventListener("change", updateSubmitVisibility);
  document.getElementById("sample-file").addEventListener("change", updateSubmitVisibility);
  updateSubmitVisibility();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData();
    const urlMode = isUrlMode();

    if (urlMode) {
      const url = document.getElementById("submit-url").value.trim();
      if (!url) {
        setSubmitStatus("Enter a URL first.", true);
        return;
      }
      fd.append("url", url);
      fd.append("url_mode", document.getElementById("url-mode").value);
    } else {
      const fileInput = document.getElementById("sample-file");
      if (!fileInput.files.length) {
        setSubmitStatus("Choose a file first.", true);
        return;
      }
      fd.append("file", fileInput.files[0]);
    }

    const sampleType = document.getElementById("sample-type").value;
    if (sampleType) fd.append("sample_type", sampleType);
    const dllEntryPoint = document.getElementById("dll-entry-point").value.trim();
    if (dllEntryPoint) fd.append("dll_entry_point", dllEntryPoint);
    const archiveEntry = document.getElementById("archive-entry").value.trim();
    if (archiveEntry) fd.append("archive_entry", archiveEntry);
    const archivePassword = document.getElementById("archive-password").value.trim();
    if (archivePassword) fd.append("archive_password", archivePassword);

    fd.append("arguments", document.getElementById("arguments").value || "");
    const timeoutVal = document.getElementById("timeout").value;
    if (timeoutVal) fd.append("timeout", timeoutVal);

    setSubmitStatus("Submitting...");
    try {
      const job = await Api.submitJob(fd);
      // There is exactly one VM: a submission either starts right away
      // (status "running") or is queued behind whatever's active. Only
      // adopt it as "the" active job in the panel if it actually started --
      // otherwise the next poll's queue list is where it'll show up.
      if (job.status === "running") {
        state.activeJobId = job.job_id;
        setSubmitStatus(`Job ${job.job_id} started.`);
        renderJobPanel(job);
      } else {
        setSubmitStatus(`Job ${job.job_id} queued (position ${job.queue_position}).`);
      }
      form.reset();
      updateSubmitVisibility();
      await refreshJobsList();
    } catch (err) {
      setSubmitStatus("Submit failed: " + err.message, true);
    }
  });
}

function setVmActionStatus(msg, isError) {
  const el = document.getElementById("vm-action-status");
  if (!el) return;
  el.textContent = msg;
  el.className = "small " + (isError ? "error-text" : "muted");
}

function wireVmButtons() {
  document.getElementById("btn-ensure-snapshot").addEventListener("click", async () => {
    setVmActionStatus("Ensuring snapshot…");
    try {
      const r = await Api.ensureSnapshot();
      setVmActionStatus("Snapshot: " + (r.status || JSON.stringify(r)));
    } catch (e) {
      setVmActionStatus("Failed: " + e.message, true);
    }
  });
  document.getElementById("btn-restore-snapshot").addEventListener("click", async () => {
    if (!confirm("Revert the VM to its clean snapshot now?")) return;
    setVmActionStatus("Restoring snapshot…");
    try {
      await Api.restoreSnapshot();
      setVmActionStatus("Snapshot restored.");
      refreshVm();
    } catch (e) {
      setVmActionStatus("Failed: " + e.message, true);
    }
  });
}

wireSubmitForm();
wireVmButtons();
refreshRecentReports();

startPoll(refreshHealth, 10000);
startPoll(refreshVm, 5000);
startPoll(refreshJobsList, 5000);
startPoll(refreshActiveJobDetail, 2000);
