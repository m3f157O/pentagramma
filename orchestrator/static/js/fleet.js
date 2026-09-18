// Fleet page: inventory of analysis environments (local host + all Hyper-V
// VMs) polled from /api/fleet, with a per-environment Manage MODAL
// (credentials + last instrumentation status + in-place provisioning).

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function setHealthBadge(ok) {
  const el = document.getElementById("health-badge");
  if (!el) return;
  el.textContent = ok ? "online" : "unreachable";
  el.className = "badge " + (ok ? "ok" : "bad");
}

function setModeBadge(mode) {
  const el = document.getElementById("mode-badge");
  if (!el) return;
  if (!mode) { el.style.display = "none"; return; }
  el.style.display = "";
  if (mode === "local") {
    el.textContent = "LOCAL — malware runs on THIS machine";
    el.className = "badge bad";
  } else {
    el.textContent = "hyperv — isolated VM";
    el.className = "badge ok";
  }
}

const CHECK_LABELS = {
  sysmon: "Sysmon",
  agent_dir: "agent dir",
  monitor_dlls: "monitor DLLs",
  guardian_driver: "Guardian",
  secure_boot: "Secure Boot",
};

function renderChecksMini(checks, type) {
  if (!checks) return "";
  const chips = Object.entries(CHECK_LABELS)
    .map(([key, label]) => {
      const ok = checks[key] === true;
      const cls = ok ? "ok" : key === "guardian_driver" ? "neutral" : "bad";
      return `<span class="badge ${cls}" title="${escapeHtml(label)}">${escapeHtml(label)}</span>`;
    })
    .join(" ");
  // defender_rtp is guest-relevant and inverted (must be OFF on a detonation VM).
  const rtp = type === "hyperv" && checks.defender_rtp !== undefined
    ? ` <span class="badge ${checks.defender_rtp === false ? "ok" : "bad"}" title="Defender realtime protection (must be off)">RTP ${checks.defender_rtp === false ? "off" : "ON"}</span>`
    : "";
  return `<div style="margin-top:6px">${chips}${rtp}</div>`;
}

function formatAge(seconds) {
  if (seconds == null) return "?";
  if (seconds < 90) return `${Math.round(seconds)}s ago`;
  return `${Math.round(seconds / 60)}min ago`;
}

// ---------------------------------------------------------------- cards ---

function renderEntry(e) {
  const stateBadge = e.state === "Running" ? "ok" : e.state === "Off" ? "neutral" : "bad";
  const activeBadge = e.active ? ' <span class="badge ok">active backend</span>' : "";
  const typeBadge = e.type === "local"
    ? '<span class="badge neutral">local host</span>'
    : '<span class="badge neutral">Hyper-V VM</span>';
  // Credential presence (never values). Local host needs no guest creds.
  const credsBadge = e.type === "hyperv"
    ? (e.managed
        ? (e.credentials_configured
            ? '<span class="badge ok" title="Credentials registered">creds configured</span>'
            : '<span class="badge bad" title="Registry entry lacks username/password">creds missing</span>')
        : '<span class="badge neutral" title="Not in the credential registry — inventory only, no guest probes">not registered</span>')
    : "";
  const sys = e.system
    ? `<div class="small muted" style="margin-top:4px">${escapeHtml(e.system.Hostname || "")}${e.system.OS ? " · " + escapeHtml(e.system.OS) : ""}${e.system.Build ? " (build " + escapeHtml(String(e.system.Build)) + ")" : ""}</div>`
    : "";
  const meta = [e.ip ? `<span class="mono">${escapeHtml(e.ip)}</span>` : "", e.uptime ? `uptime ${escapeHtml(e.uptime)}` : ""]
    .filter(Boolean).join(" · ");
  const err = e.error
    ? `<div class="error-text small" style="margin-top:4px">${escapeHtml(e.error)}</div>`
    : e.checks_error
      ? `<div class="small muted" style="margin-top:4px">checks: ${escapeHtml(e.checks_error)}</div>`
      : "";
  const checks = renderChecksMini(e.checks, e.type);
  return `
    <div class="card">
      <div class="card-title" style="display:flex; justify-content:space-between; align-items:center">
        <span>${escapeHtml(e.name)}${activeBadge}</span>
        <button class="secondary btn-manage" data-name="${escapeHtml(e.name)}" title="Manage ${escapeHtml(e.name)}" style="padding:0 8px; font-size:15px; line-height:1.6">&#9881;</button>
      </div>
      <div class="card-sub">${typeBadge} <span class="badge ${stateBadge}">${escapeHtml(e.state || "unknown")}</span> ${credsBadge}${meta ? " " + meta : ""}</div>
      ${sys}
      ${checks}
      ${err}
    </div>`;
}

// ---------------------------------------------------------------- modal ---

const PROVISION_STEPS = [
  ["agent", "Deploy agent", "copy agent files to C:\\SandboxAgent"],
  ["sysmon", "Install Sysmon", "install/reconfigure Sysmon from the bundled Sysmon64 + sysmonconfig.xml"],
  ["defender-off", "Defender off", "disable Defender realtime protection (samples must run)"],
  ["dressing", "Apply dressing", "documents, browser history, recent-run artifacts (anti-sandbox)"],
  ["noise-reduction", "Noise reduction", "disable updater/telemetry/CEIP/indexer tasks and services"],
];

let modalName = null;

function ensureModal() {
  let overlay = document.getElementById("fleet-modal-overlay");
  if (overlay) return overlay;
  overlay = document.createElement("div");
  overlay.id = "fleet-modal-overlay";
  overlay.style.cssText = "position:fixed; inset:0; background:rgba(0,0,0,.65); z-index:1000; display:none; align-items:center; justify-content:center";
  overlay.innerHTML = `
    <div class="card" style="min-width:480px; max-width:640px; max-height:85vh; overflow-y:auto">
      <div class="card-title" style="display:flex; justify-content:space-between; align-items:center">
        <span id="fleet-modal-title"></span>
        <button class="secondary" id="fleet-modal-close" style="padding:0 8px">✕</button>
      </div>
      <div id="fleet-modal-body" style="margin-top:8px"></div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener("click", (ev) => { if (ev.target === overlay) closeModal(); });
  overlay.querySelector("#fleet-modal-close").addEventListener("click", closeModal);
  return overlay;
}

function closeModal() {
  modalName = null;
  const overlay = document.getElementById("fleet-modal-overlay");
  if (overlay) overlay.style.display = "none";
}

function renderModalBody(name, d) {
  const cred = d.credentials || {};
  const credRow = cred.required === false
    ? `<div class="small"><span class="badge neutral">credentials</span> not required — ${escapeHtml(cred.note || "")}</div>`
    : `<div class="small"><span class="badge ${cred.configured ? "ok" : "bad"}">credentials</span> ${cred.configured ? `configured (user: <span class="mono">${escapeHtml(cred.username || "")}</span>, password set)` : "not configured"}</div>`;
  const credForm = cred.required === false ? "" : `
    <div style="margin-top:6px" class="small">
      <input type="text" id="cred-user" placeholder="username" style="width:140px" value="${escapeHtml(cred.username || "")}" />
      <input type="password" id="cred-pass" placeholder="password" style="width:140px" />
      <button class="secondary" id="cred-save">Save credentials</button>
      ${cred.configured ? '<button class="secondary" id="cred-delete">Remove</button>' : ""}
      <span id="cred-status" class="small muted"></span>
    </div>`;

  const h = d.last_health;
  let healthRows = '<div class="small muted">never probed (probes run when the fleet poll sees the VM running)</div>';
  if (h && h.data) {
    const checks = h.data.Checks ? renderChecksMini(h.data.Checks, d.type) : "";
    const err = h.data.ChecksError ? `<div class="small muted">probe error: ${escapeHtml(h.data.ChecksError)}</div>` : "";
    healthRows = `<div class="small muted">last recorded ${formatAge(h.age_seconds)}${h.state_at_probe && h.state_at_probe !== "Running" ? ` (VM was ${escapeHtml(h.state_at_probe)})` : ""}</div>${checks}${err}`;
  }

  const provRows = PROVISION_STEPS.map(([step, label, hint]) => `
    <div class="small" style="margin-top:4px">
      <button class="secondary btn-provision" data-step="${step}" style="min-width:150px">${label}</button>
      <span class="muted"> ${hint}</span>
      <span class="prov-status" data-step="${step}"></span>
    </div>`).join("");

  return `
    <div class="section" style="padding:8px 0; border-bottom:1px solid #333">${credRow}${credForm}</div>
    <div class="section" style="padding:8px 0; border-bottom:1px solid #333">
      <div class="small" style="font-weight:600">Instrumentation status</div>
      ${healthRows}
    </div>
    <div class="section" style="padding:8px 0">
      <div class="small" style="font-weight:600">Instrument this machine <span class="muted">(in-place, no snapshots)</span></div>
      ${provRows}
      <div class="small muted" style="margin-top:6px">Guardian driver stays manual (testsigning + reboot dance). Steps run with the orchestrator's privileges${d.type === "hyperv" ? " inside the guest via PSDirect" : " locally"}.</div>
    </div>`;
}

async function refreshModalContent() {
  if (!modalName) return;
  const body = document.getElementById("fleet-modal-body");
  if (!body) return;
  // Don't clobber the modal while the operator is typing in it.
  const passInput = body.querySelector("#cred-pass");
  if (body.contains(document.activeElement) || (passInput && passInput.value)) return;
  try {
    const d = await Api.fleetDetail(modalName);
    body.innerHTML = renderModalBody(modalName, d);
    wireModal(modalName, body);
  } catch (e) {
    body.innerHTML = `<div class="error-text small">${escapeHtml(e.message)}</div>`;
  }
}

function wireModal(name, body) {
  const status = body.querySelector("#cred-status");
  const save = body.querySelector("#cred-save");
  const del = body.querySelector("#cred-delete");
  if (save) {
    save.addEventListener("click", async () => {
      const username = body.querySelector("#cred-user").value.trim();
      const password = body.querySelector("#cred-pass").value;
      if (!username || !password) {
        if (status) status.textContent = "username and password required";
        return;
      }
      try {
        await Api.setFleetCreds(name, username, password);
        if (status) status.textContent = "saved";
        refreshFleet();
      } catch (e) {
        if (status) status.textContent = "save failed: " + e.message;
      }
    });
  }
  if (del) {
    del.addEventListener("click", async () => {
      if (!confirm(`Remove stored credentials for ${name}?`)) return;
      try {
        await Api.deleteFleetCreds(name);
        if (status) status.textContent = "removed";
        refreshFleet();
      } catch (e) {
        if (status) status.textContent = "remove failed: " + e.message;
      }
    });
  }
  body.querySelectorAll(".btn-provision").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const step = btn.getAttribute("data-step");
      const stEl = body.querySelector(`.prov-status[data-step="${step}"]`);
      const warn = (name === "local")
        ? `Run '${step}' on the LOCAL HOST (this machine)?`
        : `Run '${step}' inside VM '${name}'? In-place, no snapshot.`;
      if (!confirm(warn)) return;
      btn.disabled = true;
      if (stEl) stEl.textContent = " running…";
      try {
        const r = await Api.provisionFleet(name, step);
        if (stEl) stEl.textContent = r.status === "ok" ? " ✓ done" : ` ✗ ${r.error || "failed"}`;
      } catch (e) {
        if (stEl) stEl.textContent = " ✗ " + e.message;
      } finally {
        btn.disabled = false;
        refreshFleet();
      }
    });
  });
}

async function onManage(ev) {
  const name = ev.currentTarget.getAttribute("data-name");
  const overlay = ensureModal();
  modalName = name;
  document.getElementById("fleet-modal-title").textContent = name;
  document.getElementById("fleet-modal-body").innerHTML = '<div class="small muted">Loading…</div>';
  overlay.style.display = "flex";
  try {
    const d = await Api.fleetDetail(name);
    const body = document.getElementById("fleet-modal-body");
    body.innerHTML = renderModalBody(name, d);
    wireModal(name, body);
  } catch (e) {
    document.getElementById("fleet-modal-body").innerHTML = `<div class="error-text small">${escapeHtml(e.message)}</div>`;
  }
}

// ----------------------------------------------------------------- poll ---

async function refreshFleet() {
  const el = document.getElementById("fleet-cards");
  try {
    const data = await Api.fleet();
    setModeBadge(data.mode);
    setHealthBadge(true);
    el.innerHTML = (data.entries || []).map(renderEntry).join("") ||
      '<div class="muted small">No environments registered.</div>';
    el.querySelectorAll(".btn-manage").forEach((b) => b.addEventListener("click", onManage));
    await refreshModalContent();
  } catch (e) {
    setHealthBadge(false);
    el.innerHTML = `<div class="error-text small">Fleet unavailable: ${escapeHtml(e.message)}</div>`;
  }
}

refreshFleet();
startPoll(refreshFleet, 10000);
