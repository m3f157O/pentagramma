// Thin fetch() wrappers, one per orchestrator endpoint. Same-origin, no CORS needed.

async function apiRequest(path, options = {}) {
  const res = await fetch(path, options);
  let body = null;
  try {
    body = await res.json();
  } catch (e) {
    body = null;
  }
  if (!res.ok) {
    const detail = body && body.detail ? body.detail : `${res.status} ${res.statusText}`;
    const message = typeof detail === "string" ? detail : JSON.stringify(detail);
    const err = new Error(message);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

const Api = {
  health: () => apiRequest("/api/health"),
  vmStatus: () => apiRequest("/api/vm/status"),
  ensureSnapshot: () => apiRequest("/api/vm/snapshot", { method: "POST" }),
  restoreSnapshot: () => apiRequest("/api/vm/restore", { method: "POST" }),

  submitJob: (formData) => apiRequest("/api/jobs", { method: "POST", body: formData }),
  listJobs: () => apiRequest("/api/jobs"),
  getJob: (jobId) => apiRequest(`/api/jobs/${encodeURIComponent(jobId)}`),

  getRules: () => apiRequest("/api/rules"),
  getRulesSummary: () => apiRequest("/api/rules/summary"),
  getSigmaRuleRaw: (id) => apiRequest(`/api/rules/sigma/${encodeURIComponent(id)}/raw`),
  getYaraRuleRaw: (name) => apiRequest(`/api/rules/yara/${encodeURIComponent(name)}/raw`),
  getCapeRuleRaw: (name) => apiRequest(`/api/rules/cape/${encodeURIComponent(name)}/raw`),
  getHookset: () => apiRequest("/api/hookset"),

  // Local live trace (host-side MinHook monitor, no VM)
  localTraceStart: (target, args) => apiRequest("/api/local-trace/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, arguments: args }),
  }),
  localTraceStop: () => apiRequest("/api/local-trace/stop", { method: "POST" }),
  localTraceStatus: () => apiRequest("/api/local-trace/status"),
  localTraceEvents: (offset = 0, q = "") => {
    const params = new URLSearchParams({ offset, limit: 1000 });
    if (q) params.set("q", q);
    return apiRequest(`/api/local-trace/events?${params.toString()}`);
  },
  localTraceHistory: () => apiRequest("/api/local-trace/history"),
  localTraceHistoryEvents: (id, offset = 0, q = "") => {
    const params = new URLSearchParams({ offset, limit: 500 });
    if (q) params.set("q", q);
    return apiRequest(`/api/local-trace/history/${encodeURIComponent(id)}/events?${params.toString()}`);
  },

  listReports: (limit = 100, sinceHours = 0) => {
    const params = new URLSearchParams({ limit });
    if (sinceHours > 0) params.set("since_hours", sinceHours);
    return apiRequest(`/api/reports/list?${params.toString()}`);
  },
  getReportSummary: (id) => apiRequest(`/api/reports/${encodeURIComponent(id)}/summary`),
  getReportEvents: (id, { offset = 0, limit = 200, eventType = "", q = "", source = "" } = {}) => {
    const params = new URLSearchParams({ offset, limit });
    if (eventType) params.set("event_type", eventType);
    if (q) params.set("q", q);
    if (source) params.set("source", source);
    return apiRequest(`/api/reports/${encodeURIComponent(id)}/events?${params.toString()}`);
  },
  getReportAlerts: (id, { offset = 0, limit = 200, scope = "", eventType = "", q = "" } = {}) => {
    const params = new URLSearchParams({ offset, limit });
    if (scope) params.set("scope", scope);
    if (eventType) params.set("event_type", eventType);
    if (q) params.set("q", q);
    return apiRequest(`/api/reports/${encodeURIComponent(id)}/alerts?${params.toString()}`);
  },
  reportJsonUrl: (id) => `/api/reports/${encodeURIComponent(id)}`,

  harnessValidation: (id) => apiRequest(`/api/reports/${encodeURIComponent(id)}/harness-validation`),
  runHarness: () => apiRequest("/api/harness/run", { method: "POST" }),

  getNetworkSummary: (id) => apiRequest(`/api/reports/${encodeURIComponent(id)}/network-summary`),
  getNetworkPacket: (id, index) => apiRequest(`/api/reports/${encodeURIComponent(id)}/network-packets/${encodeURIComponent(index)}`),
  getNetworkPackets: (id, { offset = 0, limit = 100, protocol = "", ip = "", port = "", q = "" } = {}) => {
    const params = new URLSearchParams({ offset, limit });
    if (protocol) params.set("protocol", protocol);
    if (ip) params.set("ip", ip);
    if (port) params.set("port", port);
    if (q) params.set("q", q);
    return apiRequest(`/api/reports/${encodeURIComponent(id)}/network-packets?${params.toString()}`);
  },

  getScreenshots: (id) => apiRequest(`/api/reports/${encodeURIComponent(id)}/screenshots`),
  screenshotUrl: (id, index) => `/api/reports/${encodeURIComponent(id)}/screenshots/${index}`,

  getProcessDumps: (id) => apiRequest(`/api/reports/${encodeURIComponent(id)}/process-dumps`),
  processDumpDownloadUrl: (id, index) => `/api/reports/${encodeURIComponent(id)}/process-dumps/${index}/download`,

  getDroppedFiles: (id) => apiRequest(`/api/reports/${encodeURIComponent(id)}/dropped-files`),
  droppedFileDownloadUrl: (id, index) => `/api/reports/${encodeURIComponent(id)}/dropped-files/${index}/download`,
};

function fmtBytes(n) {
  if (n == null) return "-";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

function fmtDate(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString();
  } catch (e) {
    return iso;
  }
}

function fmtDuration(seconds) {
  if (seconds == null) return "-";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
