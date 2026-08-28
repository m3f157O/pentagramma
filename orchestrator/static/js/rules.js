// Top-level Rules browser: the full detection-rule catalog (Sigma + YARA +
// heuristics + static signals) exposed by GET /api/rules.

let catalog = null;

const SIGMA_PAGE = 150; // rows rendered per "show more" click (2000 rows at once is sluggish)
let sigmaFiltered = [];
let sigmaShown = 0;

function levelBadgeClass(level) {
  if (level === "critical" || level === "high") return "bad";
  if (level === "medium") return "warn";
  if (level === "low") return "neutral";
  return "neutral";
}

function attackChips(tags) {
  return (tags || [])
    .map((t) => String(t))
    .filter((t) => /^attack\.t\d{4}/i.test(t))
    .map((t) => `<span class="mitre-chip">${escapeHtml(t.split(".")[1].toUpperCase())}</span>`)
    .join(" ");
}

// --- family tab selector (one family shown at a time, mirrors the report page) ---
function selectFamily(target) {
  document.querySelectorAll("main > details.section").forEach((section) => {
    const show = section.id === target;
    section.classList.toggle("tab-hidden", !show);
    if (show) section.open = true;
  });
  document.querySelectorAll("#rules-nav .nav-chip").forEach((chip) => {
    chip.classList.toggle("active", chip.dataset.target === target);
  });
}

function renderCards() {
  const c = catalog.counts;
  document.getElementById("rules-cards").innerHTML = `
    <div class="card"><div class="card-title">Sigma</div><div class="card-value">${c.sigma}</div><div class="card-sub small muted">min level: ${escapeHtml(catalog.sigma.min_level)}</div></div>
    <div class="card"><div class="card-title">YARA</div><div class="card-value">${c.yara}</div><div class="card-sub small muted">${catalog.yara.targets.length} targets</div></div>
    <div class="card"><div class="card-title">Heuristics</div><div class="card-value">${c.heuristics}</div><div class="card-sub small muted">hardcoded detectors</div></div>
    <div class="card"><div class="card-title">Behavioral</div><div class="card-value">${c.behavioral ?? 0}</div><div class="card-sub small muted">API-trace signatures</div></div>
    <div class="card"><div class="card-title">CAPE</div><div class="card-value">${c.cape ?? 0}</div><div class="card-sub small muted">community corpus${(catalog.cape && catalog.cape.score_enabled) ? "" : " (no verdict score)"}</div></div>
    <div class="card"><div class="card-title">Static signals</div><div class="card-value">${c.static}</div><div class="card-sub small muted">feed the verdict</div></div>
  `;
  document.getElementById("catalog-intro").textContent =
    `${c.sigma} Sigma rules, ${c.yara} YARA rules, ${c.heuristics} heuristic detectors, ${c.behavioral ?? 0} behavioral signatures, ${c.cape ?? 0} CAPE community signatures and ${c.static} static-analysis signals are applied to every sample.`;
}

function buildFamilyNav() {
  const nav = document.getElementById("rules-nav");
  const fams = [
    { target: "fam-sigma", label: "Sigma", count: catalog.counts.sigma },
    { target: "fam-yara", label: "YARA", count: catalog.counts.yara },
    { target: "fam-heuristics", label: "Heuristics", count: catalog.counts.heuristics },
    { target: "fam-behavioral", label: "Behavioral", count: catalog.counts.behavioral ?? 0 },
    { target: "fam-cape", label: "CAPE", count: catalog.counts.cape ?? 0 },
    { target: "fam-static", label: "Static", count: catalog.counts.static },
  ];
  nav.innerHTML = fams
    .map(
      (f) =>
        `<span class="nav-chip" data-target="${f.target}">${escapeHtml(f.label)}<span class="nav-count">${f.count}</span></span>`
    )
    .join("");
  nav.addEventListener("click", (e) => {
    const chip = e.target.closest(".nav-chip");
    if (chip) selectFamily(chip.dataset.target);
  });
  selectFamily("fam-sigma");
}

// --- Sigma (searchable + level-filtered + paginated) ---
function sigmaRow(r) {
  const src = r.category ? `category: ${r.category}` : r.service ? `service: ${r.service}` : "-";
  return `<tr class="rule-row" data-kind="sigma" data-id="${escapeHtml(r.id || "")}" title="${escapeHtml(r.id || "")}">
    <td><span class="rule-caret">▸</span> <span class="badge ${levelBadgeClass(r.level)}">${escapeHtml(r.level || "-")}</span></td>
    <td>${escapeHtml(r.title || "(untitled)")}${r.description ? `<div class="small muted">${escapeHtml(r.description.slice(0, 140))}${r.description.length > 140 ? "…" : ""}</div>` : ""}</td>
    <td class="small mono">${escapeHtml(src)}</td>
    <td>${attackChips(r.tags)}</td>
  </tr>`;
}

function rawBlock(text) {
  return `<pre class="log">${escapeHtml(text || "")}</pre>`;
}

// Click a rule row to expand its raw source: Sigma YAML fetched lazily per
// rule, YARA source already in the catalog.
async function toggleRuleDetail(row) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("rule-detail")) {
    next.remove();
    row.classList.remove("expanded");
    return;
  }
  const tr = document.createElement("tr");
  tr.className = "rule-detail";
  const td = document.createElement("td");
  td.colSpan = row.cells.length;
  tr.appendChild(td);
  row.after(tr);
  row.classList.add("expanded");

  if (row.dataset.kind === "cape") {
    td.innerHTML = `<div class="muted small">Loading…</div>`;
    try {
      const data = await Api.getCapeRuleRaw(row.dataset.name);
      td.innerHTML = rawBlock(data.source);
    } catch (e) {
      td.innerHTML = `<div class="error-text small">${escapeHtml(e.message)}</div>`;
    }
    return;
  }

  if (row.dataset.kind === "yara") {
    const rule = catalog.yara.rules.find((r) => r.name === row.dataset.name);
    // Small rulesets carry inline source; at vendored scale the catalog drops
    // it (source === null) and we fetch it lazily, like Sigma rules do.
    if (rule && rule.source) {
      td.innerHTML = rawBlock(rule.source);
      return;
    }
    td.innerHTML = `<div class="muted small">Loading…</div>`;
    try {
      const data = await Api.getYaraRuleRaw(row.dataset.name);
      td.innerHTML = rawBlock(data.source);
    } catch (e) {
      td.innerHTML = `<div class="error-text small">${escapeHtml(e.message)}</div>`;
    }
    return;
  }

  const id = row.dataset.id;
  if (!id) {
    td.innerHTML = `<div class="muted small">This rule has no id; raw source is unavailable.</div>`;
    return;
  }
  td.innerHTML = `<div class="muted small">Loading…</div>`;
  try {
    const data = await Api.getSigmaRuleRaw(id);
    td.innerHTML = rawBlock(data.yaml);
  } catch (e) {
    td.innerHTML = `<div class="error-text small">${escapeHtml(e.message)}</div>`;
  }
}

function wireRuleExpansion() {
  document.addEventListener("click", (e) => {
    const row = e.target.closest("tr.rule-row");
    if (row) toggleRuleDetail(row);
  });
}

function applySigmaFilter() {
  const q = document.getElementById("sigma-search").value.trim().toLowerCase();
  const level = document.getElementById("sigma-level").value;
  sigmaFiltered = catalog.sigma.rules.filter((r) => {
    if (level && (r.level || "") !== level) return false;
    if (!q) return true;
    const hay = `${r.title || ""} ${r.id || ""} ${r.category || ""} ${r.service || ""} ${(r.tags || []).join(" ")}`.toLowerCase();
    return hay.includes(q);
  });
  sigmaShown = 0;
  document.getElementById("sigma-body").innerHTML = "";
  renderMoreSigma();
}

function renderMoreSigma() {
  const body = document.getElementById("sigma-body");
  const next = sigmaFiltered.slice(sigmaShown, sigmaShown + SIGMA_PAGE);
  if (sigmaShown === 0 && !next.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty-state">No matching rules.</td></tr>`;
  } else {
    body.insertAdjacentHTML("beforeend", next.map(sigmaRow).join(""));
  }
  sigmaShown += next.length;
  document.getElementById("sigma-shown").textContent = `showing ${sigmaShown} of ${sigmaFiltered.length}`;
  const more = document.getElementById("sigma-more");
  more.classList.toggle("hidden", sigmaShown >= sigmaFiltered.length);
}

function renderSigma() {
  document.getElementById("sigma-count").textContent = catalog.sigma.count;
  document.getElementById("sigma-search").addEventListener("input", applySigmaFilter);
  document.getElementById("sigma-level").addEventListener("change", applySigmaFilter);
  document.getElementById("sigma-more").addEventListener("click", renderMoreSigma);
  applySigmaFilter();
}

// --- YARA / Heuristics / Static ---
// Paginated + searchable like the Sigma table: a vendored ruleset can be
// thousands of rules, so rendering them all at once (the old behavior) would
// jank the page.
const YARA_PAGE = 100;
let yaraFiltered = [];
let yaraShown = 0;

function yaraRow(r) {
  return `<tr class="rule-row" data-kind="yara" data-name="${escapeHtml(r.name)}">
    <td class="mono small"><span class="rule-caret">▸</span> ${escapeHtml(r.name)}</td>
    <td class="small">${escapeHtml(r.description || "-")}</td>
    <td class="small muted">${escapeHtml(r.file || "-")}</td>
  </tr>`;
}

function renderMoreYara() {
  const body = document.getElementById("yara-body");
  const next = yaraFiltered.slice(yaraShown, yaraShown + YARA_PAGE);
  if (yaraShown === 0 && !next.length) {
    body.innerHTML = `<tr><td colspan="3" class="empty-state">No matching rules.</td></tr>`;
  } else {
    body.insertAdjacentHTML("beforeend", next.map(yaraRow).join(""));
  }
  yaraShown += next.length;
  document.getElementById("yara-shown").textContent = `showing ${yaraShown} of ${yaraFiltered.length}`;
  document.getElementById("yara-more").classList.toggle("hidden", yaraShown >= yaraFiltered.length);
}

function applyYaraFilter() {
  const q = document.getElementById("yara-search").value.trim().toLowerCase();
  yaraFiltered = catalog.yara.rules.filter((r) => {
    if (!q) return true;
    return `${r.name || ""} ${r.description || ""} ${r.file || ""}`.toLowerCase().includes(q);
  });
  yaraShown = 0;
  document.getElementById("yara-body").innerHTML = "";
  renderMoreYara();
}

function renderYara() {
  document.getElementById("yara-count").textContent = catalog.yara.count;
  document.getElementById("yara-targets").textContent = "Applied to: " + catalog.yara.targets.join(" · ");
  const errs = catalog.yara.load_errors || [];
  if (errs.length) {
    document.getElementById("yara-load-errors").textContent =
      `${errs.length} rule file(s) failed to compile and were skipped (see server logs).`;
  }
  document.getElementById("yara-search").addEventListener("input", applyYaraFilter);
  document.getElementById("yara-more").addEventListener("click", renderMoreYara);
  applyYaraFilter();
}

function severityBadge(sev) {
  return sev ? `<span class="badge ${levelBadgeClass(sev)}">${escapeHtml(sev)}</span>` : "";
}

function detectorCard(d) {
  const detail =
    Array.isArray(d.detail) && d.detail.length
      ? `<div class="small mono muted" style="margin-top:4px">${d.detail.map(escapeHtml).join(", ")}</div>`
      : "";
  const mitre =
    Array.isArray(d.mitre) && d.mitre.length
      ? ` ${d.mitre.map((t) => `<span class="mitre-chip">${escapeHtml(t)}</span>`).join(" ")}`
      : "";
  return `<div class="card" style="margin-bottom:10px">
    <div style="display:flex; gap:8px; align-items:baseline; flex-wrap:wrap">
      <strong>${escapeHtml(d.name)}</strong>
      ${severityBadge(d.severity)}
      <span class="badge neutral">${escapeHtml(d.kind)}</span>
      ${mitre}
    </div>
    <div class="small" style="margin-top:4px">${escapeHtml(d.description || "")}</div>
    ${detail}
  </div>`;
}

function renderHeuristics() {
  document.getElementById("heuristics-count").textContent = catalog.heuristics.count;
  document.getElementById("heuristics-body").innerHTML = catalog.heuristics.detectors.map(detectorCard).join("");
}

function renderBehavioral() {
  const b = catalog.behavioral || { count: 0, detectors: [] };
  document.getElementById("behavioral-count").textContent = b.count;
  document.getElementById("behavioral-body").innerHTML = b.detectors.map(detectorCard).join("");
}

// --- CAPE community signatures (searchable + severity-filtered + paginated) ---
const CAPE_PAGE = 100;
let capeFiltered = [];
let capeShown = 0;

function capeRow(d) {
  const name = (d.id || "").replace(/^cape\./, "");
  const ttps = (d.mitre || []).map((t) => `<span class="mitre-chip">${escapeHtml(t)}</span>`).join("");
  return `<tr class="rule-row" data-kind="cape" data-name="${escapeHtml(name)}" title="${escapeHtml(name)}">
    <td><span class="rule-caret">▸</span> <span class="badge ${levelBadgeClass(d.severity)}">${escapeHtml(d.severity || "-")}</span></td>
    <td class="small"><span class="mono">${escapeHtml(name)}</span>${d.description ? `<div class="small muted">${escapeHtml(d.description.slice(0, 140))}${d.description.length > 140 ? "…" : ""}</div>` : ""}</td>
    <td class="small muted">${escapeHtml(d.kind || "-")}</td>
    <td>${ttps}</td>
  </tr>`;
}

function renderMoreCape() {
  const body = document.getElementById("cape-body");
  const next = capeFiltered.slice(capeShown, capeShown + CAPE_PAGE);
  if (capeShown === 0 && !next.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty-state">No matching signatures.</td></tr>`;
  } else {
    body.insertAdjacentHTML("beforeend", next.map(capeRow).join(""));
  }
  capeShown += next.length;
  document.getElementById("cape-shown").textContent = `showing ${capeShown} of ${capeFiltered.length}`;
  document.getElementById("cape-more").classList.toggle("hidden", capeShown >= capeFiltered.length);
}

function applyCapeFilter() {
  const q = document.getElementById("cape-search").value.trim().toLowerCase();
  const level = document.getElementById("cape-level").value;
  const detectors = (catalog.cape && catalog.cape.detectors) || [];
  capeFiltered = detectors.filter((d) => {
    if (level && (d.severity || "") !== level) return false;
    if (!q) return true;
    const hay = `${d.id || ""} ${d.name || ""} ${d.description || ""} ${(d.mitre || []).join(" ")}`.toLowerCase();
    return hay.includes(q);
  });
  capeShown = 0;
  document.getElementById("cape-body").innerHTML = "";
  renderMoreCape();
}

function renderCape() {
  const c = catalog.cape || { count: 0, detectors: [], load_errors: [] };
  document.getElementById("cape-count").textContent = c.count;
  document.getElementById("cape-score-state").textContent = c.score_enabled ? "ON" : "OFF";
  if (c.load_errors && c.load_errors.length) {
    document.getElementById("cape-load-errors").textContent = `${c.load_errors.length} modules failed to load (e.g. ${c.load_errors[0]})`;
  }
  document.getElementById("cape-search").addEventListener("input", applyCapeFilter);
  document.getElementById("cape-level").addEventListener("change", applyCapeFilter);
  document.getElementById("cape-more").addEventListener("click", renderMoreCape);
  applyCapeFilter();
}

function renderStatic() {
  document.getElementById("static-count").textContent = catalog.static.count;
  document.getElementById("static-body").innerHTML = catalog.static.signals
    .map(
      (s) => `<div class="card" style="margin-bottom:10px">
        <div style="display:flex; gap:8px; align-items:baseline"><strong>${escapeHtml(s.name)}</strong> ${severityBadge(s.severity)}</div>
        <div class="small" style="margin-top:4px">${escapeHtml(s.description || "")}</div>
      </div>`
    )
    .join("");
}

async function main() {
  try {
    catalog = await Api.getRules();
  } catch (e) {
    document.querySelector("main").innerHTML = `<div class="empty-state error-text">Failed to load rules: ${escapeHtml(e.message)}</div>`;
    return;
  }
  renderCards();
  buildFamilyNav();
  renderSigma();
  renderYara();
  renderHeuristics();
  renderBehavioral();
  renderCape();
  renderStatic();
  wireRuleExpansion();
}

main();
