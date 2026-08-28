// Owns the whole "Network capture" section on the report detail page.
// Two-tier rendering so a slow/large capture never blocks the rest of the
// page: the metadata table renders synchronously from data already in the
// loaded report; the collapsible stats row (chart/conversations) and the
// packet browser are fetched separately and asynchronously, only when a
// capture plausibly exists. DNS is covered by the IOC "Domains" tab.
const NetworkView = (() => {
  let packetsState = { offset: 0, limit: 100, protocol: "", ip: "", port: "", q: "" };
  let protocolChart = null;
  let currentAnalysisId = null;
  let lastPackets = [];      // the currently loaded page, for popup prev/next
  let lightboxPacketPos = 0; // position within lastPackets of the open packet

  function renderMeta(nc) {
    document.getElementById("network-meta").innerHTML = `
      <table class="compact">
        <tr><td class="muted">Enabled</td><td>${nc.enabled ? "yes" : "no"}</td></tr>
        <tr><td class="muted">Started</td><td>${nc.started ? "yes" : "no"}</td></tr>
        ${nc.SizeBytes != null ? `<tr><td class="muted">Capture size</td><td>${fmtBytes(nc.SizeBytes)}</td></tr>` : ""}
        ${nc.HostPath ? `<tr><td class="muted">Host path</td><td class="mono small">${escapeHtml(nc.HostPath)}</td></tr>` : ""}
        ${nc.error ? `<tr><td class="muted">Error</td><td class="error-text small">${escapeHtml(nc.error)}</td></tr>` : ""}
      </table>
    `;
  }

  function renderUnavailable(reason, detail) {
    document.getElementById("network-visualizer").innerHTML = `
      <div class="empty-state small">No packet data available (${escapeHtml(reason)}). ${escapeHtml(detail || "")}</div>
    `;
  }

  function renderOverview(summary) {
    document.getElementById("network-packets-count").textContent = summary.total_packets;

    const truncNote = summary.truncated
      ? `<div class="small error-text" style="margin-bottom:8px">Capture truncated: analyzed first ${summary.packets_scanned} packets only.</div>`
      : "";

    // Statistics collapse into a single summary row; the chart + top
    // conversations render on first expand (the chart needs a visible
    // canvas to size correctly). DNS is deliberately not shown here -- the
    // IOC "Domains" tab already covers it.
    const statsLine =
      `${summary.total_packets} packets · ${fmtBytes(summary.total_bytes)}` +
      `${summary.duration_seconds != null ? ` · ${fmtDuration(summary.duration_seconds)}` : ""}` +
      ` · ${summary.top_conversations.length} conversations · ${Object.keys(summary.protocol_counts).length} protocols`;

    document.getElementById("network-visualizer").innerHTML = `
      ${truncNote}
      <details class="aux-details" id="network-stats">
        <summary>${escapeHtml(statsLine)}</summary>
        <div class="aux-body">
          <div class="grid cols-2">
            <div class="card">
              <div class="card-title">Protocol breakdown</div>
              <canvas id="network-protocol-chart" height="140"></canvas>
            </div>
            <div class="card">
              <div class="card-title">Top conversations</div>
              <table class="compact">
                <thead><tr><th>A</th><th>B</th><th>Proto</th><th>Packets</th><th>Bytes</th></tr></thead>
                <tbody id="network-conversations-body"></tbody>
              </table>
            </div>
          </div>
        </div>
      </details>

      <div class="controls" style="margin-top:12px">
        <select id="network-protocol-filter"><option value="">all protocols</option></select>
        <input type="text" id="network-ip-filter" placeholder="ip…" style="width:140px" />
        <input type="text" id="network-port-filter" placeholder="port…" style="width:90px" />
        <input type="text" id="network-search" placeholder="search…" />
        <button id="btn-load-packets">Load packets</button>
        <button id="btn-packets-prev" class="secondary">◀ prev</button>
        <button id="btn-packets-next" class="secondary">next ▶</button>
        <span id="network-packets-page-label" class="small muted"></span>
      </div>
      <table>
        <thead><tr><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th><th>Len</th><th>Summary</th></tr></thead>
        <tbody id="network-packets-body">
          <tr><td colspan="6" class="empty-state">Click "Load packets" to browse the capture.</td></tr>
        </tbody>
      </table>
    `;

    renderConversations(summary.top_conversations);
    const statsPanel = document.getElementById("network-stats");
    statsPanel.addEventListener("toggle", () => {
      if (statsPanel.open) renderProtocolChart(summary.protocol_counts);
    });
    wirePacketsBrowser();
  }

  function renderProtocolChart(protocolCounts) {
    const entries = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);
    const ctx = document.getElementById("network-protocol-chart").getContext("2d");
    if (protocolChart) protocolChart.destroy();
    protocolChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: entries.map((e) => e[0]),
        datasets: [{ label: "Packets", data: entries.map((e) => e[1]), backgroundColor: "#9b8bd4" }],
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

    const select = document.getElementById("network-protocol-filter");
    select.innerHTML =
      '<option value="">all protocols</option>' +
      entries.map((e) => `<option value="${escapeHtml(e[0])}">${escapeHtml(e[0])} (${e[1]})</option>`).join("");
  }

  function renderConversations(conversations) {
    const tbody = document.getElementById("network-conversations-body");
    if (!conversations.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No conversations.</td></tr>`;
      return;
    }
    tbody.innerHTML = conversations
      .map(
        (c) => `<tr>
          <td class="mono small">${escapeHtml(c.a)}</td>
          <td class="mono small">${escapeHtml(c.b)}</td>
          <td>${escapeHtml(c.protocol)}</td>
          <td>${c.packets}</td>
          <td>${fmtBytes(c.bytes)}</td>
        </tr>`
      )
      .join("");
  }

  // --- packet detail popup (layers + raw bytes) ---

  function ensurePacketLightbox() {
    let lb = document.getElementById("packet-lightbox");
    if (lb) return lb;
    lb = document.createElement("div");
    lb.id = "packet-lightbox";
    lb.className = "lightbox";
    lb.style.display = "none";
    lb.innerHTML = `
      <button id="packet-lightbox-close" class="secondary">&times;</button>
      <button id="packet-lightbox-prev" class="secondary">&#9664;</button>
      <div class="packet-lightbox-body">
        <div id="packet-lightbox-caption" class="small"></div>
        <div class="grid cols-2 packet-lightbox-grid">
          <div><h4>Layers</h4><pre id="packet-lightbox-layers" class="log"></pre></div>
          <div><h4>Raw bytes</h4><pre id="packet-lightbox-hex" class="log"></pre></div>
        </div>
      </div>
      <button id="packet-lightbox-next" class="secondary">&#9654;</button>
    `;
    document.body.appendChild(lb);
    document.getElementById("packet-lightbox-close").addEventListener("click", closePacketLightbox);
    lb.addEventListener("click", (e) => {
      if (e.target.id === "packet-lightbox") closePacketLightbox();
    });
    document.getElementById("packet-lightbox-prev").addEventListener("click", () => showPacketDetail(lightboxPacketPos - 1));
    document.getElementById("packet-lightbox-next").addEventListener("click", () => showPacketDetail(lightboxPacketPos + 1));
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && lb.style.display !== "none") closePacketLightbox();
    });
    return lb;
  }

  function closePacketLightbox() {
    document.getElementById("packet-lightbox").style.display = "none";
  }

  async function showPacketDetail(pos) {
    if (!lastPackets.length) return;
    lightboxPacketPos = (pos + lastPackets.length) % lastPackets.length;
    const p = lastPackets[lightboxPacketPos];
    const lb = ensurePacketLightbox();
    lb.style.display = "flex";
    document.getElementById("packet-lightbox-caption").innerHTML =
      `<strong>packet #${p.index}</strong> · ${escapeHtml(p.timestamp)} · ${escapeHtml(p.protocol)} · ${p.length} bytes`;
    document.getElementById("packet-lightbox-layers").textContent = "Loading…";
    document.getElementById("packet-lightbox-hex").textContent = "";
    try {
      const d = await Api.getNetworkPacket(currentAnalysisId, p.index);
      document.getElementById("packet-lightbox-layers").textContent = d.layers || "(no dissection)";
      document.getElementById("packet-lightbox-hex").textContent = d.hex || "";
    } catch (e) {
      document.getElementById("packet-lightbox-layers").textContent = `Failed to load: ${e.message}`;
    }
  }

  async function loadPackets() {
    const tbody = document.getElementById("network-packets-body");
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Loading…</td></tr>`;
    packetsState.protocol = document.getElementById("network-protocol-filter").value;
    packetsState.ip = document.getElementById("network-ip-filter").value;
    packetsState.port = document.getElementById("network-port-filter").value;
    packetsState.q = document.getElementById("network-search").value;
    try {
      const data = await Api.getNetworkPackets(currentAnalysisId, packetsState);
      const exactness = data.filtered_total_is_exact ? "" : " (lower bound — capture truncated)";
      document.getElementById("network-packets-page-label").textContent = `offset ${data.offset} · ${data.filtered_total}/${data.total}${exactness}`;
      if (!data.packets.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No matching packets.</td></tr>`;
        return;
      }
      lastPackets = data.packets;
      tbody.innerHTML = data.packets
        .map((p, i) => {
          const src = p.sport != null ? `${p.src}:${p.sport}` : p.src || "-";
          const dst = p.dport != null ? `${p.dst}:${p.dport}` : p.dst || "-";
          return `<tr class="packet-row" data-pos="${i}" title="click for layers + raw bytes">
            <td class="small">${escapeHtml(p.timestamp)}</td>
            <td class="mono small">${escapeHtml(src)}</td>
            <td class="mono small">${escapeHtml(dst)}</td>
            <td class="small">${escapeHtml(p.protocol)}</td>
            <td>${p.length}</td>
            <td class="mono small">${escapeHtml(p.summary)}</td>
          </tr>`;
        })
        .join("");
      tbody.querySelectorAll("tr.packet-row").forEach((row) => {
        row.addEventListener("click", () => showPacketDetail(parseInt(row.dataset.pos, 10)));
      });
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6" class="error-text">${escapeHtml(e.message)}</td></tr>`;
    }
  }

  function wirePacketsBrowser() {
    document.getElementById("btn-load-packets").addEventListener("click", () => {
      packetsState.offset = 0;
      loadPackets();
    });
    document.getElementById("btn-packets-prev").addEventListener("click", () => {
      packetsState.offset = Math.max(0, packetsState.offset - packetsState.limit);
      loadPackets();
    });
    document.getElementById("btn-packets-next").addEventListener("click", () => {
      packetsState.offset += packetsState.limit;
      loadPackets();
    });
  }

  async function render(report, analysisId) {
    currentAnalysisId = analysisId;
    const nc = report.network_capture || {};
    renderMeta(nc);

    if (!nc.enabled || !nc.HostPath) {
      renderUnavailable(nc.enabled ? "not_started" : "disabled", "");
      return;
    }

    document.getElementById("network-visualizer").innerHTML = `<div class="muted small">Loading capture…</div>`;
    try {
      const summary = await Api.getNetworkSummary(analysisId);
      if (!summary.capture_available) {
        renderUnavailable(summary.reason, summary.detail);
        return;
      }
      renderOverview(summary);
    } catch (e) {
      document.getElementById("network-visualizer").innerHTML = `<div class="error-text small">Failed to load capture: ${escapeHtml(e.message)}</div>`;
    }
  }

  return { render };
})();
