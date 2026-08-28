// Owns the "Screenshots" section on the report detail page. Metadata is
// already inlined in the trimmed report (report.screenshots), so unlike
// NetworkView this needs no extra fetch for the gallery itself -- only the
// <img> tags hit the network, lazily, as the browser loads them.
const ScreenshotView = (() => {
  let items = [];
  let currentAnalysisId = null;
  let lightboxIndex = 0;

  function renderMeta(sc) {
    document.getElementById("screenshots-meta").innerHTML = `
      <table class="compact">
        <tr><td class="muted">Enabled</td><td>${sc.enabled ? "yes" : "no"}</td></tr>
        <tr><td class="muted">Interval</td><td>${sc.interval_seconds != null ? `${sc.interval_seconds}s` : "-"}</td></tr>
        <tr><td class="muted">Captured</td><td>${sc.count || 0}</td></tr>
      </table>
    `;
  }

  function renderUnavailable(reason) {
    document.getElementById("screenshots-gallery").innerHTML = `
      <div class="empty-state small">No screenshots available (${escapeHtml(reason)}).</div>
    `;
  }

  function openLightbox(index) {
    lightboxIndex = index;
    renderLightbox();
    document.getElementById("screenshot-lightbox").style.display = "flex";
  }

  function closeLightbox() {
    document.getElementById("screenshot-lightbox").style.display = "none";
  }

  function renderLightbox() {
    const item = items[lightboxIndex];
    const img = document.getElementById("screenshot-lightbox-img");
    img.src = Api.screenshotUrl(currentAnalysisId, item.index);
    document.getElementById("screenshot-lightbox-caption").textContent =
      `#${item.index} · ${fmtDate(item.timestamp)}`;
  }

  function wireLightbox() {
    document.getElementById("screenshot-lightbox-close").addEventListener("click", closeLightbox);
    document.getElementById("screenshot-lightbox").addEventListener("click", (e) => {
      if (e.target.id === "screenshot-lightbox") closeLightbox();
    });
    document.getElementById("screenshot-lightbox-prev").addEventListener("click", () => {
      lightboxIndex = (lightboxIndex - 1 + items.length) % items.length;
      renderLightbox();
    });
    document.getElementById("screenshot-lightbox-next").addEventListener("click", () => {
      lightboxIndex = (lightboxIndex + 1) % items.length;
      renderLightbox();
    });
  }

  function renderGallery() {
    const captured = items.filter((i) => !i.error);
    if (!captured.length) {
      renderUnavailable(items.length ? "all captures failed" : "no_captures");
      return;
    }
    document.getElementById("screenshots-gallery").innerHTML = `
      <div class="screenshot-grid">
        ${captured
          .map(
            (item, i) => `
          <div class="screenshot-thumb" data-index="${i}">
            <img loading="lazy" src="${Api.screenshotUrl(currentAnalysisId, item.index)}" alt="Screenshot #${item.index}" />
            <div class="small muted">#${item.index} · ${fmtDate(item.timestamp)}</div>
          </div>`
          )
          .join("")}
      </div>
      <div id="screenshot-lightbox" class="lightbox" style="display:none">
        <button id="screenshot-lightbox-close" class="secondary">&times;</button>
        <button id="screenshot-lightbox-prev" class="secondary">&#9664;</button>
        <img id="screenshot-lightbox-img" alt="Screenshot" />
        <button id="screenshot-lightbox-next" class="secondary">&#9654;</button>
        <div id="screenshot-lightbox-caption" class="small"></div>
      </div>
    `;
    items = captured;
    document.querySelectorAll(".screenshot-thumb").forEach((el) => {
      el.addEventListener("click", () => openLightbox(parseInt(el.dataset.index, 10)));
    });
    wireLightbox();
  }

  function render(report, analysisId) {
    currentAnalysisId = analysisId;
    const sc = report.screenshots || {};
    renderMeta(sc);
    items = sc.items || [];
    if (!sc.enabled || !items.length) {
      renderUnavailable(sc.enabled ? "no_captures" : "disabled");
      return;
    }
    renderGallery();
  }

  return { render };
})();
