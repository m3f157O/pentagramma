// Self-rescheduling setTimeout (not setInterval) so a slow PowerShell-backed
// call never causes overlapping in-flight requests. Pauses while the tab is
// hidden (Page Visibility API) so a dashboard left open in the background
// doesn't keep hammering the API.
function startPoll(fn, intervalMs, { immediate = true } = {}) {
  let stopped = false;
  let timer = null;

  async function tick() {
    if (stopped) return;
    if (!document.hidden) {
      try {
        await fn();
      } catch (err) {
        console.error("[poll] error:", err);
      }
    }
    if (!stopped) {
      timer = setTimeout(tick, intervalMs);
    }
  }

  if (immediate) {
    tick();
  } else {
    timer = setTimeout(tick, intervalMs);
  }

  return function stop() {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}
