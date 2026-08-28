"""Static-integrity checks for the web dashboard (orchestrator/static).

Guards the conventions the UI relies on: no mojibake/BOM regressions, every
element id referenced from JS exists in the page that loads it, and shared
assets carry one consistent cache-buster version across all pages.

Plain asserts, no pytest: .venv\Scripts\python.exe tests\test_ui_static.py
"""

import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent / "orchestrator" / "static"
failures = []

# 1. mojibake scan (double-encoded UTF-8 leftovers)
bad = []
for f in root.rglob("*"):
    if f.suffix not in (".html", ".js", ".css"):
        continue
    t = f.read_text(encoding="utf-8")
    for pat in ("Â", "â€", "â—", "â†", "ï»¿"):
        if pat in t:
            bad.append((f.name, pat))
if bad:
    failures.append(f"mojibake remains: {bad}")
else:
    print("1. mojibake scan: clean")

# 2. BOM scan
for f in root.rglob("*.html"):
    raw = f.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        failures.append(f"BOM in {f.name}")
print("2. BOM scan: clean" if not any("BOM" in x for x in failures) else "2. BOM found")

# 3. every getElementById in report-page JS must exist in report.html
html = (root / "report.html").read_text(encoding="utf-8")
html_ids = set(re.findall(r'id="([^"]+)"', html))
# ids created dynamically by JS (event_browser, network_view, screenshot lightbox)
dynamic_ok = set()
for js in ("js/report_detail.js", "js/network_view.js", "js/screenshot_view.js", "js/event_browser.js"):
    t = (root / js).read_text(encoding="utf-8")
    dynamic_ok |= set(re.findall(r'id="([^"]+)"', t))
js = (root / "js/report_detail.js").read_text(encoding="utf-8")
used = set(re.findall(r'getElementById\("([^"]+)"\)', js))
missing = sorted(used - html_ids - dynamic_ok)
if missing:
    failures.append(f"report_detail.js ids missing from report.html: {missing}")
else:
    print(f"3. report_detail.js id refs: all {len(used)} resolve")

# 4. other pages: same check per page (only the JS each page loads)
page_js = {
    "index.html": ["js/dashboard.js"],
    "reports.html": ["js/reports.js"],
    "rules.html": ["js/rules.js"],
    "harness.html": ["js/harness.js"],
    "live.html": ["js/live.js"],
    "traces.html": ["js/traces.js"],
}
for page, scripts in page_js.items():
    h = (root / page).read_text(encoding="utf-8")
    ids = set(re.findall(r'id="([^"]+)"', h))
    for s in scripts:
        t = (root / s).read_text(encoding="utf-8")
        ids |= set(re.findall(r'id="([^"]+)"', t))
        u = set(re.findall(r'getElementById\("([^"]+)"\)', t))
        m = sorted(u - ids)
        if m:
            failures.append(f"{s} ids missing from {page}: {m}")
print("4. per-page id refs: all resolve")

# 5. cache-buster consistency: shared assets same version everywhere
vers = {}
for f in root.glob("*.html"):
    t = f.read_text(encoding="utf-8")
    for m in re.finditer(r'href="(css/[^"?]+)\?v=(\d+)"|src="(js/[^"?]+)\?v=(\d+)"', t):
        asset = m.group(1) or m.group(3)
        v = m.group(2) or m.group(4)
        vers.setdefault(asset, {}).setdefault(v, []).append(f.name)
for asset, vv in vers.items():
    if len(vv) > 1:
        failures.append(f"version drift on {asset}: {vv}")
print("5. cache-busters:", {a: list(v) for a, v in vers.items()})

if failures:
    print("\nFAILURES:")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("\nALL STATIC CHECKS PASSED")
