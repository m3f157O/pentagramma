# Environment Dressing (anti-sandbox realism)

**Status:** implemented 2026-07-27 — `agent/windows/apply_dressing.py` +
`POST /api/vm/provision-dressing` (orchestrator/main.py).

## Why

Fresh VMs fail the most common anti-sandbox heuristics: empty user profile,
no browser history, no recently-used files, no RunMRU. Dressing makes the
golden image look like a used machine so samples that gate on "does anyone
work here?" actually detonate.

## What it creates (per golden image, idempotent)

| Category | Artifacts |
|---|---|
| Documents/Downloads/Desktop/Pictures | ~15 files with real minimal formats (valid docx/xlsx/pdf/png/txt/csv) — plausible names (`Q3_budget_review.xlsx`, `vpn_setup_notes.txt`, …) |
| Browser (Edge) | `History` sqlite (urls + visits with realistic timestamps), `Bookmarks` JSON |
| Recent-run artifacts | RunMRU (`cmd`, `notepad todo.txt`, `ipconfig /all`, `mstsc`), TypedPaths, Recent-folder `.lnk` shortcuts (via WScript.Shell COM when pywin32 present) |

## How to apply / refresh

```
POST http://127.0.0.1:18000/api/vm/provision-dressing
```

Follows the same verify-gated pattern as the other `provision-*` endpoints:
restore snapshot → boot → copy agent → `apply_dressing.py apply` →
`apply_dressing.py verify` (exit-code gate) → **re-capture SANDBOX_READY only
if verification passes**. The golden image is never modified by a failed run.

## Known limitations (accepted)

- **Uptime cannot be faked** — every run boots fresh, so "uptime < N minutes"
  checks still fire. Fixing that needs hypervisor-level time control
  (rejected: staying on Hyper-V, no public VMI API).
- Edge history is only seeded if Edge is installed in the guest; otherwise
  skipped silently (`edge-not-installed` in the apply output).
- Registry artifacts are per-user (gigi); samples running as a different
  principal see less.
