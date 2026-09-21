# Teaching the sandbox to lie: environment dressing

> **Series:** PENTAGRAMMA, part 5/11 · **Draft skeleton** · Sources: `docs/environment-dressing.md` (2026-07-27), `scripts/collect/apply_dressing.py`

**Lede:** A fresh VM screams "sandbox": empty Documents, no browser history, uptime of 40 seconds. Malware checks. So we taught the golden image to lie — decoy documents, a fake browsing life, believable shell artifacts — and re-captured the snapshot only after proving the lies stuck.

## Outline

### What malware looks for
- Empty user profile, no Recent files, pristine Edge, no RunMRU, generic hostname, tiny uptime.
- Each check is cheap; failing any of them costs you the detonation ("sample exits cleanly" — the worst verdict: no data).

### The dressing pass
- `apply_dressing.py` + `POST /api/vm/provision-dressing`:
  - ~15 decoy documents (invoices, contracts, passwords.txt — the classics)
  - Edge History sqlite + bookmarks with plausible timestamps
  - RunMRU, TypedPaths, Recent `.lnk`s
- *[placeholder: guest desktop screenshot after dressing]*

### Verify-gated snapshot capture
- Dressing applied → verification script confirms artifacts present and readable → **only then** re-capture the golden image.
- A broken dressing baked into the snapshot is worse than none: you'd debug "evasive malware" that's actually your own failed provisioning.

### The lie we can't tell
- **Uptime can't be faked.** Every run boots fresh from snapshot; `GetTickCount` tells the truth. Accepted limitation — most uptime checks look for <10 minutes during first boot, and our pre-sample soak covers some of it, but a determined sample knows.
- Honest trade-off log: what we dressed, what we couldn't, what we didn't bother with (and why).

**Takeaway:** anti-analysis is an arms race of details; you don't have to win everywhere — just enough that the sample runs long enough to hang itself.

---
*Status: skeleton. Needs: dressing artifact list, verify script excerpt, uptime-check discussion.*
