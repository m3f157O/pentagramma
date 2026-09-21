# A fleet of one: we uninstalled Sysmon on purpose, then rebuilt the VM from a web page

> **Series:** PENTAGRAMMA, part 17/? · **Draft skeleton** · Sources: git `b7093c2`, fleet acceptance test 2026-09-18 (reports `0e821527` vs `028b8490`)

**Lede:** The dashboard answered "is the VM up?" but not the question that actually ruins afternoons: "is it *instrumented*?" So we built a Fleet page — every detonation-capable machine (local host + all Hyper-V VMs), per-VM credentials, instrumentation health chips, and one-click provisioning. The acceptance test was the fun part: strip pentagramma naked (uninstall Sysmon, delete the agent dir), rebuild it entirely through the API, detonate a canary, revert, diff the reports. It found a real bug within minutes.

## Outline

### Health is a probe, not a guess
- One shared `$script:InstrumentationProbe` (Sysmon service, agent dir, monitor DLLs, Guardian, Secure Boot, Defender RTP) — same scriptblock runs in-process for the host or via PSDirect in a guest. One contract, two transports.
- PSDirect costs 1–3s and the dashboard polls every 5s → per-VM TTL caches (30s health / 15s inventory). `/api/fleet` went from 1.7s to **12ms**.
- The inverted check: on a detonation VM, Defender RTP being *off* is the green state.

### Credentials as registry, presence only
- `hyperv.vms` list in config (explicit, one entry per VM, no defaults) + GUI-managed `vms.yaml`. The API answers "creds configured?" with the username — the password is never serialized, and a test asserts it.

### The acceptance test that bit back
- De-provisioned pentagramma live (Sysmon out, `C:\SandboxAgent` gone) → fleet chips went red, as designed.
- Rebuilt via five API calls: agent, sysmon, defender-off, dressing, noise-reduction — all verify exit 0, chips back to green.
- Canary diff: baseline **clean/0**, API-provisioned **suspicious/25**. The +25: `Virus:Win32/MpTest!amsi` — Defender flagging *our own* file. First suspect was the readiness probe; wrong. The evidence (`Path=file:_C:\SandboxAgent\__pycache__\defender_manager.cpython-311.pyc`) said Defender was detecting the **compiled bytecode of our own agent**: the author had fragmented the AMSI test string so the *source* wouldn't be quarantined, but Python **constant-folds** `"a" + "b"` at compile time — the .pyc carried the contiguous signature all along. A Defender engine update that morning (4.18.26050 → 4.18.26080, mid-run) started flagging it. Every canary on every image would have gone suspicious within the hour.
- Fix, two layers: the string is now built with `" ".join([...])` (method calls are never folded — .pyc provably clean), and the heuristic drops MpTest detections whose path is under the agent dir (our tooling, by construction, at any timestamp).
- Same self-trigger family as the recycled-PID bug — the sandbox scoring its own instrumentation — except this one was scheduled by Microsoft's engine update channel, not by us.
- Bonus empiricism: while verifying, we pasted the test string into a host shell and host AMSI blocked the command. The string is genuinely radioactive on any unexcluded machine.

**Takeaway:** "provisioned" is a claim; health checks are evidence. And if your acceptance test doesn't include strip-it-and-rebuild-it, your provisioning code is aspirational.

---
*Status: skeleton. Assets: fleet page screenshots (red → green chips), the two report diffs, the MpTest 1116 events (one with the .pyc path — the fingerprint), the two Defender product versions side by side (engine updated mid-run). See also part 13 (recycled PID) for the self-trigger family.*
