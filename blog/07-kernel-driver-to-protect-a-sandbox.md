# Writing a kernel driver to protect a malware sandbox

> **Series:** PENTAGRAMMA, part 7/11 · **Draft skeleton** · Sources: `docs/guardian-driver.md`, `docs/guardian-driver-future-work.md` (2026-08-19 → 09-03)

**Lede:** Our telemetry lives inside the same OS as the malware — and malware kills telemetry. taskkill on Sysmon64, stop the service, add a Defender exclusion, delete the evidence. So we wrote **SandboxGuard**, a kernel driver with three jobs: *protect* our components, *verify* our hooks, *place* our monitor. It survived Driver Verifier, a 20-run soak, and one very educational BSOD.

## Outline

### Threat model: the sandbox is the attacked party
- Attackers aren't hypothetical: tamper canaries routinely try taskkill/service-stop/exclusion/registry-delete against our stack.
- User-mode protection is a polite request. Kernel callbacks are enforcement.

### Design (2026-08-19): one driver, three roles
- **Protect**: Ob callbacks (strip handle access to protected processes), Cm callbacks (deny writes to Sysmon/Defender keys), minifilter for file protection (deferred — the one proven gap).
- **Verify**: hook-integrity checking (deferred).
- **Place**: APC→LoadLibraryW injection of the monitor pre-entry (→ part 8).

### A0→A1a (09-01): it boots, then it bluescreens
- A0 spike: testsigning on, driver loads, PING handshake, process-create capture. GO decision.
- **0x7E BSOD from swapped `CmRegisterCallbackEx` arguments** — the kind of bug that only exists in kernel land, caught in minutes because the whole VM is disposable.
- A1a: 7/7 checks PASS — kill-block on protected process, Sysmon key write denied, benign `wkscli.dll` injected pre-entry.

### A2 (09-02): protecting yourself out of your own telemetry
- Baked into the golden image — and immediately **the driver's boot-armed Cm protection blocked our own telemetry init**: 20 false alerts, benign canary flipped to malicious/45.
- Lesson: protection logic needs an allowlist for its own side, or it becomes the loudest false-positive generator in the system.

### A4 (09-03): the tamper canary audit
- All protected actions **denied**: taskkill Sysmon64 ❌, service stop ❌, Defender exclusion ❌, Sysmon key write ❌.
- The one success: deleting the telemetry **file** — recorded as the known gap → minifilter (A1b, deferred deliberately).
- **Driver Verifier soak: all 4 soak configs + 7 A1a checks PASS, no bugchecks.**
- Stability gate: 15/20 runs; the 5 failures were 2 host OOM + 3 verdict flaps traced to *our own tooling attribution* (AMSI self-detection +25, monitor child-following looking like injection +8, PID-reuse lineage +38 → fixed with ProcessGuid-tree lineage; benign score 37→12).
- *[placeholder: tamper canary results table]*

### What we deliberately did NOT build
- No ETW role, no network filtering, no defense against kernel-competent samples. A sandbox driver that fights a kernel rootkit is a different project with a different risk budget.

**Takeaway:** a protection driver's real enemies are your own false positives and your own init order — the malware part was the easy half.

---
*Status: skeleton. Needs: driver architecture diagram, BSOD story detail, verifier config list.*
