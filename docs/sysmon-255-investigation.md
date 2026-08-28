# Sysmon EID 255 Investigation

## Observation

Every `InjectionHarness` run produces exactly **two** `SysmonEvent255` events:

```json
{
  "source": "sysmon",
  "event_id": 255,
  "event_type": "SysmonEvent255",
  "data": {
    "ID": "IMAGE_LOAD",
    "Description": "Failed to find process image name"
  }
}
```

They occur at the same timestamp as the process-ghosting test.

## Root cause

Process ghosting creates an image section from a file that is then deleted before the process starts. When the ghosted process loads its dependent DLLs, Sysmon tries to resolve the image name from the process object. Because the on-disk executable no longer exists, Sysmon logs EID 255 (`IMAGE_LOAD: Failed to find process image name`) instead of a normal EID 7 (`ImageLoad`).

This is expected behavior and is itself an artifact of the ghosting technique.

## Verdict

- **Benign.** These errors are caused by the intentional file deletion in `TestProcessGhosting()`.
- **Do not filter them out blindly.** The presence of EID 255 `IMAGE_LOAD` failures alongside a `ProcessTampering` EID 25 (`Image is locked for access`) for the same PID is a useful corroborating signal for ghosting.
- **Correlation suggestion:** If a process has EID 25 type `Image is locked for access` **and** one or more EID 255 `IMAGE_LOAD` failures with the same PID, it is almost certainly a ghosted process.

## Action taken

None required. This note documents the behavior so future analysts do not chase it as a telemetry error.
