# Track 3.0(b) WDAC feasibility spike -- runs INSIDE the golden-image VM.
#
# Submitted as a normal sample. The agent deploy already staged the monitor
# binaries into C:\SandboxAgent (agent/windows ships them), so this script just
# drives them and reports whether monitor_x64.dll LOADS under the golden image's
# WDAC / Code-Integrity policy -- the one question the host-side proof could not
# answer. It prints a compact machine-readable result block; the sandbox
# captures the sample's stdout into report.execution_info.Stdout, which is how
# the orchestrator reads the outcome back.
#
# VERDICT values:
#   DLL_LOADED   - LoadLibraryW succeeded (loader exit 0) => WDAC allows the DLL.
#   DLL_BLOCKED  - loader exit 5 (LoadLibraryW returned 0) => WDAC blocked it;
#                  build POST /api/vm/provision-monitor (WDAC allowlist) next.
#   LOADER_FAILED- the loader EXE itself could not run (unexpected).

$ErrorActionPreference = 'Continue'
$agent     = 'C:\SandboxAgent'
$dll       = Join-Path $agent 'monitor_x64.dll'
$loader    = Join-Path $agent 'monitor_loader.exe'
$collector = Join-Path $agent 'apitrace_collector.py'
$out       = Join-Path $agent 'apitrace_spike.jsonl'
$colerr    = Join-Path $agent 'spike_col_err.txt'
$copyDst   = Join-Path $agent 'spike_copy.txt'

$python = Join-Path $agent '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) { $python = 'C:\Python311\python.exe' }
if (-not (Test-Path $python)) { $python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source }

"=== MONITOR_WDAC_SPIKE ==="
"DLL_PRESENT=$([int](Test-Path $dll))"
"LOADER_PRESENT=$([int](Test-Path $loader))"
"PYTHON=$python"

# 1) start the collector (named-pipe server), auto-stops after 12s
$colStarted = 0
if ($python -and (Test-Path $collector)) {
    try {
        $col = Start-Process -FilePath $python `
            -ArgumentList @($collector, '--out', $out, '--max-seconds', '12') `
            -PassThru -WindowStyle Hidden -RedirectStandardError $colerr
        $colStarted = 1
        Start-Sleep -Milliseconds 900   # let the pipe server bind
    } catch { "COLLECTOR_START_ERROR=$($_.Exception.Message)" }
}
"COLLECTOR_STARTED=$colStarted"

# 2) run the loader: inject monitor_x64.dll into `cmd /c copy` (triggers NtCreateFile)
$loaderExit = -1
$loaderErr = ''
try {
    $p = Start-Process -FilePath $loader `
        -ArgumentList @($dll, 'C:\Windows\System32\cmd.exe', '/c', 'copy', '/y', 'C:\Windows\win.ini', $copyDst) `
        -PassThru -Wait -NoNewWindow -RedirectStandardError "$agent\spike_loader_err.txt"
    $loaderExit = $p.ExitCode
    if (Test-Path "$agent\spike_loader_err.txt") { $loaderErr = (Get-Content "$agent\spike_loader_err.txt" -Raw) }
} catch {
    "LOADER_LAUNCH_ERROR=$($_.Exception.Message)"
}
"LOADER_EXIT=$loaderExit"
"LOADER_STDERR=$($loaderErr.Trim())"

# 3) let the collector flush, then read captured events
if ($colStarted) { try { $col.WaitForExit(15000) | Out-Null } catch {} }
$events = @()
if (Test-Path $out) { $events = @(Get-Content $out -ErrorAction SilentlyContinue) }
"APITRACE_EVENTS=$($events.Count)"
$events | Select-Object -First 3 | ForEach-Object { "EVENT=$_" }

# 4) cross-check the CodeIntegrity operational log for a recent block of our DLL
$ciBlocks = 0
try {
    $ciBlocks = @(Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 20 -ErrorAction Stop |
        Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) -and $_.Message -match 'monitor_x64' }).Count
} catch { }
"CI_BLOCK_EVENTS=$ciBlocks"

# 5) verdict
$verdict = 'LOADER_FAILED'
if ($loaderExit -eq 0)      { $verdict = 'DLL_LOADED' }
elseif ($loaderExit -eq 5)  { $verdict = 'DLL_BLOCKED' }
"VERDICT=$verdict"
"=== END_MONITOR_WDAC_SPIKE ==="
