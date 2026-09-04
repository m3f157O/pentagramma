# Guest-side interactive launcher. Runs INSIDE the interactive console
# session (started via scheduled task by Invoke-SampleExecutionInteractive),
# so the sample's UI renders on the visible desktop -- unlike the normal
# PSDirect launch, whose window station is invisible (verified 2026-09-03:
# modal MessageBox up for 90s, never visible in any console thumbnail).
#
# Reads its launch spec from launch_spec.json in -WorkDir (written by the
# host right before the task starts -- a JSON file, NOT command-line args,
# so arbitrary sample arguments survive scheduled-task quoting untouched):
#   {
#     "launcher_path": "C:\\Sandbox\\sample.exe",   # resolved launcher
#     "arguments": "...",
#     "working_directory": "C:\\Sandbox",
#     "timeout_seconds": 120,
#     "behavioral_tracing": true,
#     "monitor_dll_path": "C:\\SandboxAgent\\monitor_x64.dll",
#     "monitor_loader_path": "C:\\SandboxAgent\\monitor_loader.exe",
#     "monitor_pid_file": "C:\\SandboxAgent\\sample_pid.txt"
#   }
# Writes launch_result.json: {Started, ProcessId, ExitCode, TimedOut, ...}
# and captures stdout/stderr to files. Process dumps are NOT done here
# (interactive mode disables them; the executor notes it in the report).
[CmdletBinding()]
param([string]$WorkDir = "C:\SandboxAgent\interactive_run")

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$specPath = Join-Path $WorkDir "launch_spec.json"
$resultPath = Join-Path $WorkDir "launch_result.json"
$stdoutPath = Join-Path $WorkDir "stdout.txt"
$stderrPath = Join-Path $WorkDir "stderr.txt"

$spec = Get-Content $specPath -Raw | ConvertFrom-Json

$launcherPath = [string]$spec.launcher_path
$argumentString = [string]$spec.arguments
$workingDirectory = if ($spec.working_directory) { [string]$spec.working_directory } else { Split-Path -Parent $launcherPath }
$timeoutSeconds = [int]$spec.timeout_seconds
$behavioralTracing = [bool]$spec.behavioral_tracing
$monitorDllPath = [string]$spec.monitor_dll_path
$monitorLoaderPath = [string]$spec.monitor_loader_path
$monitorPidFile = [string]$spec.monitor_pid_file

# WoW64: a 32-bit PE target needs the 32-bit monitor + loader (same PE-sniff
# logic as Invoke-SampleExecution in hyperv-vm.ps1 -- keep in sync).
$exeToRun = $launcherPath
$argsToRun = $argumentString
if ($behavioralTracing) {
    if (Test-Path $monitorPidFile) { Remove-Item -Path $monitorPidFile -Force -ErrorAction SilentlyContinue }
    $dllToUse = $monitorDllPath
    $loaderToUse = $monitorLoaderPath
    try {
        $fs = [System.IO.File]::OpenRead($launcherPath)
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek([int64]0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOff = $br.ReadInt32()
        $fs.Seek([int64]$peOff + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        $machine = $br.ReadUInt16()
        $br.Close(); $fs.Close()
        if ($machine -eq 0x14c) {  # IMAGE_FILE_MACHINE_I386
            $dll86 = $monitorDllPath -replace 'monitor_x64\.dll$', 'monitor_x86.dll'
            $ldr86 = $monitorLoaderPath -replace 'monitor_loader\.exe$', 'monitor_loader_x86.exe'
            if ((Test-Path $dll86) -and (Test-Path $ldr86)) {
                $dllToUse = $dll86
                $loaderToUse = $ldr86
            }
        }
    } catch { }
    $exeToRun = $loaderToUse
    $argsToRun = '"' + $dllToUse + '" "' + $launcherPath + '" ' + $argumentString
}

# The monitor loader reads MONITOR_PID_FILE from the ENVIRONMENT (mirrors
# Execute-Sample's $psi.EnvironmentVariables[...]); children inherit it.
if ($behavioralTracing -and $monitorPidFile) { $env:MONITOR_PID_FILE = $monitorPidFile }

# Start-Process (not Diagnostics.Process) so stdio redirects land in files we
# can read after exit; the loader forwards the sample's std handles, so both
# traced and untraced paths are captured the same way.
$spArgs = @{
    FilePath = $exeToRun
    WorkingDirectory = $workingDirectory
    RedirectStandardOutput = $stdoutPath
    RedirectStandardError = $stderrPath
    PassThru = $true
}
if ($argsToRun) { $spArgs["ArgumentList"] = $argsToRun }
$proc = Start-Process @spArgs

# Traced path: the loader publishes the REAL sample's pid to the pid file
# right after CreateProcess -- poll bounded, mirroring Execute-Sample.
$samplePid = $null
if ($behavioralTracing) {
    $wait = [System.Diagnostics.Stopwatch]::StartNew()
    while ($null -eq $samplePid -and $wait.Elapsed.TotalSeconds -lt 10) {
        if (Test-Path $monitorPidFile) {
            $raw = (Get-Content -Path $monitorPidFile -Raw -ErrorAction SilentlyContinue)
            $parsed = 0
            if ($raw -and [int]::TryParse($raw.Trim(), [ref]$parsed)) { $samplePid = $parsed }
        }
        if ($null -eq $samplePid) {
            if ($proc.HasExited) { break }
            Start-Sleep -Milliseconds 100
        }
    }
}

$timedOut = $false
$wait = [System.Diagnostics.Stopwatch]::StartNew()
while (-not $proc.HasExited) {
    if ($wait.Elapsed.TotalSeconds -ge $timeoutSeconds) { $timedOut = $true; break }
    Start-Sleep -Milliseconds 250
}
if ($timedOut) {
    # Kill the whole tree: the loader first, then the sample if published.
    try { taskkill /PID $proc.Id /T /F 2>$null | Out-Null } catch {}
    if ($null -ne $samplePid) { try { taskkill /PID $samplePid /T /F 2>$null | Out-Null } catch {} }
    try { $proc.WaitForExit(5000) } catch {}
} else {
    $proc.WaitForExit()
}

[PSCustomObject]@{
    Started                 = $true
    ProcessId               = if ($null -ne $samplePid) { $samplePid } else { $proc.Id }
    LauncherPid             = $proc.Id
    Path                    = $launcherPath
    ExitCode                = $proc.ExitCode
    TimedOut                = $timedOut
    BehavioralTracingActive = [bool]($behavioralTracing -and $null -ne $samplePid)
} | ConvertTo-Json -Compress | Set-Content -Path $resultPath -Encoding ascii
