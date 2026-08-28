#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Runs the local Sysmon telemetry test.

.DESCRIPTION
    Ensures Sysmon is installed, runs the benign dropper, then queries
    Sysmon events and prints a summary.
#>

param(
    [string]$TestTarget = "tests\local\test-dropper.bat",
    [string]$Output = "logs\sysmon_test.jsonl"
)

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python = Join-Path $root ".venv\Scripts\python.exe"
$sysmonManager = Join-Path $root "agent\windows\sysmon_manager.py"
$sysmonParser = Join-Path $root "agent\windows\sysmon_parser.py"
$summarize = Join-Path $root "tests\local\summarize-sysmon.py"
$target = Join-Path $root $TestTarget
$out = Join-Path $root $Output

if (-not (Test-Path $python)) { throw "Python not found at $python" }
if (-not (Test-Path $sysmonManager)) { throw "Sysmon manager not found" }
if (-not (Test-Path $sysmonParser)) { throw "Sysmon parser not found" }
if (-not (Test-Path $target)) { throw "Test target not found at $target" }

# Check Sysmon binary is present
$sysmonExe = Join-Path $root "agent\windows\Sysmon64.exe"
if (-not (Test-Path $sysmonExe)) {
    Write-Host "[!] Sysmon64.exe not found at $sysmonExe" -ForegroundColor Red
    Write-Host "    Download Sysmon from: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"
    Write-Host "    Place Sysmon64.exe in agent\windows\ and rerun."
    exit 1
}

Write-Host "[*] Ensuring Sysmon is installed and running"
& $python $sysmonManager ensure
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[*] Running test target: $target"
& $target
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Test target failed with exit code $LASTEXITCODE" -ForegroundColor Red
}

Write-Host "[*] Waiting 3 seconds for Sysmon to flush events"
Start-Sleep -Seconds 3

Write-Host "[*] Querying Sysmon events"
& $python $sysmonParser
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[*] Summary"
& $python $summarize $out

$count = (Get-Content $out | Measure-Object -Line).Lines
Write-Host "[*] Total Sysmon events captured: $count"
