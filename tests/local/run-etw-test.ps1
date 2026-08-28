#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Runs the local ETW collector test in an elevated context.

.DESCRIPTION
    Kernel ETW providers require Administrator privileges. This script
    re-launches itself elevated if needed, then runs the dropper test
    through agent/windows/etw_collector.py.
#>

param(
    [string]$TestTarget = "tests\local\test-dropper.bat",
    [string]$Output = "logs\etw_test.jsonl"
)

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python = Join-Path $root ".venv\Scripts\python.exe"
$collector = Join-Path $root "agent\windows\etw_collector.py"
$summaryScript = Join-Path $root "tests\local\summarize-etw.py"
$target = Join-Path $root $TestTarget
$out = Join-Path $root $Output

if (-not (Test-Path $python)) {
    throw "Python not found at $python"
}
if (-not (Test-Path $collector)) {
    throw "Collector not found at $collector"
}
if (-not (Test-Path $target)) {
    throw "Test target not found at $target"
}

Write-Host "[*] Running ETW collector test"
Write-Host "    Target: $target"
Write-Host "    Output: $out"

& $python $collector $target

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Collector failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[*] Summary of captured events:"
& $python $summaryScript $out

$count = (Get-Content $out | Measure-Object -Line).Lines
Write-Host "[*] Total events captured: $count"
