#requires -RunAsAdministrator
<#
.SYNOPSIS
    Reproducible injection-harness test runner for the Hyper-V sandbox.

.DESCRIPTION
    - Re-builds InjectionHarness.exe from source.
    - Runs it inside the sandbox VM via the orchestrator executor.
    - Prints Sysmon event counts and EID 25 details.
    - Optionally compares the new report against a previous report.

.EXAMPLE
    .\scripts\run_injection_harness.ps1

.EXAMPLE
    .\scripts\run_injection_harness.ps1 -PreviousReport reports\<id>.json
#>
[CmdletBinding()]
param(
    [string]$VMName = "pentagramma",
    [string]$SnapshotName = "SANDBOX_READY",
    [int]$TimeoutSeconds = 120,
    [string]$PreviousReport = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$harnessDir = Join-Path $projectRoot "samples\InjectionHarness\InjectionHarness"
$reportsDir = Join-Path $projectRoot "reports"

function Write-Step([string]$msg) {
    Write-Host "[+] $msg" -ForegroundColor Cyan
}

Write-Step "Building InjectionHarness.exe ..."
$publishDir = Join-Path $harnessDir "bin\Release\net8.0\win-x64\publish"
if (Test-Path $publishDir) {
    Remove-Item $publishDir\InjectionHarness.exe -ErrorAction SilentlyContinue
}
Push-Location $harnessDir
try {
    & dotnet publish -r win-x64 -c Release `
        /p:PublishSingleFile=true `
        /p:SelfContained=true `
        --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
}
finally {
    Pop-Location
}

$samplePath = Join-Path $publishDir "InjectionHarness.exe"
if (-not (Test-Path $samplePath)) {
    throw "InjectionHarness.exe not found at $samplePath"
}

Write-Step "Running sandbox analysis (VM: $VMName, snapshot: $SnapshotName) ..."
$runPy = @"
from pathlib import Path
from orchestrator.config import get_config
from orchestrator.executor import SandboxExecutor

cfg = get_config()
report = SandboxExecutor(cfg).run_analysis(
    sample_path=r'$samplePath',
    arguments='',
    timeout_seconds=$TimeoutSeconds
)
print(report['analysis_id'])
"@

$analysisId = & $venvPython -c $runPy
if ($LASTEXITCODE -ne 0) { throw "Sandbox analysis failed" }

$reportPath = Join-Path $reportsDir "$analysisId.json"
if (-not (Test-Path $reportPath)) {
    throw "Report not found: $reportPath"
}

Write-Step "Analysis complete: $analysisId"

$report = Get-Content $reportPath -Raw | ConvertFrom-Json

if ($report.execution_info) {
    Write-Host "`n=== Sample Execution ===" -ForegroundColor Green
    if ($report.execution_info.Stdout) {
        Write-Host "--- stdout ---"
        Write-Host $report.execution_info.Stdout
    }
    if ($report.execution_info.Stderr) {
        Write-Host "--- stderr ---"
        Write-Host $report.execution_info.Stderr
    }
    if ($report.execution_info.TimedOut) {
        Write-Host "WARNING: sample timed out" -ForegroundColor Red
    }
}

Write-Host "`n=== Event Summary ===" -ForegroundColor Green
Write-Host "Total events  : $($report.summary.total_events)"
Write-Host "Alert count   : $($report.summary.alert_count)"
Write-Host ""
Write-Host "Event counts:" -ForegroundColor Green
$report.summary.event_counts | ConvertTo-Json | Write-Host

$eid25 = $report.alerts | Where-Object { $_.event_id -eq 25 }
Write-Host "`nEID 25 (ProcessTampering) count: $($eid25.Count)" -ForegroundColor Green
if ($eid25) {
    $eid25 | ForEach-Object {
        Write-Host "  - Time=$($_.data.UtcTime) Image=$($_.data.Image) Type=$($_.data.Type) PID=$($_.data.ProcessId)"
    }
}

if ($PreviousReport -and (Test-Path $PreviousReport)) {
    Write-Step "Comparing with previous report: $PreviousReport"
    & $venvPython (Join-Path $projectRoot "scripts\compare_reports.py") $PreviousReport $reportPath
    if ($LASTEXITCODE -ne 0) { throw "Report comparison failed" }
}

Write-Host "`nReport path: $reportPath" -ForegroundColor Yellow
