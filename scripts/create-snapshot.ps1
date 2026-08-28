#!/usr/bin/env pwsh
# One-time helper: ensure the clean snapshot exists for the analysis VM.
# Run this after manually preparing the VM (EDR agent auto-start, network, etc.).

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$rootDir = Split-Path -Parent $scriptDir
$helper = Join-Path $scriptDir "hyperv-vm.ps1"

# Read VM name from config.yaml
$configPath = Join-Path $rootDir "config\config.yaml"
if (-not (Test-Path $configPath)) {
    throw "Config file not found: $configPath"
}

$yaml = Get-Content -Raw $configPath
# Simple regex extraction; avoids requiring a YAML parser
$vmNameMatch = [regex]::Match($yaml, 'analysis_vm:\s*"?([^\r\n"]+)"?')
if (-not $vmNameMatch.Success) {
    throw "Could not find 'analysis_vm' in $configPath"
}
$vmName = $vmNameMatch.Groups[1].Value.Trim()

$snapshotMatch = [regex]::Match($yaml, 'snapshot_name:\s*"?([^\r\n"]+)"?')
$snapshotName = if ($snapshotMatch.Success) { $snapshotMatch.Groups[1].Value.Trim() } else { "SANDBOX-CLEAN" }

Write-Host "Ensuring snapshot '$snapshotName' for VM '$vmName'..."
& powershell.exe -ExecutionPolicy Bypass -File $helper Ensure-Snapshot -VMName $vmName -SnapshotName $snapshotName
Write-Host "Snapshot created/verified."
