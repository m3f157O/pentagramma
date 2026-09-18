# package_local.ps1 -- build the standalone local-mode package zip.
#
# Stages everything install_local.ps1 + the orchestrator need into
# out\pentagramma-local\ and zips it. config.yaml is templated: every
# absolute repo path becomes __ROOT__\<...>, which install_local.ps1's
# config step (or first run) must substitute with the extracted package
# root.
#
#   powershell -ExecutionPolicy Bypass -File scripts\package_local.ps1 [-OutZip path]
#
# Rule packs (sigma/yara/capa/cape) are vendored as-is -- they are the bulk
# of the size but make the package fully self-contained.

param(
    [string]$OutZip = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$stage = Join-Path $root "out\pentagramma-local"
if (-not $OutZip) { $OutZip = Join-Path $root "out\pentagramma-local.zip" }

if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$includes = @(
    "orchestrator",
    "agent",
    "scripts",
    "config",
    "sigma_rules",
    "sigma_rules_custom",
    "yara",
    "yara_rules",
    "capa_rules",
    "capa_sigs",
    "cape_signatures",
    "schemas",
    "requirements.txt",
    "start.ps1",
    "README.md"
)
foreach ($item in $includes) {
    $src = Join-Path $root $item
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $stage $item) -Recurse -Force
    } else {
        Write-Host "note: skipped missing $item"
    }
}

# Guardian driver binaries (if built) -- installer degrades gracefully without them
$guardianOut = Join-Path $root "guardian\out"
if (Test-Path $guardianOut) {
    New-Item -ItemType Directory -Path (Join-Path $stage "guardian\out") -Force | Out-Null
    Copy-Item $guardianOut (Join-Path $stage "guardian\out") -Recurse -Force
}

# Runtime dirs (empty)
foreach ($d in @("reports", "logs", "samples")) {
    New-Item -ItemType Directory -Path (Join-Path $stage $d) -Force | Out-Null
}

# Template the config: absolute repo paths -> __ROOT__ placeholder
$cfgPath = Join-Path $stage "config\config.yaml"
$cfgText = Get-Content $cfgPath -Raw
$escapedRoot = [regex]::Escape($root)
$cfgText = $cfgText -replace $escapedRoot, "__ROOT__"
Set-Content $cfgPath $cfgText -Encoding UTF8

if (Test-Path $OutZip) { Remove-Item $OutZip -Force }
Compress-Archive -Path "$stage\*" -DestinationPath $OutZip -CompressionLevel Optimal
$sizeMB = [math]::Round((Get-Item $OutZip).Length / 1MB, 1)
Write-Host "package: $OutZip ($sizeMB MB)"
Write-Host "deploy: extract, then run scripts\install_local.ps1 elevated."
