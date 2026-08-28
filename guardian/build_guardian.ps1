# build_guardian.ps1 -- compile SandboxGuard.sys via the WDK's command-line
# MSBuild targets (no VS driver extension needed). Mirrors the spirit of
# scripts/build_monitor.ps1: build, then stage the artifact.
#
# Usage:  powershell -File guardian\build_guardian.ps1
# Output: guardian\out\x64\Release\SandboxGuard.sys

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $PSScriptRoot "SandboxGuard.vcxproj"

# --- locate msbuild via vswhere ---
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere not found at $vswhere" }
$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
if (-not $msbuild) { throw "MSBuild not found (need VS2022 with VC tools)" }
Write-Host "[build] msbuild: $msbuild"

# --- sanity: WDK CLI targets present ---
$wdkTargets = "C:\Program Files (x86)\Windows Kits\10\build\10.0.26100.0\WindowsDriver.Common.targets"
if (-not (Test-Path $wdkTargets)) { throw "WDK build targets missing: $wdkTargets (is the WDK installed?)" }

$outDir = Join-Path $PSScriptRoot "out"
Write-Host "[build] building SandboxGuard (Release|x64)..."
& $msbuild $proj /p:Configuration=Release /p:Platform=x64 /p:OutDir="$outDir\x64\Release\\" /v:minimal
if ($LASTEXITCODE -ne 0) { throw "msbuild failed ($LASTEXITCODE)" }

$sys = Join-Path $outDir "x64\Release\SandboxGuard.sys"
if (-not (Test-Path $sys)) { throw "expected output missing: $sys" }
Write-Host "[build] OK -> $sys ($((Get-Item $sys).Length) bytes)"
