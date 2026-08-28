# Build the sandbox behavioral monitor (Track 3) and stage the binaries into
# agent/windows/ for guest deployment -- they ship prebuilt there, exactly like
# Sysmon64.exe (no per-run build in the guest).
#
#   pwsh scripts/build_monitor.ps1
#   pwsh scripts/build_monitor.ps1 -Config Debug
#
# Requires Visual Studio 2022 (VC++ x64 tools) + CMake on PATH. Produces
# monitor_x64.dll and monitor_loader.exe.
#
# NOTE on -BuildDir: MSBuild's C/C++ file tracker writes .tlog paths that
# overflow Windows' 260-char MAX_PATH when the build dir is deeply nested (it
# fails configure with MSB6003). Keep the build dir SHORT -- the default below
# is intentional. Do not point it inside a deep temp/scratch tree.
param(
    [string]$BuildDir = "C:\Users\giammy\mb",
    [string]$Config = "Release"
)
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot           # repo root (scripts/..)
$src  = Join-Path $root "agent\windows\monitor_src"
$dest = Join-Path $root "agent\windows"

foreach ($arch in @("x64", "Win32")) {
    $bd = "$BuildDir-$arch"
    Write-Host "Configuring $arch ($src -> $bd)..."
    cmake -G "Visual Studio 17 2022" -A $arch -S $src -B $bd
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($arch)" }

    Write-Host "Building $arch ($Config)..."
    cmake --build $bd --config $Config
    if ($LASTEXITCODE -ne 0) { throw "cmake build failed ($arch)" }
}

foreach ($bin in @("monitor_x64.dll", "monitor_loader.exe", "monitor_x86.dll", "monitor_loader_x86.exe")) {
    $archDir = if ($bin -match "x86") { "$BuildDir-Win32" } else { "$BuildDir-x64" }
    Copy-Item (Join-Path $archDir "$Config\$bin") $dest -Force
    Write-Host "  staged $bin -> $dest"
}
Write-Host "Done."
