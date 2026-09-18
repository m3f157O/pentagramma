# install_local.ps1 -- standalone "local mode" installer (docs/local-mode.md).
#
# Turns the machine it runs on into the analysis environment: the
# orchestrator (this repo/package) then detonates samples LOCALLY instead of
# in the Hyper-V VM. For expert operators inside their own disposable VM --
# there is NO snapshot rollback in local mode.
#
# Idempotent; safe to re-run. Elevated required.
#
#   powershell -ExecutionPolicy Bypass -File scripts\install_local.ps1
#     [-KeepDefender] [-SkipGuardian] [-NoAutostart]
#
# What it does:
#   1. Prereq checks (admin, Windows 10+, Python 3.11+ discoverable).
#   2. Deploys the agent to C:\SandboxAgent (preserving an existing .venv),
#      creates C:\Sandbox; installs agent python deps (vendored pywintrace).
#   3. Secure Boot check -> Guardian kernel driver:
#        - Secure Boot ON : driver cannot load (test-signed) -> guardian
#          disabled in config, reason recorded. Everything else still works.
#        - Secure Boot OFF: testsigning enabled, test cert imported, driver
#          installed + auto-start service (needs one reboot if testsigning
#          was just flipped).
#   4. Defender real-time protection disabled (samples must run to
#      completion; our own telemetry does the observing). -KeepDefender skips.
#   5. Writes sandbox.mode=local into config\config.yaml (backing up the
#      original once).
#   6. Optionally registers an elevated orchestrator autostart scheduled task.
#
# Sysmon needs NO explicit install here: telemetry init installs/updates it
# per run from the bundled Sysmon64.exe + sysmonconfig.xml.

#requires -RunAsAdministrator
param(
    [string]$PackageRoot = "",     # repo/package root; default: parent of this script
    [switch]$KeepDefender,
    [switch]$SkipGuardian,
    [switch]$NoAutostart
)

$ErrorActionPreference = "Stop"

if (-not $PackageRoot) { $PackageRoot = Split-Path -Parent $PSScriptRoot }
$PackageRoot = (Resolve-Path $PackageRoot).Path
$agentSrc  = Join-Path $PackageRoot "agent\windows"
$agentDest = "C:\SandboxAgent"
$sandboxDir = "C:\Sandbox"
$configPath = Join-Path $PackageRoot "config\config.yaml"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# --- 1. prereqs -------------------------------------------------------------
Step "Prerequisites"
$os = Get-CimInstance Win32_OperatingSystem
if ([int]$os.BuildNumber -lt 19041) { throw "Windows 10 2004+ required (build $($os.BuildNumber))" }
Write-Host "OS: $($os.Caption) build $($os.BuildNumber)"

$python = $null
foreach ($cand in @("C:\Python311\python.exe", (Get-Command python.exe -ErrorAction SilentlyContinue).Source)) {
    if ($cand -and (Test-Path $cand)) {
        $ver = & $cand -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver -and [version]$ver -ge [version]"3.11") { $python = $cand; break }
    }
}
if (-not $python) { throw "Python 3.11+ not found. Install python.org 3.11 (NOT the Store alias) or place it at C:\Python311." }
Write-Host "Python: $python"

foreach ($req in @($agentSrc, (Join-Path $PackageRoot "orchestrator"), (Join-Path $PackageRoot "scripts\hyperv-vm.ps1"), $configPath)) {
    if (-not (Test-Path $req)) { throw "package incomplete -- missing: $req" }
}

# --- 2. agent + dirs ----------------------------------------------------------
Step "Deploying agent to $agentDest"
$venvBackup = $null
if (Test-Path "$agentDest\.venv") {
    $venvBackup = Join-Path $env:TEMP "SandboxAgent_venv_backup"
    if (Test-Path $venvBackup) { Remove-Item $venvBackup -Recurse -Force }
    Move-Item "$agentDest\.venv" $venvBackup
}
if (Test-Path $agentDest) { Remove-Item $agentDest -Recurse -Force }
Copy-Item $agentSrc $agentDest -Recurse -Force
if ($venvBackup) { Move-Item $venvBackup "$agentDest\.venv"; $venvBackup = $null }
New-Item -ItemType Directory -Path $sandboxDir -Force | Out-Null
New-Item -ItemType Directory -Path "$agentDest\dumps" -Force | Out-Null
Write-Host "agent deployed ($( @(Get-ChildItem $agentDest -File).Count ) files)"

# Agent python deps: vendored pywintrace (no network needed)
$vendorWhl = Get-ChildItem "$agentDest\vendor\*.whl" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($vendorWhl) {
    & $python -m pip install --no-index --find-links="$agentDest\vendor" pywintrace 2>&1 | Select-Object -Last 1
} else {
    Write-Host "note: no vendored wheels found; ETW collectors needing pywintrace will no-op"
}

# Orchestrator python deps (the machine runs the orchestrator too)
$reqTxt = Join-Path $PackageRoot "requirements.txt"
if (Test-Path $reqTxt) {
    Step "Orchestrator python deps"
    & $python -m pip install -r $reqTxt 2>&1 | Select-Object -Last 2
}

# --- 3. Secure Boot -> Guardian ---------------------------------------------
Step "Guardian kernel driver"
$secureBoot = $false
try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $secureBoot = $false }
$guardianEnabled = $false
$guardianReason = ""

if ($SkipGuardian) {
    $guardianReason = "skipped_by_operator"
    Write-Host "skipped (-SkipGuardian)"
} elseif ($secureBoot) {
    $guardianReason = "secure_boot"
    Write-Host "Secure Boot is ON -- the test-signed driver cannot load. Guardian DISABLED (the pipeline treats it as optional; you lose kernel placement + self-defense, not detection)."
} else {
    $sys  = Join-Path $PackageRoot "guardian\out\x64\Release\SandboxGuard.sys"
    $cer  = Join-Path $PackageRoot "guardian\out\SandboxGuardTest.cer"
    if (-not (Test-Path $sys) -or -not (Test-Path $cer)) {
        $guardianReason = "driver_not_built"
        Write-Host "driver binaries not found ($sys) -- build first (guardian\build_guardian.ps1) or re-run with -SkipGuardian. Guardian DISABLED."
    } else {
        $testSigning = (bcdedit /enum "{current}" | Out-String) -match 'testsigning\s+Yes'
        if (-not $testSigning) {
            bcdedit /set testsigning on | Out-Null
            Write-Host "testsigning ENABLED -- a REBOOT is required before the driver can load"
            $guardianReason = "testsigning_pending_reboot"
        }
        certutil -addstore -f Root $cer | Out-Null
        certutil -addstore -f TrustedPublisher $cer | Out-Null
        Copy-Item $sys "C:\Windows\System32\drivers\SandboxGuard.sys" -Force
        sc.exe create SandboxGuard type= kernel start= auto binPath= "C:\Windows\System32\drivers\SandboxGuard.sys" | Out-Null
        if ($testSigning) {
            sc.exe start SandboxGuard | Out-Null
            $guardianEnabled = $true
            Write-Host "driver installed and started"
        } else {
            Write-Host "driver installed; will load after the testsigning reboot"
        }
    }
}

# --- 4. Defender ---------------------------------------------------------------
Step "Defender real-time protection"
if ($KeepDefender) {
    Write-Host "kept ON (-KeepDefender) -- note: samples may be killed mid-run and detection gaps ensue"
} else {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Write-Host "real-time monitoring disabled (analysis box profile)"
}

# --- 5. Config -----------------------------------------------------------------
Step "Config"
if (-not (Test-Path "$configPath.bak")) { Copy-Item $configPath "$configPath.bak" }
$cfgText = Get-Content $configPath -Raw
# Packaged configs carry __ROOT__ placeholders for the install location
# (scripts/package_local.ps1); the repo's own config has absolute paths
# already and is unaffected by this substitution.
$cfgText = $cfgText.Replace('__ROOT__', $PackageRoot)
if ($cfgText -match '(?ms)^sandbox:\s*\r?\n\s*mode:\s*\S+') {
    $cfgText = $cfgText -replace '(?ms)^(sandbox:\s*\r?\n\s*mode:\s*)\S+', "`${1}local"
} else {
    $cfgText = "sandbox:`n  mode: local`n`n" + $cfgText
}
if ($guardianReason) {
    $cfgText = $cfgText -replace '(?ms)^(guardian:\s*\r?\n\s*enabled:\s*)\S+', "`${1}false"
}
Set-Content $configPath $cfgText -Encoding UTF8
Write-Host "sandbox.mode=local written$(if ($guardianReason) { " (guardian.enabled=false: $guardianReason)" })"

# --- 6. Autostart (optional) ---------------------------------------------------
if (-not $NoAutostart) {
    Step "Orchestrator autostart"
    $startPs1 = Join-Path $PackageRoot "start.ps1"
    if (Test-Path $startPs1) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$startPs1`"" -WorkingDirectory $PackageRoot
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName 'PentagrammaOrchestrator' -Action $action -Principal $principal -Force | Out-Null
        Write-Host "scheduled task 'PentagrammaOrchestrator' registered (run at startup: enable manually if desired)"
    }
}

Step "Done"
$startScript = Join-Path $PackageRoot 'start.ps1'
$rebootNote = if ($guardianReason -eq 'testsigning_pending_reboot') { "`n!! REBOOT REQUIRED for the Guardian driver (testsigning just enabled) !!" } else { '' }
$guardianNote = if ($guardianReason -eq 'secure_boot') { "`nGuardian: disabled (Secure Boot on). Optional -- detection works without it." } else { '' }
Write-Host "Local mode installed. Start the orchestrator elevated:`n  powershell -ExecutionPolicy Bypass -File '$startScript'`nThen open http://127.0.0.1:18000 -- the dashboard shows 'mode: local'.$rebootNote$guardianNote"
