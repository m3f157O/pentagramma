# provision_golden_image.ps1 -- turn a CLEAN pre-existing VM into the golden
# analysis image and capture the SANDBOX_READY snapshot.
#
# Manual prerequisites (NOT automated by this script):
#   - VM already exists (Gen 2, >= 4 GB RAM / 4 vCPU, Default Switch) with
#     Windows installed and updated. This script NEVER creates VMs.
#   - Guest user per config.yaml (vm_username/vm_password) exists, is a local
#     admin, and autologon is configured.
#   - PowerShell Direct works from this elevated host.
#   - WDAC / Code-Integrity policy: the current golden image enforces one
#     (see README) but no policy artifact exists in this repo -- apply it
#     MANUALLY before running, if wanted. The script only warns.
#
# Everything else is automated and verify-gated: guest Python 3.11 (via
# -PythonInstaller), agent deploy, pip deps, Sysmon, audit policy + PS logging
# (Telemetry-Init), environment dressing, Defender state, SandboxGuard driver
# (via guardian\install_guardian.ps1 -NoRestore -NoRecapture). The snapshot is
# captured ONLY if every verification passes.
#
# Usage (elevated):
#   powershell -ExecutionPolicy Bypass -File scripts\provision_golden_image.ps1 `
#       -PythonInstaller C:\path\python-3.11.9-amd64.exe
#
#   # re-bake an already-provisioned VM (snapshot exists):
#   ... -Force

param(
    [string]$VMName = "",
    [string]$SnapshotName = "",
    [string]$PythonInstaller = "",
    [switch]$SkipPython,
    [switch]$SkipDressing,
    [switch]$SkipGuardian,
    # Default posture (per README): Defender ON as AMSI provider. This switch
    # disables it instead (verify-gated, Tamper Protection may block).
    [switch]$DefenderOff,
    # Allow recapturing when the snapshot already exists.
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$hvScript = Join-Path $root "scripts\hyperv-vm.ps1"
$guardianInstall = Join-Path $root "guardian\install_guardian.ps1"
$guestPython = "C:\Python311\python.exe"
$guestAgentDir = "C:\SandboxAgent"

# --- config.yaml (same regex pattern as guardian\install_guardian.ps1) -------
$_cfgText = Get-Content (Join-Path $root "config\config.yaml") -Raw
if (-not $VMName)       { $VMName = ([regex]::Match($_cfgText, 'analysis_vm:\s*"([^"]+)"')).Groups[1].Value }
if (-not $SnapshotName) { $SnapshotName = ([regex]::Match($_cfgText, 'snapshot_name:\s*"([^"]+)"')).Groups[1].Value }
$_vmUser = ([regex]::Match($_cfgText, 'vm_username:\s*"([^"]+)"')).Groups[1].Value
$_vmPass = ([regex]::Match($_cfgText, 'vm_password:\s*"([^"]+)"')).Groups[1].Value
if (-not $VMName -or -not $SnapshotName -or -not $_vmUser -or -not $_vmPass) {
    throw "config.yaml missing analysis_vm / snapshot_name / vm credentials"
}
$sec = ConvertTo-SecureString $_vmPass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($_vmUser, $sec)

# --- helpers ------------------------------------------------------------------
function Wait-GuestReady([int]$TimeoutSec = 300) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { "ok" } -ErrorAction Stop
            if ($r -eq "ok") { return }
        } catch { Start-Sleep -Seconds 5 }
    }
    throw "guest did not become ready within $TimeoutSec s"
}

# hyperv-vm.ps1 commands that take guest credentials
$script:GuestCommands = @("Copy-Agent", "Invoke-GuestPython", "Telemetry-Init", "Restart-Guest")

function Invoke-Hv([string]$Command, [object[]]$Rest = @()) {
    $args2 = @("-ExecutionPolicy", "Bypass", "-File", $hvScript, $Command, "-VMName", $VMName) + $Rest
    if ($script:GuestCommands -contains $Command) {
        $args2 += @("-CredentialUsername", $_vmUser, "-CredentialPassword", $_vmPass)
    }
    $out = & powershell.exe @args2 2>&1 | Out-String
    Write-Host $out.Trim()
    if ($LASTEXITCODE -ne 0) { throw "hyperv-vm.ps1 $Command failed (exit $LASTEXITCODE)" }
    return $out.Trim()
}

function Invoke-HvJson([string]$Command, [object[]]$Rest = @()) {
    $raw = Invoke-Hv $Command $Rest
    try { return ($raw | ConvertFrom-Json) } catch { throw "$Command did not return JSON: $raw" }
}

function Invoke-Guest([scriptblock]$Script, [object[]]$ArgumentList = @()) {
    return Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script -ArgumentList $ArgumentList -ErrorAction Stop
}

function Test-GuestPython {
    try {
        $v = Invoke-Guest { & C:\Python311\python.exe --version 2>&1 | Out-String }
        return ($v -match "Python 3\.11")
    } catch { return $false }
}

$script:Step = 0
function Step([string]$Name) {
    $script:Step++
    Write-Host ""
    Write-Host "=== [step $($script:Step)] $Name ==="
}

# --- [step 0] preflight --------------------------------------------------------
Step "preflight"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "must run elevated (Hyper-V + PowerShell Direct require admin)"
}
$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if (-not $vm) { throw "VM '$VMName' does not exist. Create + install Windows manually first." }
if ($PythonInstaller -and -not (Test-Path $PythonInstaller)) { throw "PythonInstaller not found: $PythonInstaller" }
if (-not $SkipGuardian) {
    foreach ($f in @("guardian\out\x64\Release\SandboxGuard.sys", "guardian\out\SandboxGuardTest.cer", "guardian\probe\guardian_probe.py")) {
        if (-not (Test-Path (Join-Path $root $f))) { throw "missing: $f (build guardian first, or use -SkipGuardian)" }
    }
}
$snaps = Get-VMSnapshot -VMName $VMName -ErrorAction SilentlyContinue
if ($snaps) { Write-Warning "VM '$VMName' already has $($snaps.Count) snapshot(s) -- expected none on a clean VM." }
Write-Warning "MANUAL CHECKLIST (not automated): WDAC/Code-Integrity policy, Windows activated+updated, autologon as '$_vmUser', integration services enabled."

# --- boot ----------------------------------------------------------------------
Step "boot VM + wait for PowerShell Direct"
Invoke-Hv "Start-VM" @("-TimeoutSeconds", "240") | Out-Null
Wait-GuestReady

# --- guest Python 3.11 ---------------------------------------------------------
if (-not $SkipPython) {
    Step "guest Python 3.11 (C:\Python311)"
    if (Test-GuestPython) {
        Write-Host "[python] already present -- skipping install"
    } else {
        if (-not $PythonInstaller) { throw "guest Python 3.11 missing and no -PythonInstaller given. Download python-3.11.x-amd64.exe from python.org and pass it." }
        Write-Host "[python] copying installer into guest..."
        Invoke-Guest { param($d) New-Item -ItemType Directory -Force $d | Out-Null } @("C:\Sandbox") | Out-Null
        Copy-VMFile -VMName $VMName -SourcePath $PythonInstaller -DestinationPath "C:\Sandbox\python-installer.exe" -CreateFullPath -FileSource Host -Force
        Write-Host "[python] silent install (can take several minutes)..."
        $rc = Invoke-Guest {
            $p = Start-Process -Wait -PassThru -FilePath "C:\Sandbox\python-installer.exe" -ArgumentList "/quiet","InstallAllUsers=1","TargetDir=C:\Python311","PrependPath=0","Include_test=0","Include_launcher=0"
            $p.ExitCode
        }
        if ($rc -ne 0) { throw "python installer exited with $rc" }
        if (-not (Test-GuestPython)) { throw "python still not callable at C:\Python311 after install" }
        Write-Host "[python] installed + verified"
    }
}

# --- agent deploy --------------------------------------------------------------
Step "deploy agent to $guestAgentDir"
Invoke-Hv "Copy-Agent" @("-AgentSourceDir", (Join-Path $root "agent\windows")) | Out-Null

# --- pip dependencies ------------------------------------------------------------
if (-not $SkipPython) {
    Step "pip install agent requirements (needs guest network via Default Switch)"
    $pip = Invoke-Guest {
        & C:\Python311\python.exe -m pip install -r "C:\SandboxAgent\requirements.txt" 2>&1 | Out-String
        "PIP_EXIT=$LASTEXITCODE"
    }
    Write-Host ($pip | Out-String).Trim()
    if (($pip | Out-String) -notmatch "PIP_EXIT=0") { throw "pip install failed -- check guest network (Default Switch NAT) and rerun" }
}

# --- Sysmon ----------------------------------------------------------------------
Step "Sysmon install/ensure + verify"
$r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "sysmon_manager.py", "-ScriptArgs", "ensure")
if ($r.ExitCode -ne 0) { throw "sysmon ensure failed: $($r.Output)" }
$r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "sysmon_manager.py", "-ScriptArgs", "status")
if ($r.Output -notmatch "running" -or $r.Output -match "not running") { throw "sysmon not running after ensure: $($r.Output)" }

# --- audit policy + PowerShell logging ------------------------------------------
Step "Telemetry-Init (security audit policy + PS script-block logging)"
Invoke-Hv "Telemetry-Init" @() | Out-Null

# --- environment dressing ---------------------------------------------------------
if (-not $SkipDressing) {
    Step "environment dressing (decoy files, browser history, MRU)"
    $r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "apply_dressing.py", "-ScriptArgs", "apply")
    if ($r.ExitCode -ne 0) { throw "dressing apply failed: $($r.Output)" }
    $r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "apply_dressing.py", "-ScriptArgs", "verify")
    if ($r.ExitCode -ne 0) { throw "dressing verify failed: $($r.Output)" }
}

# --- Defender ---------------------------------------------------------------------
Step "Defender posture"
$r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "defender_manager.py", "-ScriptArgs", "status")
if ($DefenderOff) {
    $r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "defender_manager.py", "-ScriptArgs", "disable")
    Invoke-Hv "Restart-Guest" @() | Out-Null
    Wait-GuestReady
    $r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "defender_manager.py", "-ScriptArgs", "verify")
    if ($r.ExitCode -ne 0) { throw "defender still ON after disable -- Tamper Protection likely blocks it; disable Tamper Protection manually in the guest UI, then rerun. $($r.Output)" }
} else {
    $r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "defender_manager.py", "-ScriptArgs", "verify-on")
    if ($r.ExitCode -ne 0) { Write-Warning "Defender real-time protection is OFF (README posture: ON as AMSI provider). Rerun with -DefenderOff if intentional." }
}

# --- SandboxGuard kernel driver ------------------------------------------------------
if (-not $SkipGuardian) {
    Step "SandboxGuard driver (testsigning + auto-start, verify-gated)"
    & powershell.exe -ExecutionPolicy Bypass -File $guardianInstall -VMName $VMName -SnapshotName $SnapshotName -NoRestore -NoRecapture
    if ($LASTEXITCODE -ne 0) { throw "guardian install failed (exit $LASTEXITCODE)" }
    Wait-GuestReady
}

# --- final verification sweep ---------------------------------------------------------
Step "final verification sweep"
$failures = @()
try { Wait-GuestReady -TimeoutSec 60 } catch { $failures += "PSDirect not responsive" }
if (-not $SkipPython -and -not (Test-GuestPython)) { $failures += "guest python broken" }
$r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "sysmon_manager.py", "-ScriptArgs", "status")
if ($r.Output -notmatch "running" -or $r.Output -match "not running") { $failures += "sysmon not running" }
if (-not $SkipDressing) {
    $r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "apply_dressing.py", "-ScriptArgs", "verify")
    if ($r.ExitCode -ne 0) { $failures += "dressing verify failed" }
}
if (-not $DefenderOff) {
    $r = Invoke-HvJson "Invoke-GuestPython" @("-ScriptName", "defender_manager.py", "-ScriptArgs", "verify-on")
    if ($r.ExitCode -ne 0) { Write-Warning "defender OFF at sweep (see earlier warning)" }
}
if (-not $SkipGuardian) {
    $svc = Invoke-Guest { sc.exe query SandboxGuard | Out-String }
    if ($svc -notmatch "RUNNING") { $failures += "SandboxGuard service not running" }
}
$archive = Invoke-Guest { Test-Path "C:\SandboxArchive" }
if (-not $archive) { $failures += "C:\SandboxArchive missing (Sysmon ArchiveDirectory)" }
if ($failures.Count -gt 0) { throw "verification sweep FAILED -- snapshot NOT captured:`n - $($failures -join "`n - ")" }

# --- snapshot ---------------------------------------------------------------------------
Step "capture golden snapshot '$SnapshotName'"
$existing = Get-VMSnapshot -VMName $VMName -Name $SnapshotName -ErrorAction SilentlyContinue
if ($existing -and -not $Force) {
    throw "snapshot '$SnapshotName' already exists on '$VMName'. Rerun with -Force to recapture."
}
if ($existing) {
    Invoke-Hv "Recapture-Snapshot" @("-SnapshotName", $SnapshotName) | Out-Null
    Write-Host "[snapshot] recaptured '$SnapshotName'"
} else {
    Invoke-Hv "Ensure-Snapshot" @("-SnapshotName", $SnapshotName) | Out-Null
    Write-Host "[snapshot] captured '$SnapshotName'"
}

Write-Host ""
Write-Host "=== DONE: '$VMName' is a golden image. Next: run the benign canary via the orchestrator to validate end-to-end. ==="
