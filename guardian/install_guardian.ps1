# install_guardian.ps1 -- provision SandboxGuard into the golden image (A3).
#
# Flow: restore golden snapshot -> boot -> enable testsigning + import test
# cert -> install driver to System32\drivers + auto-start service -> reboot
# -> verify (service running + probe PING) -> recapture the golden snapshot.
# Recapture happens ONLY when verification passes.
#
# Driven via POST /api/guardian/run?action=provision (or elevated directly):
#   powershell -ExecutionPolicy Bypass -File guardian\install_guardian.ps1

param(
    [string]$VMName = "",
    [string]$SnapshotName = "",
    # Fresh-image provisioning (no golden snapshot exists yet): skip the
    # initial restore and/or the final recapture; caller owns the snapshot.
    [switch]$NoRestore,
    [switch]$NoRecapture
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$hvScript = Join-Path $root "scripts\hyperv-vm.ps1"
$sys   = Join-Path $PSScriptRoot "out\x64\Release\SandboxGuard.sys"
$cer   = Join-Path $PSScriptRoot "out\SandboxGuardTest.cer"
$probe = Join-Path $PSScriptRoot "probe\guardian_probe.py"
$guestStage = "C:\SandboxAgent\guardian"
$driverDest = "C:\Windows\System32\drivers\SandboxGuard.sys"

$_cfgText = Get-Content (Join-Path $root "config\config.yaml") -Raw
if (-not $VMName)       { $VMName = ([regex]::Match($_cfgText, 'analysis_vm:\s*"([^"]+)"')).Groups[1].Value }
if (-not $SnapshotName) { $SnapshotName = ([regex]::Match($_cfgText, 'snapshot_name:\s*"([^"]+)"')).Groups[1].Value }
$_vmUser = ([regex]::Match($_cfgText, 'vm_username:\s*"([^"]+)"')).Groups[1].Value
$_vmPass = ([regex]::Match($_cfgText, 'vm_password:\s*"([^"]+)"')).Groups[1].Value
if (-not $VMName -or -not $_vmUser -or -not $_vmPass) { throw "config.yaml missing analysis_vm / vm credentials" }
$sec = ConvertTo-SecureString $_vmPass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($_vmUser, $sec)

foreach ($f in @($sys, $cer, $probe)) { if (-not (Test-Path $f)) { throw "missing: $f (run build+sign first)" } }

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

function Wait-GuestRebooted([datetime]$PreRebootBootTime, [int]$TimeoutSec = 300) {
    # Restart-Computer returns before the guest actually goes down; a plain
    # readiness wait can catch the PRE-reboot OS. Wait until the guest
    # reports a NEWER LastBootUpTime instead.
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $bt = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
                (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            } -ErrorAction Stop
            if ($bt -gt $PreRebootBootTime) { return }
        } catch { }
        Start-Sleep -Seconds 5
    }
    throw "guest did not come back with a new boot time within $TimeoutSec s"
}

function Invoke-Hv([string]$Command, [object[]]$Rest) {
    $out = & powershell.exe -ExecutionPolicy Bypass -File $hvScript $Command -VMName $VMName @Rest 2>&1 | Out-String
    Write-Host $out.Trim()
}

Write-Host "[provision] fast-path check: is the driver already verified in the current VM state?"
$alreadyProvisioned = $false
$vm = Get-VM -Name $VMName
if ($vm.State -ne "Off") {
    try {
        if ($vm.State -ne "Running") { Start-VM -Name $VMName }
        Wait-GuestReady -TimeoutSec 180
        $hostHash = (Get-FileHash $sys -Algorithm SHA256).Hash
        $quick = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
            param($stage, $driverDest, $hostHash)
            $svc = sc.exe query SandboxGuard 2>$null | Out-String
            $ping = "no probe"
            if (Test-Path "$stage\guardian_probe.py") {
                $ping = & C:\Python311\python.exe "$stage\guardian_probe.py" --rounds 1 2>&1 | Out-String
            }
            $guestHash = ""
            if (Test-Path $driverDest) { $guestHash = (Get-FileHash $driverDest -Algorithm SHA256).Hash }
            [PSCustomObject]@{ Service = $svc.Trim(); Ping = $ping.Trim(); HashMatch = ($guestHash -eq $hostHash) }
        } -ArgumentList $guestStage, $driverDest, $hostHash
        if ($quick.Service -match "RUNNING" -and $quick.Ping -match "PING ok" -and $quick.HashMatch) {
            $alreadyProvisioned = $true
            Write-Host "[provision] driver already installed + running + PING ok + hash match -- skipping to recapture"
        } else {
            Write-Host "[provision] fast-path mismatch (running=$($quick.Service -match 'RUNNING'), ping=$($quick.Ping -match 'PING ok'), hashMatch=$($quick.HashMatch)) -- full flow"
        }
    } catch {
        Write-Host "[provision] fast-path check failed ($_); running full flow"
    }
}

if (-not $alreadyProvisioned) {
if (-not $NoRestore) {
    Write-Host "[provision] restoring golden snapshot '$SnapshotName' on '$VMName'..."
    Invoke-Hv "Restore-Snapshot" @("-SnapshotName", $SnapshotName)
} else {
    Write-Host "[provision] -NoRestore: skipping snapshot restore (fresh-image provisioning)"
}
Write-Host "[provision] booting..."
Invoke-Hv "Start-VM" @("-TimeoutSeconds", "240")
Wait-GuestReady

Write-Host "[provision] copying driver + cert + probe to guest..."
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { param($d) New-Item -ItemType Directory -Force $d | Out-Null } -ArgumentList $guestStage
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { param($d) Remove-Item "$d\*" -Force -ErrorAction SilentlyContinue } -ArgumentList $guestStage
Copy-VMFile -VMName $VMName -SourcePath $cer -DestinationPath "$guestStage\SandboxGuardTest.cer" -CreateFullPath -FileSource Host
Copy-VMFile -VMName $VMName -SourcePath $sys -DestinationPath "$guestStage\SandboxGuard.sys" -CreateFullPath -FileSource Host
Copy-VMFile -VMName $VMName -SourcePath $probe -DestinationPath "$guestStage\guardian_probe.py" -CreateFullPath -FileSource Host

Write-Host "[provision] enabling testsigning, importing cert, installing driver (auto-start)..."
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    param($stage, $driverDest)
    bcdedit /set testsigning on | Out-String
    Import-Certificate -FilePath "$stage\SandboxGuardTest.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath "$stage\SandboxGuardTest.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    # Stop/delete BEFORE overwriting the .sys: a previously baked (running)
    # driver locks its own image file.
    sc.exe stop SandboxGuard 2>$null | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete SandboxGuard 2>$null | Out-Null
    Copy-Item "$stage\SandboxGuard.sys" $driverDest -Force
    sc.exe create SandboxGuard binPath= $driverDest type= kernel start= auto | Out-String
    "guest configured"
} -ArgumentList $guestStage, $driverDest

Write-Host "[provision] rebooting guest..."
$preBoot = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
}
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { Restart-Computer -Force } 2>$null
Wait-GuestRebooted -PreRebootBootTime $preBoot -TimeoutSec 300

Write-Host "[provision] verifying driver auto-start + PING handshake..."
$verify = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    param($stage)
    $svc = sc.exe query SandboxGuard | Out-String
    $ping = & C:\Python311\python.exe "$stage\guardian_probe.py" --rounds 1 2>&1 | Out-String
    [PSCustomObject]@{ Service = $svc.Trim(); Ping = $ping.Trim() }
} -ArgumentList $guestStage
Write-Host $verify.Service
Write-Host $verify.Ping

if ($verify.Service -notmatch "RUNNING" -or $verify.Ping -notmatch "PING ok") {
    throw "verification FAILED -- driver not running or PING failed. Snapshot NOT recaptured."
}
}

if (-not $NoRecapture) {
    Write-Host "[provision] verified. Recapturing golden snapshot '$SnapshotName'..."
    Invoke-Hv "Recapture-Snapshot" @("-SnapshotName", $SnapshotName)
    Write-Host "[provision] DONE -- SandboxGuard is baked into the golden image (testsigning + auto-start)."
} else {
    Write-Host "[provision] verified. -NoRecapture: snapshot capture left to caller."
}
