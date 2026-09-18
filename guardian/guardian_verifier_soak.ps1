# guardian_verifier_soak.ps1 -- A4: run the A1a functional battery with Driver
# Verifier (standard flags) watching SandboxGuard.sys.
#
# Verifier is NOT baked into the golden snapshot: this script enables it at
# runtime, reboots (verifier only engages at boot), soaks, then restores the
# golden snapshot at the end so normal runs stay verifier-free.
#
# A verifier-detected violation (bad IRQL, pool corruption, ...) bugchecks the
# guest (0xC4 ...) -- that surfaces as the guest not coming back / Invoke-
# Command failing, i.e. this script throwing and the job failing. Reaching the
# end with all checks green means the driver survived standard verification.
#
# Usage (elevated host PowerShell; normally via POST /api/guardian/run?action=verifier-soak):
#   powershell -ExecutionPolicy Bypass -File guardian\guardian_verifier_soak.ps1

param(
    [string]$VMName = "pentagramma",
    [string]$SnapshotName = "SANDBOX_READY"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$hvScript = Join-Path $root "scripts\hyperv-vm.ps1"
$a1Script = Join-Path $PSScriptRoot "guardian_a1_test.ps1"
$probe = Join-Path $PSScriptRoot "probe\guardian_probe.py"
$guestStage = "C:\SandboxAgent\guardian"

# Guest creds from config\config.yaml (gitignored).
$_cfgText = Get-Content (Join-Path $root "config\config.yaml") -Raw
$_vmUser = ([regex]::Match($_cfgText, 'username:\s*"([^"]+)"')).Groups[1].Value
$_vmPass = ([regex]::Match($_cfgText, 'password:\s*"([^"]+)"')).Groups[1].Value
if (-not $_vmUser -or -not $_vmPass) { throw "credentials not found in config\config.yaml (hyperv.vms list)" }
$sec = ConvertTo-SecureString $_vmPass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($_vmUser, $sec)

function Wait-GuestReady([int]$TimeoutSec = 180) {
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
    # Restart-Computer returns before the guest actually goes down; wait until
    # the guest reports a NEWER LastBootUpTime.
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
    throw "guest did not come back with a new boot time within $TimeoutSec s (bugcheck?)"
}

function Invoke-Hv([string]$Command, [object[]]$Rest) {
    $out = & powershell.exe -ExecutionPolicy Bypass -File $hvScript $Command -VMName $VMName @Rest 2>&1 | Out-String
    Write-Host $out.Trim()
}

$results = @{}

try {
    Write-Host "[soak] restoring golden snapshot '$SnapshotName' on '$VMName'..."
    Invoke-Hv "Restore-Snapshot" @("-SnapshotName", $SnapshotName)
    Invoke-Hv "Start-VM" @("-TimeoutSeconds", "240")
    Wait-GuestReady

    Write-Host "[soak] copying probe to guest..."
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { param($d) New-Item -ItemType Directory -Force $d | Out-Null } -ArgumentList $guestStage
    # Copy-VMFile refuses to overwrite: clear any stale stage files first.
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { param($d) Remove-Item "$d\guardian_probe.py" -Force -ErrorAction SilentlyContinue } -ArgumentList $guestStage
    Copy-VMFile -VMName $VMName -SourcePath $probe -DestinationPath "$guestStage\guardian_probe.py" -CreateFullPath -FileSource Host

    Write-Host "[soak] enabling Driver Verifier (standard flags) on SandboxGuard.sys..."
    $vset = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { verifier /standard /driver SandboxGuard.sys 2>&1 | Out-String }
    Write-Host $vset.Trim()

    Write-Host "[soak] rebooting guest (verifier engages at boot)..."
    $preBoot = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
        (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    }
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { Restart-Computer -Force } 2>$null
    Wait-GuestRebooted -PreRebootBootTime $preBoot -TimeoutSec 300

    Write-Host "[soak] verifying verifier is active on the driver + PING..."
    $check = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
        param($stage)
        $vquery = verifier /query 2>&1 | Out-String
        $svc = sc.exe query SandboxGuard | Out-String
        $ping = & C:\Python311\python.exe "$stage\guardian_probe.py" --rounds 1 2>&1 | Out-String
        [PSCustomObject]@{ Verifier = $vquery.Trim(); Service = $svc.Trim(); Ping = $ping.Trim() }
    } -ArgumentList $guestStage
    Write-Host $check.Verifier
    $results["V1 verifier active on SandboxGuard.sys"] = ($check.Verifier -match "SandboxGuard\.sys")
    $results["V2 driver running + PING ok under verifier"] = ($check.Service -match "RUNNING" -and $check.Ping -match "PING ok")

    Write-Host "[soak] running A1a functional battery under verifier..."
    & powershell.exe -ExecutionPolicy Bypass -File $a1Script -Stage test -VMName $VMName
    $a1rc = $LASTEXITCODE
    $results["V3 A1a battery clean under verifier"] = ($a1rc -eq 0)

    Write-Host "[soak] verifier statistics after battery:"
    $stats = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { verifier /query 2>&1 | Out-String }
    Write-Host $stats.Trim()
    $results["V4 guest survived (no bugcheck; still responsive)"] = $true
}
finally {
    Write-Host "[soak] restoring golden snapshot (discards verifier config)..."
    try {
        Invoke-Hv "Stop-VM" @()
        Invoke-Hv "Restore-Snapshot" @("-SnapshotName", $SnapshotName)
    } catch { Write-Host "[soak] cleanup restore failed: $_" }
}

Write-Host ""
foreach ($k in $results.Keys) {
    Write-Host ("[{0}] {1}" -f $(if ($results[$k]) { "PASS" } else { "FAIL" }), $k)
}
if ($results.Count -eq 0 -or ($results.Values -contains $false)) {
    Write-Host "[soak] SOAK FAILED"
    exit 1
}
Write-Host "[soak] ALL CHECKS PASSED -- driver survived standard Driver Verifier"
exit 0
