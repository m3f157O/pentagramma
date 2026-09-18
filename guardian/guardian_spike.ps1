# guardian_spike.ps1 -- WS-A0 feasibility spike (host-side, ELEVATED).
#
# Drives the "pentagramma" analysis VM via PowerShell Direct to answer the
# go/no-go question for SandboxGuard.sys:
#   inspect : guest CI/WDAC policy + testsigning state (read-only)
#   enable  : testsigning on + test cert into Root/TrustedPublisher + reboot
#   load    : copy signed driver + probe, sc create/start, PING, spawn
#             notepad, DRAIN ring, verify the create event was captured
#   cleanup : sc stop/delete (the VM is reverted afterwards via the usual
#             restore path -- this script never touches the snapshot)
#
# Prereqs: driver built (build_guardian.ps1) + signed (make_test_cert.ps1).
# Run from an ELEVATED host PowerShell (Hyper-V PSDirect needs it).
#
#   powershell -ExecutionPolicy Bypass -File guardian\guardian_spike.ps1 -Stage inspect
#   powershell -ExecutionPolicy Bypass -File guardian\guardian_spike.ps1 -Stage enable
#   powershell -ExecutionPolicy Bypass -File guardian\guardian_spike.ps1 -Stage load
#   powershell -ExecutionPolicy Bypass -File guardian\guardian_spike.ps1 -Stage cleanup

param(
    [Parameter(Mandatory = $true)][ValidateSet("inspect", "enable", "load", "diag", "cleanup")][string]$Stage,
    [string]$VMName = "pentagramma"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$sys  = Join-Path $PSScriptRoot "out\x64\Release\SandboxGuard.sys"
$cer  = Join-Path $PSScriptRoot "out\SandboxGuardTest.cer"
$probe = Join-Path $PSScriptRoot "probe\guardian_probe.py"
$guestDir = "C:\SandboxAgent\guardian"

# Guest creds come from config\config.yaml (gitignored -- never hardcode them
# here; this repo is pushed to a public remote).
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

function Invoke-Guest([scriptblock]$Script, [object[]]$ArgumentList = @()) {
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script -ArgumentList $ArgumentList
}

function Ensure-VmRunning {
    $vm = Get-VM -Name $VMName
    if ($vm.State -ne "Running") {
        Write-Host "[spike] starting VM '$VMName'..."
        Start-VM -Name $VMName
    }
    Wait-GuestReady
}

switch ($Stage) {

    "inspect" {
        Ensure-VmRunning
        Write-Host "== CI / WDAC policy =="
        Invoke-Guest {
            $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                CodeIntegrityPolicyEnforcementStatus = $dg.CodeIntegrityPolicyEnforcementStatus  # 0 off, 1 audit, 2 enforce
                UsermodeCodeIntegrityPolicyEnforcementStatus = $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
                VirtualizationBasedSecurityStatus = $dg.VirtualizationBasedSecurityStatus
            } | Format-List | Out-String
        }
        Write-Host "== deployed CI policies =="
        Invoke-Guest { Get-ChildItem "$env:windir\System32\CodeIntegrity" -Filter *.p7b -ErrorAction SilentlyContinue | Select-Object -Expand Name }
        Write-Host "== bcdedit testsigning =="
        Invoke-Guest { bcdedit /enum '{current}' | Select-String -Pattern "testsigning|nointegritychecks" }
    }

    "enable" {
        if (-not (Test-Path $cer)) { throw "cert missing: $cer (run make_test_cert.ps1)" }
        Ensure-VmRunning
        Write-Host "[spike] enabling testsigning + importing test cert..."
        Invoke-Guest { param($d) New-Item -ItemType Directory -Force $d | Out-Null } -ArgumentList $guestDir
        Copy-VMFile -VMName $VMName -SourcePath $cer -DestinationPath "$guestDir\SandboxGuardTest.cer" -CreateFullPath -FileSource Host
        Invoke-Guest {
            param($d)
            bcdedit /set testsigning on | Out-String
            Import-Certificate -FilePath "$d\SandboxGuardTest.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
            Import-Certificate -FilePath "$d\SandboxGuardTest.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
            "cert imported, testsigning set"
        } -ArgumentList $guestDir
        Write-Host "[spike] rebooting guest..."
        # Restart-Computer returns before the guest goes down; key the wait
        # off the guest reporting a NEWER boot time, not mere readiness.
        $preBoot = Invoke-Guest { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
        Invoke-Guest { Restart-Computer -Force } 2>$null
        $deadline = (Get-Date).AddSeconds(300)
        $rebooted = $false
        while ((Get-Date) -lt $deadline) {
            try {
                $bt = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
                    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                } -ErrorAction Stop
                if ($bt -gt $preBoot) { $rebooted = $true; break }
            } catch { }
            Start-Sleep -Seconds 5
        }
        if (-not $rebooted) { throw "guest did not come back with a new boot time within 300 s" }
        Write-Host "[spike] guest back up; testsigning state:"
        Invoke-Guest { bcdedit /enum '{current}' | Select-String -Pattern "testsigning" }
    }

    "load" {
        foreach ($f in @($sys, $probe)) { if (-not (Test-Path $f)) { throw "missing: $f" } }
        Ensure-VmRunning
        Write-Host "[spike] copying driver + probe to guest..."
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock { param($d) New-Item -ItemType Directory -Force $d | Out-Null } -ArgumentList $guestDir
        # Copy-VMFile refuses to overwrite (0x80070050 File Exists) -- clear first.
        Invoke-Guest { param($d) Remove-Item "$d\SandboxGuard.sys", "$d\guardian_probe.py" -Force -ErrorAction SilentlyContinue } -ArgumentList $guestDir
        Copy-VMFile -VMName $VMName -SourcePath $sys -DestinationPath "$guestDir\SandboxGuard.sys" -CreateFullPath -FileSource Host
        Copy-VMFile -VMName $VMName -SourcePath $probe -DestinationPath "$guestDir\guardian_probe.py" -CreateFullPath -FileSource Host

        Write-Host "[spike] installing + starting driver..."
        Invoke-Guest {
            param($d)
            # Idempotent: clear a stale service from a previous failed attempt.
            sc.exe stop SandboxGuard 2>$null | Out-Null
            sc.exe delete SandboxGuard 2>$null | Out-Null
            sc.exe create SandboxGuard binPath= "$d\SandboxGuard.sys" type= kernel start= demand | Out-String
            sc.exe start SandboxGuard | Out-String
        } -ArgumentList $guestDir

        Write-Host "[spike] probe: PING + initial drain..."
        Invoke-Guest {
            param($d) & C:\Python311\python.exe "$d\guardian_probe.py" --rounds 1
        } -ArgumentList $guestDir

        Write-Host "[spike] spawning notepad to generate a process-create event..."
        Invoke-Guest { Start-Process notepad.exe; Start-Sleep -Seconds 2 }
        $events = Invoke-Guest {
            param($d) & C:\Python311\python.exe "$d\guardian_probe.py" --rounds 2 --interval 1
        } -ArgumentList $guestDir
        Invoke-Guest { Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue }

        $events
        $hit = $events | Where-Object { $_ -match '"image": "[^"]*notepad\.exe"' -and $_ -match '"kind": "create"' }
        if ($hit) {
            Write-Host "`n[spike] *** GO: driver loaded under guest CI policy, callback captured notepad.exe creation, IOCTL channel works ***" -ForegroundColor Green
        } else {
            Write-Host "`n[spike] driver loaded but no notepad create event seen -- inspect output above" -ForegroundColor Yellow
        }
    }

    "diag" {
        # Why did `sc start` fail with error 5? The kernel's refusal reason is
        # in the CodeIntegrity operational log; testsigning + Secure Boot state
        # decide what that log is even allowed to say.
        Ensure-VmRunning
        Write-Host "== testsigning state (post-reboot) =="
        Invoke-Guest { bcdedit /enum '{current}' } | Out-String
        Write-Host "== Secure Boot =="
        Invoke-Guest {
            try { "SecureBootUEFI: " + (Confirm-SecureBootUEFI) }
            catch { "Confirm-SecureBootUEFI: " + $_.Exception.Message }
        }
        Write-Host "== retry driver start, capture error =="
        Invoke-Guest { sc.exe start SandboxGuard } | Out-String
        Write-Host "== CodeIntegrity operational log (recent, driver-related) =="
        Invoke-Guest {
            Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 30 -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -match "SandboxGuard" -or $_.TimeCreated -gt (Get-Date).AddMinutes(-15) } |
                Select-Object TimeCreated, Id, @{n='Msg';e={ $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }} |
                Format-List | Out-String
        }
        Write-Host "== System log: service control events for SandboxGuard =="
        Invoke-Guest {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 15 -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -match "SandboxGuard" } |
                Select-Object TimeCreated, Id, Message | Format-List | Out-String
        }
        Write-Host "== bugcheck events (System, BugCheck source / ID 1001) =="
        Invoke-Guest {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001 } -MaxEvents 3 -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Message | Format-List | Out-String
        }
        Write-Host "== crash dumps =="
        Invoke-Guest {
            Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime | Format-Table | Out-String
            Get-Item C:\Windows\MEMORY.DMP -ErrorAction SilentlyContinue | Select-Object Length, LastWriteTime | Format-List | Out-String
            Get-ChildItem C:\Windows\LiveKernelReports -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Format-List | Out-String
        }
        # Pull the newest minidump to the host for local cdb analysis.
        # (Copy-VMFile is host->guest only on this build; use a PS session.)
        Write-Host "== copying newest minidump to host =="
        $newest = Invoke-Guest {
            Get-ChildItem C:\Windows\Minidump -Filter *.dmp -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
        }
        if ($newest) {
            $dumpDir = Join-Path $PSScriptRoot "dumps"
            New-Item -ItemType Directory -Force $dumpDir | Out-Null
            $dest = Join-Path $dumpDir (Split-Path $newest -Leaf)
            Remove-Item $dest -Force -ErrorAction SilentlyContinue
            $s = New-PSSession -VMName $VMName -Credential $cred
            try {
                Copy-Item -FromSession $s -Path $newest -Destination $dest -Force
            } finally {
                Remove-PSSession $s
            }
            Write-Host "[diag] minidump -> $dest"
        } else {
            Write-Host "[diag] no minidump found"
        }
    }

    "cleanup" {
        Ensure-VmRunning
        Invoke-Guest {
            sc.exe stop SandboxGuard | Out-String
            sc.exe delete SandboxGuard | Out-String
            "driver service removed"
        }
        Write-Host "[spike] cleanup done. Revert the VM to SANDBOX_READY via the orchestrator when finished."
    }
}
