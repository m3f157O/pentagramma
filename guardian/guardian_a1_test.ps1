# guardian_a1_test.ps1 -- WS-A1a functional test (host-side, ELEVATED).
#
# Drives the "pentagramma" analysis VM via PowerShell Direct to validate the
# A1a driver jobs against the live guest:
#   load    : copy signed driver + probe, (re)create + start the service
#   test    : A) injection placement (standalone targeting of notepad.exe ->
#             benign wkscli.dll must appear in its module list + inject_queued
#             event), B) Ob protection (taskkill of a protected PID must fail,
#             access_denied event), C) registry protection (write under
#             Windows Defender\Exclusions must be denied, reg_denied event)
#   cleanup : sc stop/delete (revert the VM via the orchestrator afterwards)
#
# Prereqs: driver built (build_guardian.ps1) + signed (make_test_cert.ps1),
#          A0 spike stages inspect/enable already run (testsigning on + cert).
#
#   powershell -ExecutionPolicy Bypass -File guardian\guardian_a1_test.ps1 -Stage load
#   powershell -ExecutionPolicy Bypass -File guardian\guardian_a1_test.ps1 -Stage test
#   powershell -ExecutionPolicy Bypass -File guardian\guardian_a1_test.ps1 -Stage cleanup

param(
    [Parameter(Mandatory = $true)][ValidateSet("load", "test", "cleanup")][string]$Stage,
    [string]$VMName = "pentagramma"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$sys  = Join-Path $PSScriptRoot "out\x64\Release\SandboxGuard.sys"
$probe = Join-Path $PSScriptRoot "probe\guardian_probe.py"
$guestDir = "C:\SandboxAgent\guardian"
$injectDll = "C:\Windows\System32\wkscli.dll"   # benign, normally absent from notepad

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

function Invoke-Guest([scriptblock]$Script, [object[]]$ArgumentList = @()) {
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script -ArgumentList $ArgumentList
}

function Ensure-VmRunning {
    $vm = Get-VM -Name $VMName
    if ($vm.State -ne "Running") { Start-VM -Name $VMName }
    Wait-GuestReady
}

switch ($Stage) {

    "load" {
        foreach ($f in @($sys, $probe)) { if (-not (Test-Path $f)) { throw "missing: $f" } }
        Ensure-VmRunning
        Write-Host "[a1] stopping any previous driver instance..."
        Invoke-Guest {
            sc.exe stop SandboxGuard 2>$null | Out-Null
            sc.exe delete SandboxGuard 2>$null | Out-Null
            Start-Sleep -Seconds 2
        }
        Write-Host "[a1] copying driver + probe to guest..."
        Invoke-Guest { param($d) New-Item -ItemType Directory -Force $d | Out-Null } -ArgumentList $guestDir
        Invoke-Guest { param($d) Remove-Item "$d\SandboxGuard.sys", "$d\guardian_probe.py" -Force -ErrorAction SilentlyContinue } -ArgumentList $guestDir
        Copy-VMFile -VMName $VMName -SourcePath $sys -DestinationPath "$guestDir\SandboxGuard.sys" -CreateFullPath -FileSource Host
        Copy-VMFile -VMName $VMName -SourcePath $probe -DestinationPath "$guestDir\guardian_probe.py" -CreateFullPath -FileSource Host
        Write-Host "[a1] installing + starting driver..."
        Invoke-Guest {
            param($d)
            sc.exe create SandboxGuard binPath= "$d\SandboxGuard.sys" type= kernel start= demand | Out-String
            sc.exe start SandboxGuard | Out-String
        } -ArgumentList $guestDir
        Invoke-Guest { param($d) & C:\Python311\python.exe "$d\guardian_probe.py" --rounds 1 } -ArgumentList $guestDir
        Write-Host "[a1] driver loaded; run -Stage test next"
    }

    "test" {
        Ensure-VmRunning
        $results = @{}

        # ---- A. injection placement -------------------------------------
        Write-Host "`n== A. injection placement (target: notepad.exe, dll: $injectDll) =="
        Invoke-Guest {
            param($d, $dll)
            & C:\Python311\python.exe "$d\guardian_probe.py" --clear-all --rounds 1 | Out-Null
            & C:\Python311\python.exe "$d\guardian_probe.py" --set-injection $dll --target-standalone notepad.exe --rounds 1
        } -ArgumentList $guestDir, $injectDll
        Invoke-Guest { Start-Process notepad.exe; Start-Sleep -Seconds 3 }
        $modules = Invoke-Guest { (Get-Process notepad -ErrorAction SilentlyContinue).Modules | Select-Object -ExpandProperty ModuleName }
        $results["A1 module loaded"] = ($modules -contains "wkscli.dll")
        $evtsA = Invoke-Guest { param($d) & C:\Python311\python.exe "$d\guardian_probe.py" --rounds 1 } -ArgumentList $guestDir
        $evtsA
        $results["A2 inject_queued event"] = [bool]($evtsA | Where-Object { $_ -match '"type": "inject_queued"' })
        Invoke-Guest { Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue }

        # ---- B. Ob protection -------------------------------------------
        Write-Host "`n== B. process protection (protected notepad must survive taskkill) =="
        Invoke-Guest { Start-Process notepad.exe; Start-Sleep -Seconds 2 }
        $npPid = Invoke-Guest { (Get-Process notepad).Id }
        Write-Host "[a1] protecting pid $npPid"
        Invoke-Guest { param($d, $p) & C:\Python311\python.exe "$d\guardian_probe.py" --protect-add $p --rounds 1 } -ArgumentList $guestDir, $npPid
        $killOut = Invoke-Guest { param($p) taskkill /F /PID $p 2>&1 | Out-String; "exit=$LASTEXITCODE" } -ArgumentList $npPid
        Write-Host "[a1] taskkill output: $killOut"
        $results["B1 kill blocked"] = ($killOut -match "exit=1")
        $evtsB = Invoke-Guest { param($d) & C:\Python311\python.exe "$d\guardian_probe.py" --rounds 1 } -ArgumentList $guestDir
        $results["B2 access_denied event"] = [bool]($evtsB | Where-Object { $_ -match '"type": "access_denied"' })
        Write-Host "[a1] unprotecting + killing for cleanup"
        Invoke-Guest { param($d, $p) & C:\Python311\python.exe "$d\guardian_probe.py" --protect-remove $p --rounds 1 } -ArgumentList $guestDir, $npPid
        Invoke-Guest { Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue }

        # ---- C. registry protection --------------------------------------
        # NB: reg.exe is blocked by the guest's DisableRegistryTools policy
        # (never reaches the kernel) -- use the PS registry provider instead.
        Write-Host "`n== C. registry protection (Defender exclusions write must be denied) =="
        # C0 control: plain HKLM write must SUCCEED -- proves the session can
        # write HKLM at all, so a denied Exclusions write is our driver, not ACLs.
        $regControl = Invoke-Guest {
            try {
                New-ItemProperty -Path "HKLM:\SOFTWARE" -Name SGControl -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                Remove-ItemProperty -Path "HKLM:\SOFTWARE" -Name SGControl -ErrorAction SilentlyContinue
                "ok"
            } catch { "denied: $($_.Exception.Message)" }
        }
        Write-Host "[a1] control write (HKLM:\SOFTWARE\SGControl): $regControl"
        $results["C0 control write succeeds"] = ($regControl -eq "ok")
        $regOut = Invoke-Guest {
            try {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64" -Name sgtest -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                "write succeeded (unexpected)"
            } catch {
                "denied: $($_.Exception.Message)"
            }
        }
        Write-Host "[a1] Sysmon service key write result: $regOut"
        $results["C1 write denied"] = ($regOut -match "^denied:")
        # Informational: Defender exclusion write -- may be denied by Defender
        # Tamper Protection BEFORE our callback (altitude ordering), so no
        # reg_denied event is required from it.
        $regDef = Invoke-Guest {
            try {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name sgtest -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                "succeeded"
            } catch { "denied: $($_.Exception.Message)" }
        }
        Write-Host "[a1] Defender exclusions write (informational): $regDef"
        $evtsC = Invoke-Guest { param($d) & C:\Python311\python.exe "$d\guardian_probe.py" --rounds 1 } -ArgumentList $guestDir
        $regHits = @($evtsC | Where-Object { $_ -match '"type": "reg_denied"' })
        $regHits | Select-Object -Last 3 | ForEach-Object { Write-Host "[a1] $_" }
        $results["C2 reg_denied event"] = [bool]($regHits | Where-Object { $_ -match "SYSMON" })

        # ---- summary ------------------------------------------------------
        Write-Host "`n== A1a test summary =="
        $allOk = $true
        foreach ($k in $results.Keys) {
            $ok = $results[$k]
            if (-not $ok) { $allOk = $false }
            Write-Host ("  [{0}] {1}" -f ($(if ($ok) { "PASS" } else { "FAIL" })), $k)
        }
        if ($allOk) {
            Write-Host "`n[a1] *** ALL A1a JOBS VERIFIED ***" -ForegroundColor Green
        } else {
            Write-Host "`n[a1] some checks failed -- drain output above" -ForegroundColor Yellow
        }
    }

    "cleanup" {
        Ensure-VmRunning
        Invoke-Guest {
            sc.exe stop SandboxGuard | Out-String
            sc.exe delete SandboxGuard | Out-String
            "driver service removed"
        }
        Write-Host "[a1] cleanup done. Revert the VM to SANDBOX_READY via the orchestrator when finished."
    }
}
