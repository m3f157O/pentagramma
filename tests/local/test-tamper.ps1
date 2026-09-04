# test-tamper.ps1 -- A4 guardian tamper canary (benign: every action is an
# ATTEMPT the guardian driver is expected to block; nothing here is armed).
#
# Expected on a guardian-protected run:
#   - taskkill /F /IM Sysmon64.exe FAILS (Ob strips PROCESS_TERMINATE)
#       -> GuardianProtectedAccess alert
#   - Defender exclusion write FAILS (Cm deny)
#       -> GuardianProtectedRegistry alert
#   - Sysmon service-key write FAILS (Cm deny)
#       -> GuardianProtectedRegistry alert
#   - Sysmon64 still Running at the end
# Known boundaries (documented, not failures):
#   - Stop-Service goes through the SCM control channel, not OpenProcess --
#     outside job 1's scope.
#   - Deleting telemetry files is job 3 (minifilter, A1b) -- succeeds for now.
#
# Prints JSON results to stdout so the report's execution_info captures them.

$results = [ordered]@{}

# 1. Try to kill the Sysmon process outright.
taskkill /F /IM Sysmon64.exe 2>&1 | Out-Null
$results["taskkill_sysmon_exitcode"] = $LASTEXITCODE   # expect 1 (access denied)

# 2. Try the service control channel (SCM) -- boundary case, see header.
try {
    Stop-Service Sysmon64 -Force -ErrorAction Stop
    $results["stop_service_sysmon"] = "succeeded (boundary: SCM channel)"
} catch {
    $results["stop_service_sysmon"] = "denied"
}

# 3. Try to add a Defender exclusion for the sandbox dir.
try {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" `
        -Name "C:\Sandbox" -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    $results["defender_exclusion_write"] = "succeeded (BAD)"
} catch {
    $results["defender_exclusion_write"] = "denied"
}

# 4. Try to write the Sysmon service key (config tampering).
try {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64" `
        -Name "tamper" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    $results["sysmon_key_write"] = "succeeded (BAD)"
} catch {
    $results["sysmon_key_write"] = "denied"
}

# 5. Try to delete the telemetry output file (job 3 gap until A1b).
$telemetry = "C:\SandboxAgent\telemetry.jsonl"
Remove-Item $telemetry -Force -ErrorAction SilentlyContinue
$results["telemetry_delete_attempted"] = (-not (Test-Path $telemetry))

# 6. Final state: is Sysmon still alive?
Start-Sleep -Seconds 1
$results["sysmon_status_end"] = (Get-Service Sysmon64).Status.ToString()   # expect Running

$results | ConvertTo-Json -Compress
