# Persistent console-input helper (host side). Spawned by
# orchestrator/console.py when the browser console opens.
#
# Holds ONE PowerShell Direct session to the VM. The guest-side input server
# (console_input_server.ps1) runs in the INTERACTIVE session (scheduled task,
# logged-on user) and listens on the named pipe \\.\pipe\sandbox_console_in.
# Pipes are session-independent kernel objects, so this helper -- running
# commands in the non-interactive PSRP session -- can still reach the
# interactive desktop by writing to the pipe through the PSSession.
#
# Protocol:
#   stdin  <- one JSON input command per line, e.g. {"action":"click","x":640,"y":400}
#   stdout -> one JSON ack per command: {"ok":true,"output":"..."} or {"ok":false,"error":"..."}
# For action=screeninfo the ack's "output" carries the guest screen JSON.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VMName,
    [Parameter(Mandatory = $true)][string]$CredentialUsername,
    [Parameter(Mandatory = $true)][string]$CredentialPassword,
    [string]$PipeName = "sandbox_console_in",
    [string]$ScreenFile = "C:\SandboxAgent\console_screen.json"
)

$ErrorActionPreference = "Stop"

function New-ConsoleSession {
    $sec = ConvertTo-SecureString $CredentialPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($CredentialUsername, $sec)
    return New-PSSession -VMName $VMName -Credential $cred
}

$pipeScript = {
    param($pipeName, $json, $screenFile, $wantScreen)
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::Out)
    try {
        $client.Connect(5000)
        $writer = New-Object System.IO.StreamWriter($client)
        $writer.AutoFlush = $true
        $writer.WriteLine($json)
        $writer.Flush()
        Start-Sleep -Milliseconds 200   # let the server consume before disconnect
        $writer.Dispose()
    } finally {
        $client.Dispose()
    }
    if ($wantScreen) {
        Start-Sleep -Milliseconds 400   # server writes the file async
        if (Test-Path $screenFile) { return (Get-Content $screenFile -Raw) }
        return ""
    }
    return ""
}

function Invoke-GuestInput($sess, $json) {
    $wantScreen = ($json | ConvertFrom-Json).action -eq "screeninfo"
    return Invoke-Command -Session $sess -ScriptBlock $pipeScript -ArgumentList $PipeName, $json, $ScreenFile, $wantScreen
}

function Write-Ack($obj) {
    [Console]::Out.WriteLine(($obj | ConvertTo-Json -Compress -Depth 4))
    [Console]::Out.Flush()
}

$sess = $null
try { $sess = New-ConsoleSession } catch { Write-Ack @{ ok = $false; error = "session open failed: $_" } }

while ($true) {
    $line = [Console]::In.ReadLine()
    if ($null -eq $line) { break }          # stdin closed by orchestrator -> exit
    $line = $line.Trim()
    if (-not $line) { continue }

    try {
        if (-not $sess) { $sess = New-ConsoleSession }
        try {
            $out = Invoke-GuestInput $sess $line
        } catch {
            # one reconnect attempt, then report the failure
            try { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } } catch {}
            $sess = New-ConsoleSession
            $out = Invoke-GuestInput $sess $line
        }
        Write-Ack @{ ok = $true; output = ($out | Out-String).Trim() }
    } catch {
        Write-Ack @{ ok = $false; error = "$_" }
    }
}

if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
