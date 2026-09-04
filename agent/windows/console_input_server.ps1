# Guest-side interactive-session input server. Started by the orchestrator
# (Console-InputServer-Start) via a scheduled task running as the LOGGED-ON
# user (gigi) with an interactive token -- that session is the one whose
# desktop the WMI thumbnails show, so input injected HERE is visible and
# effective. PSDirect sessions are non-interactive and CANNOT reach it.
#
# Protocol: named-pipe server \\.\pipe\sandbox_console_in, one JSON command
# per line (pipes are session-independent kernel objects, so the PSRP-side
# helper can connect as a client without any network listener):
#   {"action":"screeninfo"}                          -> writes console_screen.json
#   {"action":"click","x":640,"y":400}               rightclick/dblclick/move too
#   {"action":"wheel","delta":120}
#   {"action":"key","key":"ENTER"|"CTRL+F4"|...}
#   {"action":"text","text":"..."}
#   {"action":"quit"}                                -> exit
# Errors are appended to console_input_server.log. No acks on the wire -- the
# orchestrator polls the screen/status files it needs.
[CmdletBinding()]
param(
    [string]$WorkDir = "C:\SandboxAgent",
    [string]$PipeName = "sandbox_console_in"
)

$ErrorActionPreference = "Stop"
$logFile = Join-Path $WorkDir "console_input_server.log"
$screenFile = Join-Path $WorkDir "console_screen.json"

function Write-Log([string]$msg) {
    try { Add-Content -Path $logFile -Value ("{0} {1}" -f (Get-Date -Format o), $msg) -ErrorAction SilentlyContinue } catch {}
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class ConsoleInput {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, int data, UIntPtr extra);
    [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
    [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] inputs, int size);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);

    public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
    public const uint MOUSEEVENTF_LEFTUP = 0x0004;
    public const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
    public const uint MOUSEEVENTF_RIGHTUP = 0x0010;
    public const uint MOUSEEVENTF_WHEEL = 0x0800;
    public const uint KEYEVENTF_KEYUP = 0x0002;
    public const uint KEYEVENTF_UNICODE = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT { public uint type; public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo; }

    public static void TypeUnicode(string text) {
        foreach (char c in text) {
            INPUT[] down = new INPUT[] { new INPUT { type = 1, ki = new KEYBDINPUT { wVk = 0, wScan = (ushort)c, dwFlags = KEYEVENTF_UNICODE, time = 0, dwExtraInfo = UIntPtr.Zero } } };
            INPUT[] up   = new INPUT[] { new INPUT { type = 1, ki = new KEYBDINPUT { wVk = 0, wScan = (ushort)c, dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, time = 0, dwExtraInfo = UIntPtr.Zero } } };
            SendInput(1, down, Marshal.SizeOf(typeof(INPUT)));
            SendInput(1, up, Marshal.SizeOf(typeof(INPUT)));
        }
    }
}
"@

$VK = @{
    "BACKSPACE" = 0x08; "TAB" = 0x09; "ENTER" = 0x0D; "ESC" = 0x1B; "SPACE" = 0x20
    "PAGEUP" = 0x21; "PAGEDOWN" = 0x22; "END" = 0x23; "HOME" = 0x24
    "LEFT" = 0x25; "UP" = 0x26; "RIGHT" = 0x27; "DOWN" = 0x28; "DELETE" = 0x2E
    "F1" = 0x70; "F2" = 0x71; "F3" = 0x72; "F4" = 0x73; "F5" = 0x74; "F6" = 0x75
    "F7" = 0x76; "F8" = 0x77; "F9" = 0x78; "F10" = 0x79; "F11" = 0x7A; "F12" = 0x7B
    "CTRL" = 0x11; "SHIFT" = 0x10; "ALT" = 0x12
}

function Send-KeyCombo([string]$combo) {
    $names = $combo.ToUpperInvariant() -split "\+" | Where-Object { $_ }
    if (-not $names) { throw "empty key combo" }
    foreach ($n in $names) { if (-not $VK.ContainsKey($n)) { throw "unknown key: $n" } }
    foreach ($n in $names) { [ConsoleInput]::keybd_event([byte]$VK[$n], 0, 0, [UIntPtr]::Zero) }
    [Array]::Reverse($names)
    foreach ($n in $names) { [ConsoleInput]::keybd_event([byte]$VK[$n], 0, [ConsoleInput]::KEYEVENTF_KEYUP, [UIntPtr]::Zero) }
}

function Send-MouseClick([int]$x, [int]$y, [bool]$right, [int]$count) {
    [ConsoleInput]::SetCursorPos($x, $y) | Out-Null
    $down = if ($right) { [ConsoleInput]::MOUSEEVENTF_RIGHTDOWN } else { [ConsoleInput]::MOUSEEVENTF_LEFTDOWN }
    $up = if ($right) { [ConsoleInput]::MOUSEEVENTF_RIGHTUP } else { [ConsoleInput]::MOUSEEVENTF_LEFTUP }
    for ($i = 0; $i -lt $count; $i++) {
        [ConsoleInput]::mouse_event($down, 0, 0, 0, [UIntPtr]::Zero)
        [ConsoleInput]::mouse_event($up, 0, 0, 0, [UIntPtr]::Zero)
    }
}

function Invoke-ConsoleCommand($cmd) {
    switch ($cmd.action) {
        "screeninfo" {
            $w = [ConsoleInput]::GetSystemMetrics(0)
            $h = [ConsoleInput]::GetSystemMetrics(1)
            [PSCustomObject]@{ Width = $w; Height = $h } | ConvertTo-Json -Compress | Set-Content -Path $screenFile -Encoding ascii
        }
        "click"      { Send-MouseClick ([int]$cmd.x) ([int]$cmd.y) $false 1 }
        "rightclick" { Send-MouseClick ([int]$cmd.x) ([int]$cmd.y) $true 1 }
        "dblclick"   { Send-MouseClick ([int]$cmd.x) ([int]$cmd.y) $false 2 }
        "move"       { [ConsoleInput]::SetCursorPos([int]$cmd.x, [int]$cmd.y) | Out-Null }
        "wheel"      { [ConsoleInput]::mouse_event([ConsoleInput]::MOUSEEVENTF_WHEEL, 0, 0, [int]$cmd.delta, [UIntPtr]::Zero) }
        "key"        { Send-KeyCombo ([string]$cmd.key) }
        "text"       { [ConsoleInput]::TypeUnicode([string]$cmd.text) }
        default      { throw "unknown action: $($cmd.action)" }
    }
}

Write-Log "server starting (pipe $PipeName)"
# Mark readiness (orchestrator polls for this file after starting the task)
[PSCustomObject]@{ Started = (Get-Date -Format o); PID = $PID } | ConvertTo-Json -Compress | Set-Content -Path (Join-Path $WorkDir "console_input_server.ready") -Encoding ascii

while ($true) {
    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeServerStream($PipeName, [System.IO.Pipes.PipeDirection]::In, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None)
        $pipe.WaitForConnection()
        $reader = New-Object System.IO.StreamReader($pipe)
        while ($pipe.IsConnected) {
            $line = $reader.ReadLine()
            if ($null -eq $line) { break }
            $line = $line.Trim()
            if (-not $line) { continue }
            try {
                $cmd = $line | ConvertFrom-Json
                if ($cmd.action -eq "quit") { Write-Log "quit received"; exit 0 }
                Invoke-ConsoleCommand $cmd
            } catch {
                Write-Log "command error: $_"
            }
        }
    } catch {
        Write-Log "pipe error: $_"
        Start-Sleep -Milliseconds 500
    } finally {
        if ($reader) { try { $reader.Dispose() } catch {} ; $reader = $null }
        if ($pipe) { try { $pipe.Dispose() } catch {} }
    }
}
