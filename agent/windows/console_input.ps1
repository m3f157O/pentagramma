# Guest-side console input injector. Deployed to C:\SandboxAgent when the
# browser console is opened; inert file, no listener, no persistence.
#
# Each invocation performs ONE input action against the interactive desktop:
#   -Action screeninfo                 -> JSON {Width, Height} of the primary screen
#   -Action click|rightclick|dblclick  -X <px> -Y <px>
#   -Action move                       -X <px> -Y <px>
#   -Action wheel                      -Delta <int>   (120 = one notch up)
#   -Action key                        -Key "ENTER" | "ESC" | "CTRL+F4" | ...
#   -Action text                       -Text "string to type"
#
# Key names: ENTER ESC TAB BACKSPACE DELETE SPACE UP DOWN LEFT RIGHT HOME END
# PAGEUP PAGEDOWN F1..F12, optionally joined with CTRL+ SHIFT+ ALT+.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Action,
    [int]$X = 0,
    [int]$Y = 0,
    [int]$Delta = 0,
    [string]$Key = "",
    [string]$Text = ""
)

$ErrorActionPreference = "Stop"

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
    public struct INPUT {
        public uint type;           // 1 = keyboard
        public KEYBDINPUT ki;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public UIntPtr dwExtraInfo;
    }

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
    # modifiers down in order, everything up in reverse order
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

switch ($Action) {
    "screeninfo" {
        $w = [ConsoleInput]::GetSystemMetrics(0)  # SM_CXSCREEN
        $h = [ConsoleInput]::GetSystemMetrics(1)  # SM_CYSCREEN
        [PSCustomObject]@{ Width = $w; Height = $h } | ConvertTo-Json -Compress
    }
    "click"      { Send-MouseClick $X $Y $false 1 }
    "rightclick" { Send-MouseClick $X $Y $true 1 }
    "dblclick"   { Send-MouseClick $X $Y $false 2 }
    "move"       { [ConsoleInput]::SetCursorPos($X, $Y) | Out-Null }
    "wheel"      { [ConsoleInput]::mouse_event([ConsoleInput]::MOUSEEVENTF_WHEEL, 0, 0, $Delta, [UIntPtr]::Zero) }
    "key"        { Send-KeyCombo $Key }
    "text"       { [ConsoleInput]::TypeUnicode($Text) }
    default      { throw "unknown action: $Action" }
}
