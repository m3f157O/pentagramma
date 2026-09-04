// guardian_loadlib_x86.c -- print the 32-bit user-mode VA of
// kernel32!LoadLibraryW as hex on stdout (e.g. "0x76A1B2C0").
//
// The guardian driver injects monitor_x86.dll into WoW64 targets by queueing
// a user APC whose routine is LoadLibraryW in the target's 32-bit address
// space. System DLL bases are per-boot/per-bitness, so the address resolved
// in THIS 32-bit process is valid for every WoW64 process until reboot.
// guardian_agent.py (itself 64-bit, unable to load 32-bit kernel32) runs
// this helper once at startup and forwards the address to the driver via
// IOCTL SET_INJECTION (LoadLibraryX86 field).
//
// Build (x86!): build_loadlib_x86.cmd
#include <windows.h>
#include <stdio.h>

int main(void)
{
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) { fprintf(stderr, "GetModuleHandleW failed\n"); return 1; }
    FARPROC p = GetProcAddress(k32, "LoadLibraryW");
    if (!p) { fprintf(stderr, "GetProcAddress failed\n"); return 1; }
    printf("0x%08X", (unsigned)(ULONG_PTR)p);
    return 0;
}
