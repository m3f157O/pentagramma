// Shared monitor-injection helper -- see inject.h.
//
// This is byte-for-byte the sequence that used to live inline in
// monitor_loader.cpp's wmain (VirtualAllocEx the DLL path, CreateRemoteThread
// on LoadLibraryW, then wait for the monitor's ready event), made reusable so
// the monitor's child-following hook can run the identical steps for each new
// child process.
#include "inject.h"
#include <stdio.h>

bool inject_monitor_into_process(HANDLE hProcess, HANDLE hThread,
                                 const wchar_t* dllPath, DWORD timeoutMs,
                                 const wchar_t* tag, bool fireAndForget) {
    (void)hThread;  // the caller resumes it after we return
    if (!tag) tag = L"inject";

    DWORD pid = GetProcessId(hProcess);
    if (!pid) {
        fwprintf(stderr, L"[%ls] GetProcessId failed: %lu\n", tag, GetLastError());
        return false;
    }

    // "Hooks are live" handshake event -- only created in the strict path;
    // fire-and-forget never waits on it.
    HANDLE readyEvent = NULL;
    if (!fireAndForget) {
        wchar_t evname[64];
        swprintf_s(evname, L"Local\\sandbox_monitor_ready_%lu", pid);
        readyEvent = CreateEventW(NULL, TRUE, FALSE, evname);  // manual-reset
    }

    SIZE_T bytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hProcess, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        fwprintf(stderr, L"[%ls] VirtualAllocEx failed: %lu\n", tag, GetLastError());
        if (readyEvent) CloseHandle(readyEvent);
        return false;
    }
    if (!WriteProcessMemory(hProcess, remote, dllPath, bytes, NULL)) {
        fwprintf(stderr, L"[%ls] WriteProcessMemory failed: %lu\n", tag, GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        if (readyEvent) CloseHandle(readyEvent);
        return false;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto loadlib = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
    HANDLE th = CreateRemoteThread(hProcess, NULL, 0, loadlib, remote, 0, NULL);
    if (!th) {
        fwprintf(stderr, L"[%ls] CreateRemoteThread failed: %lu\n", tag, GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        if (readyEvent) CloseHandle(readyEvent);
        return false;
    }

    if (fireAndForget) {
        // Do NOT wait for the thread and do NOT free `remote` (LoadLibraryW
        // may not have read the path yet -- see inject.h). The remote string
        // allocation is intentionally leaked.
        CloseHandle(th);
        return true;
    }

    // Wait for LoadLibraryW to return; its exit code is the loaded HMODULE
    // (low 32 bits) -- zero means the DLL failed to load (the WDAC signal).
    WaitForSingleObject(th, 10000);
    DWORD loadResult = 0;
    GetExitCodeThread(th, &loadResult);
    CloseHandle(th);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    if (loadResult == 0) {
        fwprintf(stderr, L"[%ls] LoadLibraryW returned 0 -- DLL did not load "
                         L"(blocked? bad path? WDAC?): %ls\n", tag, dllPath);
        if (readyEvent) CloseHandle(readyEvent);
        return false;
    }

    // Wait for the monitor to report hooks are live (bounded); a timeout is a
    // soft failure -- the caller may still proceed.
    if (readyEvent) {
        DWORD w = WaitForSingleObject(readyEvent, timeoutMs);
        if (w != WAIT_OBJECT_0)
            fwprintf(stderr, L"[%ls] warning: monitor-ready wait returned %lu for pid %lu; proceeding anyway\n",
                     tag, w, pid);
        CloseHandle(readyEvent);
    }
    return true;
}
