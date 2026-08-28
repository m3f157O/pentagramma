// Sandbox monitor loader (Track 3 feasibility spike / 3.1 core).
//
// Becomes the launched process on the traced execution path. It:
//   1. creates the real sample SUSPENDED,
//   2. injects monitor_x64.dll (VirtualAllocEx the DLL path + CreateRemoteThread
//      on LoadLibraryW) so hooks are in place before the sample's first
//      instruction runs,
//   3. resumes the sample, forwards its exit code, and tears down if killed.
//
//   monitor_loader.exe <dll_path> <target_exe> [args...]
//
// On the traced path the sandbox sets MONITOR_PID_FILE; the loader writes the
// real sample's PID there so the dump loop targets the sample, not the loader.
// The sample is placed in a kill-on-close job so it dies with the loader if the
// sandbox's timeout path kills it (no orphaned sample). stdout/stderr reach the
// sandbox via normal handle inheritance (the loader's redirected std handles are
// inherited by the child). Child-following comes in Track 3.2.

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "../common/inject.h"

static int fail(const wchar_t* what, HANDLE proc) {
    fwprintf(stderr, L"[loader] %ls failed: %lu\n", what, GetLastError());
    if (proc) TerminateProcess(proc, 1);
    return 1;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        fwprintf(stderr, L"usage: monitor_loader <dll_path> <target_exe> [args...]\n"
                         L"       monitor_loader attach <dll_path> <pid>\n");
        return 2;
    }

    // Attach mode (used for cross-bitness child-following: the x64 monitor
    // spawns monitor_loader_x86.exe to inject monitor_x86.dll into a WoW64
    // child it can't load into itself). Fire-and-forget: the child is already
    // running (or auto-resumed by its parent's CreateProcess path), so no
    // ready handshake -- same tradeoff as in-monitor child injection.
    // NOTE: this only works same-bitness -- in the x86 build, our own
    // LoadLibraryW address is the 32-bit one valid in every WoW64 process.
    if (argc >= 4 && _wcsicmp(argv[1], L"attach") == 0) {
        const wchar_t* dllPath = argv[2];
        DWORD pid = wcstoul(argv[3], NULL, 10);
        if (!pid) return 2;
        HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!proc) return fail(L"OpenProcess", NULL);
        bool ok = inject_monitor_into_process(proc, NULL, dllPath, 0, L"attach", true);
        CloseHandle(proc);
        if (ok) fwprintf(stderr, L"[loader] attached %ls to pid %lu\n", dllPath, pid);
        return ok ? 0 : 6;
    }

    std::wstring dll = argv[1];

    // Reassemble a command line from argv[2..], quoting only tokens that need
    // it (contain a space or are empty) so switches like `/c` reach the target
    // unquoted.
    std::wstring cmd;
    for (int i = 2; i < argc; i++) {
        if (i > 2) cmd += L" ";
        std::wstring tok = argv[i];
        if (tok.empty() || tok.find(L' ') != std::wstring::npos) {
            cmd += L"\""; cmd += tok; cmd += L"\"";
        } else {
            cmd += tok;
        }
    }
    std::vector<wchar_t> cmdbuf(cmd.begin(), cmd.end());
    cmdbuf.push_back(0);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(NULL, cmdbuf.data(), NULL, NULL, TRUE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return fail(L"CreateProcess", NULL);
    }

    // Kill-on-close job: if the sandbox kills this loader (timeout path), the
    // sample child is terminated with it instead of orphaned. The loader holds
    // the job handle for the child's lifetime; closing it (on loader exit/kill)
    // terminates the still-running child.
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
        AssignProcessToJobObject(job, pi.hProcess);
    }

    // Publish the real sample's PID so the sandbox dump loop targets the sample,
    // not this loader. Opt-in via env var (host-local spike needs no pid file).
    wchar_t pidfile[MAX_PATH];
    DWORD pf = GetEnvironmentVariableW(L"MONITOR_PID_FILE", pidfile, MAX_PATH);
    if (pf > 0 && pf < MAX_PATH) {
        HANDLE f = CreateFileW(pidfile, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            char buf[32];
            int len = sprintf_s(buf, "%lu", pi.dwProcessId);
            if (len > 0) { DWORD w = 0; WriteFile(f, buf, (DWORD)len, &w, NULL); }
            CloseHandle(f);
        }
    }

    // Inject the monitor and wait for its "hooks live" handshake (bounded);
    // the shared helper owns the ready event.
    if (!inject_monitor_into_process(pi.hProcess, pi.hThread, dll.c_str(), 5000, L"loader")) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return 5;
    }
    ResumeThread(pi.hThread);
    fwprintf(stderr, L"[loader] injected %ls into pid %lu, resumed\n", dll.c_str(), pi.dwProcessId);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}
