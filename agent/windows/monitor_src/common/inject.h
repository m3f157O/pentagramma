// Shared monitor-injection helper (Track 3.2).
//
// Extracted from monitor_loader.cpp so the exact same injection sequence is
// used for the root sample (loader) and for child processes (the monitor's
// NtCreateUserProcess hook, child-following).
#pragma once

#include <windows.h>

// Injects `dllPath` into a suspended target process via the classic
// VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW)
// sequence, then waits (bounded, `timeoutMs`) for the monitor's "hooks live"
// ready event (Local\sandbox_monitor_ready_<pid>, created here BEFORE the
// injection so the monitor can always open it).
//
// Returns true only if the DLL loaded AND (the ready event was signaled OR
// the wait timed out -- a timeout is a soft failure, logged, not fatal: the
// monitor may still be initializing; the caller decides whether to proceed).
// A LoadLibraryW failure (return 0 -- e.g. WDAC block) is a hard false.
//
// `tag` prefixes stderr diagnostics ("loader" / "monitor").
//
// `fireAndForget` (used for child-following): alloc + write + create the
// LoadLibrary thread, then return IMMEDIATELY -- no LoadLibrary wait, no
// ready handshake, and deliberately NO VirtualFreeEx of the remote string
// (we can't know when LoadLibraryW finished reading it; the ~520-byte leak
// per child is acceptable -- the analysis VM reverts per run). Rationale:
// holding the child frozen through a full load+hook+handshake cycle while
// the parent is mid-CreateProcess inside kernel32 corrupts the child's own
// startup (observed: nested cmd failing with ERROR_ACCESS_DENIED). The root
// sample keeps the strict handshake; children trade a few ms of unhooked
// startup for a creation path indistinguishable from unhooked.
bool inject_monitor_into_process(HANDLE hProcess, HANDLE hThread,
                                 const wchar_t* dllPath, DWORD timeoutMs,
                                 const wchar_t* tag, bool fireAndForget = false);
