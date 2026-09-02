// Shared IOCTL ABI between SandboxGuard.sys and its user-mode clients
// (guardian_agent.py, guardian_probe.py). Keep this file dependency-free:
// it is parsed by hand into the Python clients (constants duplicated there).
#ifndef GUARDIAN_IOCTL_H
#define GUARDIAN_IOCTL_H

#define GUARDIAN_DEVICE_NAME  L"\\Device\\SandboxGuard"
#define GUARDIAN_SYMLINK_NAME L"\\??\\SandboxGuard"
// User-mode opens: \\\\.\\SandboxGuard

// Handshake signature returned by IOCTL_GUARDIAN_PING ("SBGUARD1").
#define GUARDIAN_PING_SIGNATURE 0x3144524155474253ULL

#define IOCTL_GUARDIAN_PING          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARDIAN_DRAIN         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_GUARDIAN_PROTECT_PID   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_GUARDIAN_SET_TARGETING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_GUARDIAN_SET_INJECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_GUARDIAN_CLEAR_ALL     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_DATA)

// ---------------------------------------------------------------------------
// Event types in the ring (drained via IOCTL_GUARDIAN_DRAIN).
// Synthetic EIDs surfaced to telemetry: 9400..9405 (see docs/guardian-driver.md).
// ---------------------------------------------------------------------------
#define GUARDIAN_EVT_PROC_CREATE   1   // process created (always logged)
#define GUARDIAN_EVT_PROC_EXIT     2   // process exited  (always logged)
#define GUARDIAN_EVT_ACCESS_DENIED 3   // Ob callback stripped/denied access to a protected PID
#define GUARDIAN_EVT_REG_DENIED    4   // Cm callback denied write/delete on a protected key
#define GUARDIAN_EVT_MODULE_REMAP  5   // ntdll/kernel32/amsi mapped twice into one PID
#define GUARDIAN_EVT_INJECT_QUEUED 6   // LoadLibrary APC queued on a target's initial thread
#define GUARDIAN_EVT_INJECT_FAILED 7   // placement attempted and failed (Value = NTSTATUS)

// Targeting modes for IOCTL_GUARDIAN_SET_TARGETING.
#define GUARDIAN_TARGET_OFF        0
#define GUARDIAN_TARGET_SANDBOX    1   // RootPid + all descendants (driver tracks lineage)
#define GUARDIAN_TARGET_STANDALONE 2   // image-name list match (+ optional follow children)

// Injection / targeting caps.
#define GUARDIAN_MAX_IMAGE_RULES 8
#define GUARDIAN_RULE_NAME_LEN   64

#pragma pack(push, 8)

// Unified ring event. Text carries an image path (create), a module path
// (remap), a registry key path (reg denied), or a DLL path (inject).
typedef struct _GUARDIAN_EVENT {
    LARGE_INTEGER Timestamp;      // KeQuerySystemTime (UTC FILETIME)
    ULONG Sequence;               // monotonically increasing, 1-based
    ULONG Type;                   // GUARDIAN_EVT_*
    ULONG ProcessId;              // acting process (access denied: the caller)
    ULONG TargetProcessId;        // affected process (proc events: the subject)
    ULONG ParentProcessId;        // proc-create only
    ULONG IsWow64;                // proc-create only
    ULONG Value;                  // access mask stripped / NTSTATUS / module id
    WCHAR Text[160];
} GUARDIAN_EVENT;

// IOCTL_GUARDIAN_PROTECT_PID input.
typedef struct _GUARDIAN_PROTECT_PID {
    ULONG Pid;
    ULONG Remove;                 // 0 = add to protected set, 1 = remove
} GUARDIAN_PROTECT_PID;

// IOCTL_GUARDIAN_SET_TARGETING input.
typedef struct _GUARDIAN_TARGETING {
    ULONG Mode;                   // GUARDIAN_TARGET_*
    ULONG RootPid;                // sandbox mode
    ULONG FollowChildren;         // standalone mode: also target children of matches
    ULONG Reserved;
    WCHAR ImageNames[GUARDIAN_MAX_IMAGE_RULES][GUARDIAN_RULE_NAME_LEN]; // standalone mode
} GUARDIAN_TARGETING;

// IOCTL_GUARDIAN_SET_INJECTION input. LoadLibrary addresses are the address
// of kernel32!LoadLibraryW AS THE REGISTERING PROCESS SEES IT -- system DLL
// bases are per-boot/per-bitness, so an x64 agent's address is valid for all
// x64 targets (same for a WoW64 agent's 32-bit address for x86 targets).
typedef struct _GUARDIAN_INJECTION {
    ULONG64 LoadLibraryX64;       // user-mode VA of kernel32!LoadLibraryW (x64)
    ULONG64 LoadLibraryX86;       // user-mode VA of kernel32!LoadLibraryW (x86, low 32 bits)
    WCHAR DllPathX64[260];
    WCHAR DllPathX86[260];
} GUARDIAN_INJECTION;

#pragma pack(pop)

#endif // GUARDIAN_IOCTL_H
