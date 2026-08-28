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

#define IOCTL_GUARDIAN_PING  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARDIAN_DRAIN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

// One process create/exit record (A0 spike event; A1 adds guardian alert
// events on separate EIDs via the same ring).
#pragma pack(push, 8)
typedef struct _GUARDIAN_PROC_EVENT {
    LARGE_INTEGER Timestamp;      // KeQuerySystemTime (UTC FILETIME)
    ULONG Sequence;               // monotonically increasing, 1-based
    ULONG ProcessId;
    ULONG ParentProcessId;        // create only
    ULONG IsCreate;               // 1 = create, 0 = exit
    ULONG IsWow64;                // create only
    ULONG Reserved;
    WCHAR ImageName[128];         // full image path (create only)
} GUARDIAN_PROC_EVENT;
#pragma pack(pop)

#endif // GUARDIAN_IOCTL_H
