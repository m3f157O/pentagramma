// SandboxGuard.sys -- guardian driver for the Hyper-V malware sandbox.
//
// A1a scope (on top of the proven A0 skeleton):
//   - unified event ring (proc create/exit + guardian alert events)
//   - job 1: ObRegisterCallbacks -- strip dangerous access to protected PIDs
//   - job 2: CmRegisterCallbackEx -- deny write/delete on protected keys
//   - job 5: PsSetLoadImageNotifyRoutine -- ntdll/kernel32/amsi remap flag
//   - job 6: injection placement -- process+thread notify, kernel APC ->
//            user APC (LoadLibraryW) on the target's initial thread,
//            pre-entry-point
//
// Deferred to A1b: job 3 (minifilter file protection -- changes the driver
// model and install path) and job 4 (hook-integrity verifier thread).
//
// Rules (hold for the full driver too): documented callbacks only, no
// undocumented structures, no IRQL games beyond spinlock-protected state
// access. A bug here is a guest BSOD -- keep it tiny. All callbacks are
// inert until the agent registers state via IOCTL.

#include <ntifs.h>
#include <Ntstrsafe.h>
#include "guardian_ioctl.h"

// MSDN-documented and exported by ntoskrnl, but the 26100 WDK omits these
// prototypes from its headers -- declare them ourselves.
NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process);
NTKERNELAPI BOOLEAN PsIsProtectedProcess(_In_ PEPROCESS Process);

// --- Removed from the 26100 WDK headers but still exported by ntoskrnl and
// documented on MSDN (the standard EDR APC-injection machinery). KAPC itself
// is still defined in wdm.h; these companions are not.
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    InsertedApcEnvironment,
    CurrentApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID (NTAPI KNORMAL_ROUTINE)(
    _In_opt_ PVOID NormalContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2);
typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef VOID (NTAPI KKERNEL_ROUTINE)(
    _In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2);
typedef KKERNEL_ROUTINE* PKKERNEL_ROUTINE;

typedef VOID (NTAPI KRUNDOWN_ROUTINE)(_In_ PKAPC Apc);
typedef KRUNDOWN_ROUTINE* PKRUNDOWN_ROUTINE;

NTKERNELAPI VOID KeInitializeApc(
    _In_ PKAPC Apc, _In_ PKTHREAD Thread, _In_ KAPC_ENVIRONMENT ApcEnvironment,
    _In_ PKKERNEL_ROUTINE KernelRoutine, _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine, _In_ KPROCESSOR_MODE ApcMode,
    _In_opt_ PVOID NormalContext);
NTKERNELAPI BOOLEAN KeInsertQueueApc(
    _In_ PKAPC Apc, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment);

// Access-rights constants (stable ABI values; some are missing from the WDK
// kernel headers).
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE         0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD     0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION      0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE          0x0020
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION   0x0200
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE          0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME     0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT        0x0010
#endif

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD GuardianUnload;

// APC housekeeping (defined below; referenced by the injection path).
static VOID NTAPI GuardianFreeApcKernelRoutine(
    _In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2);
static VOID NTAPI GuardianFreeApcRundownRoutine(_In_ PKAPC Apc);

// ---------------------------------------------------------------------------
// Global state (guarded by g_StateLock)
// ---------------------------------------------------------------------------

#define GUARDIAN_RING_CAP   512
#define GUARDIAN_PROC_CAP   256
#define GUARDIAN_PROTECT_CAP 64

// Per-process tracking: lineage/targeting + remap flags.
#define PROC_F_TARGET    0x01   // matches targeting ruleset -> inject
#define PROC_F_INJECTED  0x02   // placement APC already queued
#define PROC_F_NTDLL     0x04   // ntdll.dll seen mapped
#define PROC_F_KERNEL32  0x08   // kernel32.dll seen mapped
#define PROC_F_AMSI      0x10   // amsi.dll seen mapped

typedef struct _GUARDIAN_PROC_ENTRY {
    ULONG Pid;                  // 0 = free slot
    ULONG ParentPid;
    ULONG Flags;
} GUARDIAN_PROC_ENTRY;

static GUARDIAN_EVENT g_Ring[GUARDIAN_RING_CAP];
static volatile LONG g_RingSeq = 0;   // index = (seq-1) % CAP
static GUARDIAN_PROC_ENTRY g_Procs[GUARDIAN_PROC_CAP];
static ULONG g_Protected[GUARDIAN_PROTECT_CAP];   // PIDs, 0 = free slot
static GUARDIAN_TARGETING g_Targeting;
static GUARDIAN_INJECTION g_Injection;
static BOOLEAN g_InjectionConfigured = FALSE;
// Registry protection stays INERT until the guardian agent registers its
// first protected PID (which happens right before the sample launches).
// Armed from boot it would block our OWN tooling -- telemetry_init's
// sysmon -c config update writes Services\Sysmon* and produced 20 false
// GuardianProtectedRegistry alerts on a benign run. Cleared by CLEAR_ALL.
static volatile BOOLEAN g_ProtectionArmed = FALSE;
static KSPIN_LOCK g_StateLock;

// Callback registration handles (for unload).
static BOOLEAN g_ProcessNotifyOn = FALSE;
static BOOLEAN g_ThreadNotifyOn = FALSE;
static BOOLEAN g_ImageNotifyOn = FALSE;
static PVOID   g_ObHandle = NULL;
static LARGE_INTEGER g_CmCookie = { 0 };
static BOOLEAN g_CmOn = FALSE;

// Never inject into these basenames (system/PPL/critical; a bad APC into
// csrss is a boot failure -- this list is review-critical code).
static const WCHAR* kInjectDenylist[] = {
    L"system",       // pseudo
    L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
    L"services.exe", L"lsass.exe", L"lsaiso.exe", L"svchost.exe",
    L"fontdrvhost.exe", L"dwm.exe", L"memory compression",
};

// Registry path fragments (uppercased) protected from write/delete.
static const WCHAR* kProtectedKeyFragments[] = {
    L"\\SERVICES\\SYSMON",          // Sysmon / Sysmon64 service + config
    L"\\SERVICES\\SANDBOXGUARD",
    L"\\MICROSOFT\\AMSI\\PROVIDERS",
    L"\\WINDOWS DEFENDER\\EXCLUSIONS",
    L"\\IMAGE FILE EXECUTION OPTIONS\\",
};

// Module basenames (uppercased, with leading backslash) tracked for remap.
static const WCHAR* kRemapWatchSuffixes[] = {
    L"\\NTDLL.DLL", L"\\KERNEL32.DLL", L"\\AMSI.DLL",
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// Case-insensitive "does the UNICODE_STRING contain this uppercase literal".
static BOOLEAN GuardianContainsUppercase(_In_ PCUNICODE_STRING Haystack,
                                         _In_ PCWSTR UpperNeedle) {
    if (!Haystack || !Haystack->Buffer || !UpperNeedle) return FALSE;
    SIZE_T needleLen = wcslen(UpperNeedle);
    SIZE_T hayChars = Haystack->Length / sizeof(WCHAR);
    if (needleLen == 0 || hayChars < needleLen) return FALSE;
    for (SIZE_T i = 0; i + needleLen <= hayChars; i++) {
        SIZE_T j = 0;
        for (; j < needleLen; j++) {
            WCHAR c = Haystack->Buffer[i + j];
            if (c >= L'a' && c <= L'z') c -= (L'a' - L'A');
            if (c != UpperNeedle[j]) break;
        }
        if (j == needleLen) return TRUE;
    }
    return FALSE;
}

// Case-insensitive basename match: does the image path end in "\name" or
// equal "name"?
static BOOLEAN GuardianBasenameMatch(_In_ PCUNICODE_STRING ImagePath,
                                     _In_ PCWSTR LowerName) {
    if (!ImagePath || !ImagePath->Buffer || !LowerName) return FALSE;
    SIZE_T nameLen = wcslen(LowerName);
    SIZE_T chars = ImagePath->Length / sizeof(WCHAR);
    if (nameLen == 0 || chars < nameLen) return FALSE;
    PCWSTR tail = ImagePath->Buffer + (chars - nameLen);
    for (SIZE_T i = 0; i < nameLen; i++) {
        WCHAR c = tail[i];
        if (c >= L'A' && c <= L'Z') c += (L'a' - L'A');
        if (c != LowerName[i]) return FALSE;
    }
    // Must be a full basename: preceded by '\\' or the whole string.
    return (chars == nameLen) || (ImagePath->Buffer[chars - nameLen - 1] == L'\\');
}

static void GuardianCopyText(_Out_writes_(RTL_NUMBER_OF(((GUARDIAN_EVENT*)0)->Text)) PWCHAR dst,
                             _In_opt_ PCUNICODE_STRING src) {
    dst[0] = L'\0';
    if (!src || !src->Buffer) return;
    SIZE_T chars = src->Length / sizeof(WCHAR);
    if (chars >= 160) chars = 159;
    RtlCopyMemory(dst, src->Buffer, chars * sizeof(WCHAR));
    dst[chars] = L'\0';
}

// Caller must hold g_StateLock.
static void GuardianPushEvent(_In_ ULONG type, _In_ ULONG actorPid, _In_ ULONG targetPid,
                              _In_ ULONG parentPid, _In_ ULONG isWow64, _In_ ULONG value,
                              _In_opt_ PCUNICODE_STRING text) {
    LONG seq = InterlockedIncrement(&g_RingSeq);
    GUARDIAN_EVENT* e = &g_Ring[(seq - 1) % GUARDIAN_RING_CAP];
    RtlZeroMemory(e, sizeof(*e));
    KeQuerySystemTime(&e->Timestamp);
    e->Sequence = (ULONG)seq;
    e->Type = type;
    e->ProcessId = actorPid;
    e->TargetProcessId = targetPid;
    e->ParentProcessId = parentPid;
    e->IsWow64 = isWow64;
    e->Value = value;
    GuardianCopyText(e->Text, text);
}

// Caller must hold g_StateLock.
static GUARDIAN_PROC_ENTRY* GuardianFindProc(_In_ ULONG pid) {
    for (ULONG i = 0; i < GUARDIAN_PROC_CAP; i++) {
        if (g_Procs[i].Pid == pid) return &g_Procs[i];
    }
    return NULL;
}

// Caller must hold g_StateLock.
static GUARDIAN_PROC_ENTRY* GuardianFindOrAddProc(_In_ ULONG pid, _In_ ULONG parentPid) {
    GUARDIAN_PROC_ENTRY* e = GuardianFindProc(pid);
    if (e) return e;
    for (ULONG i = 0; i < GUARDIAN_PROC_CAP; i++) {
        if (g_Procs[i].Pid == 0) {
            g_Procs[i].Pid = pid;
            g_Procs[i].ParentPid = parentPid;
            g_Procs[i].Flags = 0;
            return &g_Procs[i];
        }
    }
    return NULL;   // table full: untracked, no injection (fail-safe)
}

static BOOLEAN GuardianIsProtectedPid(_In_ ULONG pid) {
    KIRQL irql;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_StateLock, &irql);
    for (ULONG i = 0; i < GUARDIAN_PROTECT_CAP; i++) {
        if (g_Protected[i] == pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_StateLock, irql);
    return found;
}

// ---------------------------------------------------------------------------
// Job 6: injection placement
// ---------------------------------------------------------------------------

static BOOLEAN GuardianIsInjectDenied(_In_ PEPROCESS process, _In_ PCUNICODE_STRING imagePath) {
    if (PsIsProtectedProcess(process)) return TRUE;   // PPL: DLL can't load anyway
    for (ULONG i = 0; i < RTL_NUMBER_OF(kInjectDenylist); i++) {
        if (GuardianBasenameMatch(imagePath, kInjectDenylist[i])) return TRUE;
    }
    return FALSE;
}

// Runs in the TARGET process context (initial thread, PASSIVE_LEVEL, before
// user code). Allocates user memory for the DLL path and queues the
// LoadLibraryW user APC.
static VOID GuardianInjectKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2) {

    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePool(Apc);

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do {
        if (!g_InjectionConfigured) { status = STATUS_DEVICE_NOT_READY; break; }

        BOOLEAN wow64 = PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL;
        PCWSTR dllPath = wow64 ? g_Injection.DllPathX86 : g_Injection.DllPathX64;
        ULONG64 loadLib = wow64 ? g_Injection.LoadLibraryX86 : g_Injection.LoadLibraryX64;
        if (loadLib == 0 || dllPath[0] == L'\0') { status = STATUS_INVALID_PARAMETER; break; }

        // Write the DLL path into the target's user address space.
        SIZE_T bytes = (wcslen(dllPath) + 1) * sizeof(WCHAR);
        PVOID base = NULL;
        __try {
            status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &bytes,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(base, dllPath, bytes);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
        if (!NT_SUCCESS(status)) break;

        // Queue the user-mode APC: LoadLibraryW(dllPath) on this thread.
        PVOID apcRoutine = (PVOID)(ULONG_PTR)loadLib;
        PVOID apcContext = base;
        if (wow64) {
            // Documented: adjust routine/context for WoW64 APC delivery.
            status = PsWrapApcWow64Thread(&apcContext, &apcRoutine);
            if (!NT_SUCCESS(status)) break;
        }
        PKAPC userApc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'gApU');
        if (!userApc) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
        KeInitializeApc(userApc, PsGetCurrentThread(), OriginalApcEnvironment,
                        GuardianFreeApcKernelRoutine, GuardianFreeApcRundownRoutine,
                        (PKNORMAL_ROUTINE)apcRoutine, UserMode, apcContext);
        if (!KeInsertQueueApc(userApc, NULL, NULL, IO_NO_INCREMENT)) {
            ExFreePool(userApc);
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        KIRQL irql;
        KeAcquireSpinLock(&g_StateLock, &irql);
        GuardianPushEvent(GUARDIAN_EVT_INJECT_QUEUED, 0, pid, 0, wow64 ? 1 : 0, 0, NULL);
        KeReleaseSpinLock(&g_StateLock, irql);
        return;
    } while (FALSE);

    KIRQL irql;
    KeAcquireSpinLock(&g_StateLock, &irql);
    GuardianPushEvent(GUARDIAN_EVT_INJECT_FAILED, 0, pid, 0, 0, (ULONG)status, NULL);
    KeReleaseSpinLock(&g_StateLock, irql);
}

// Called from the thread-create notify (creator's context). Queues a special
// kernel APC on the target's initial thread; the real work happens in
// GuardianInjectKernelRoutine inside the target.
static VOID GuardianQueueInjection(_In_ HANDLE processId, _In_ HANDLE threadId) {
    PETHREAD thread = NULL;
    if (!NT_SUCCESS(PsLookupThreadByThreadId(threadId, &thread))) return;

    PKAPC apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'gApK');
    if (!apc) { ObDereferenceObject(thread); return; }

    KeInitializeApc(apc, thread, OriginalApcEnvironment,
                    GuardianInjectKernelRoutine, GuardianFreeApcRundownRoutine,
                    NULL, KernelMode, NULL);
    if (!KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT)) {
        ExFreePool(apc);
    } else {
        (void)processId;
    }
    ObDereferenceObject(thread);
}

static VOID GuardianThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create) {
    if (!Create) return;

    KIRQL irql;
    BOOLEAN inject = FALSE;
    KeAcquireSpinLock(&g_StateLock, &irql);
    GUARDIAN_PROC_ENTRY* e = GuardianFindProc((ULONG)(ULONG_PTR)ProcessId);
    if (e && (e->Flags & PROC_F_TARGET) && !(e->Flags & PROC_F_INJECTED)) {
        e->Flags |= PROC_F_INJECTED;
        inject = TRUE;
    }
    KeReleaseSpinLock(&g_StateLock, irql);

    if (inject) {
        GuardianQueueInjection(ProcessId, ThreadId);
    }
}

// ---------------------------------------------------------------------------
// Process notify: lineage tracking, targeting evaluation, proc events
// ---------------------------------------------------------------------------

// Decide whether a new process is an injection target.
// Caller must hold g_StateLock.
static BOOLEAN GuardianShouldTarget(_In_ ULONG pid, _In_ ULONG parentPid,
                                    _In_ PCUNICODE_STRING imagePath) {
    switch (g_Targeting.Mode) {
    case GUARDIAN_TARGET_SANDBOX:
        if (pid == g_Targeting.RootPid) return TRUE;
        if (parentPid != 0) {
            GUARDIAN_PROC_ENTRY* parent = GuardianFindProc(parentPid);
            if (parent && (parent->Flags & PROC_F_TARGET)) return TRUE;   // lineage survives direct-syscall spawns
        }
        return FALSE;
    case GUARDIAN_TARGET_STANDALONE:
        for (ULONG i = 0; i < GUARDIAN_MAX_IMAGE_RULES; i++) {
            if (g_Targeting.ImageNames[i][0] != L'\0' &&
                GuardianBasenameMatch(imagePath, g_Targeting.ImageNames[i])) return TRUE;
        }
        if (g_Targeting.FollowChildren && parentPid != 0) {
            GUARDIAN_PROC_ENTRY* parent = GuardianFindProc(parentPid);
            if (parent && (parent->Flags & PROC_F_TARGET)) return TRUE;
        }
        return FALSE;
    default:
        return FALSE;
    }
}

static VOID GuardianProcessNotify(_In_ PEPROCESS Process, _In_ HANDLE ProcessId,
                                  _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    KIRQL irql;

    if (CreateInfo != NULL) {
        ULONG parentPid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        ULONG wow64 = PsGetProcessWow64Process(Process) != NULL ? 1 : 0;
        // PsIsProtectedProcess IRQL is not documented -- evaluate before
        // taking the spinlock.
        BOOLEAN denied = GuardianIsInjectDenied(Process, CreateInfo->ImageFileName);

        KeAcquireSpinLock(&g_StateLock, &irql);
        GUARDIAN_PROC_ENTRY* e = GuardianFindOrAddProc(pid, parentPid);
        if (e) {
            if (!denied && GuardianShouldTarget(pid, parentPid, CreateInfo->ImageFileName)) {
                e->Flags |= PROC_F_TARGET;
            }
        }
        GuardianPushEvent(GUARDIAN_EVT_PROC_CREATE, 0, pid, parentPid, wow64, 0,
                          CreateInfo->ImageFileName);
        KeReleaseSpinLock(&g_StateLock, irql);
    } else {
        KeAcquireSpinLock(&g_StateLock, &irql);
        GUARDIAN_PROC_ENTRY* e = GuardianFindProc(pid);
        if (e) e->Pid = 0;   // free the slot
        GuardianPushEvent(GUARDIAN_EVT_PROC_EXIT, 0, pid, 0, 0, 0, NULL);
        KeReleaseSpinLock(&g_StateLock, irql);
    }
}

// ---------------------------------------------------------------------------
// Job 5: module-remap detection via image-load notify
// ---------------------------------------------------------------------------

static VOID GuardianImageNotify(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId,
                                _In_ PIMAGE_INFO ImageInfo) {
    UNREFERENCED_PARAMETER(ImageInfo);
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    if (pid == 0 || !FullImageName || !FullImageName->Buffer) return;   // driver load

    ULONG flag = 0;
    if (GuardianBasenameMatch(FullImageName, kRemapWatchSuffixes[0])) flag = PROC_F_NTDLL;
    else if (GuardianBasenameMatch(FullImageName, kRemapWatchSuffixes[1])) flag = PROC_F_KERNEL32;
    else if (GuardianBasenameMatch(FullImageName, kRemapWatchSuffixes[2])) flag = PROC_F_AMSI;
    if (flag == 0) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_StateLock, &irql);
    GUARDIAN_PROC_ENTRY* e = GuardianFindProc(pid);
    if (e) {
        if (e->Flags & flag) {
            // Second mapping of an already-loaded module into this PID.
            GuardianPushEvent(GUARDIAN_EVT_MODULE_REMAP, 0, pid, 0, 0, flag, FullImageName);
        } else {
            e->Flags |= flag;
        }
    }
    KeReleaseSpinLock(&g_StateLock, irql);
}

// ---------------------------------------------------------------------------
// APC housekeeping. Both the kernel APC and the user APC are pool-allocated;
// the kernel routine / rundown routine must free them (documented pattern).
// ---------------------------------------------------------------------------

static VOID NTAPI GuardianFreeApcKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2) {
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePool(Apc);
}

static VOID NTAPI GuardianFreeApcRundownRoutine(_In_ PKAPC Apc) {
    ExFreePool(Apc);
}

// ---------------------------------------------------------------------------
// Job 1: ObRegisterCallbacks -- strip dangerous access rights when the
// target of the open belongs to the protected set (agent, Sysmon, us).
// ---------------------------------------------------------------------------

// Access bits we strip from opens of protected processes.
#define GUARDIAN_STRIP_PROCESS (PROCESS_TERMINATE | PROCESS_VM_WRITE | \
                                PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | \
                                PROCESS_SET_INFORMATION)
#define GUARDIAN_STRIP_THREAD  (THREAD_TERMINATE | THREAD_SET_CONTEXT | \
                                THREAD_SUSPEND_RESUME)

static BOOLEAN GuardianCallerExempt(_In_ ULONG callerPid) {
    // System and protected processes keep full access (Sysmon must be able to
    // query itself, services.exe manages services, etc.).
    if (callerPid == 0 || callerPid == 4) return TRUE;
    return GuardianIsProtectedPid(callerPid);
}

static OB_PREOP_CALLBACK_STATUS GuardianObPreCallback(
    _In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (GuardianCallerExempt(callerPid)) return OB_PREOP_SUCCESS;

    BOOLEAN isProcess = (OperationInfo->ObjectType == *PsProcessType);
    ULONG targetPid;
    ULONG strip;
    if (isProcess) {
        targetPid = (ULONG)(ULONG_PTR)PsGetProcessId((PEPROCESS)OperationInfo->Object);
        strip = GUARDIAN_STRIP_PROCESS;
    } else if (OperationInfo->ObjectType == *PsThreadType) {
        targetPid = (ULONG)(ULONG_PTR)PsGetThreadProcessId((PETHREAD)OperationInfo->Object);
        strip = GUARDIAN_STRIP_THREAD;
    } else {
        return OB_PREOP_SUCCESS;
    }

    if (!GuardianIsProtectedPid(targetPid)) return OB_PREOP_SUCCESS;

    ACCESS_MASK original = 0;
    ACCESS_MASK* desired = NULL;
    if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desired = &OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
    }
    if (!desired) return OB_PREOP_SUCCESS;

    original = *desired;
    *desired &= ~(ACCESS_MASK)strip;
    ACCESS_MASK stripped = original & strip;
    if (stripped != 0) {
        KIRQL irql;
        KeAcquireSpinLock(&g_StateLock, &irql);
        GuardianPushEvent(GUARDIAN_EVT_ACCESS_DENIED, callerPid, targetPid, 0, 0,
                          (ULONG)stripped, NULL);
        KeReleaseSpinLock(&g_StateLock, irql);
    }
    return OB_PREOP_SUCCESS;
}

// ---------------------------------------------------------------------------
// Job 2: CmRegisterCallbackEx -- deny write/delete on protected keys.
// ---------------------------------------------------------------------------

static NTSTATUS GuardianCmCallback(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1,
                                   _In_opt_ PVOID Argument2) {
    UNREFERENCED_PARAMETER(CallbackContext);

    if (!g_ProtectionArmed) return STATUS_SUCCESS;   // inert until armed

    REG_NOTIFY_CLASS op = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PVOID object = NULL;
    switch (op) {
    case RegNtPreSetValueKey:    object = ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object; break;
    case RegNtPreDeleteKey:      object = ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object; break;
    case RegNtPreDeleteValueKey: object = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->Object; break;
    case RegNtPreRenameKey:      object = ((PREG_RENAME_KEY_INFORMATION)Argument2)->Object; break;
    default: return STATUS_SUCCESS;
    }

    PCUNICODE_STRING keyName = NULL;
    NTSTATUS status = CmCallbackGetKeyObjectIDEx(&g_CmCookie, object, NULL, &keyName, 0);
    if (!NT_SUCCESS(status) || !keyName) return STATUS_SUCCESS;

    BOOLEAN protect = FALSE;
    for (ULONG i = 0; i < RTL_NUMBER_OF(kProtectedKeyFragments); i++) {
        if (GuardianContainsUppercase(keyName, kProtectedKeyFragments[i])) { protect = TRUE; break; }
    }

    if (protect) {
        ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        KIRQL irql;
        KeAcquireSpinLock(&g_StateLock, &irql);
        GuardianPushEvent(GUARDIAN_EVT_REG_DENIED, callerPid, 0, 0, 0, (ULONG)op, keyName);
        KeReleaseSpinLock(&g_StateLock, irql);
    }

    CmCallbackReleaseKeyObjectIDEx(keyName);
    return protect ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Device + IOCTL
// ---------------------------------------------------------------------------

static NTSTATUS GuardianCreateClose(_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Inert-by-default: CLEAR_ALL zeroes all registration state; callbacks
// no-op until the agent registers targeting/protection/injection.
static void GuardianClearAll(void) {
    KIRQL irql;
    KeAcquireSpinLock(&g_StateLock, &irql);
    RtlZeroMemory(g_Procs, sizeof(g_Procs));
    RtlZeroMemory(g_Protected, sizeof(g_Protected));
    RtlZeroMemory(&g_Targeting, sizeof(g_Targeting));
    RtlZeroMemory(&g_Injection, sizeof(g_Injection));
    g_InjectionConfigured = FALSE;
    g_ProtectionArmed = FALSE;
    KeReleaseSpinLock(&g_StateLock, irql);
}

static NTSTATUS GuardianDeviceControl(_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_GUARDIAN_PING: {
        static const ULONG64 kPong = GUARDIAN_PING_SIGNATURE;
        if (outLen >= sizeof(ULONG64)) {
            *(ULONG64*)buf = kPong;
            info = sizeof(ULONG64);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_GUARDIAN_DRAIN: {
        // Input: ULONG last-seen sequence. Output: array of events with
        // Sequence > lastSeen, oldest first, capped by the output buffer.
        ULONG outCap = outLen / sizeof(GUARDIAN_EVENT);
        if (inLen < sizeof(ULONG) || outCap == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ULONG lastSeen = *(ULONG*)buf;
        GUARDIAN_EVENT* out = (GUARDIAN_EVENT*)buf;

        KIRQL irql;
        KeAcquireSpinLock(&g_StateLock, &irql);
        LONG head = g_RingSeq;
        LONG oldest = (head > GUARDIAN_RING_CAP) ? (head - GUARDIAN_RING_CAP + 1) : 1;
        LONG from = (LONG)lastSeen + 1;
        if (from < oldest) from = oldest;
        ULONG n = 0;
        for (LONG s = from; s <= head && n < outCap; s++, n++) {
            RtlCopyMemory(&out[n], &g_Ring[(s - 1) % GUARDIAN_RING_CAP], sizeof(GUARDIAN_EVENT));
        }
        KeReleaseSpinLock(&g_StateLock, irql);

        info = (ULONG_PTR)n * sizeof(GUARDIAN_EVENT);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_GUARDIAN_PROTECT_PID: {
        if (inLen < sizeof(GUARDIAN_PROTECT_PID)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        GUARDIAN_PROTECT_PID* req = (GUARDIAN_PROTECT_PID*)buf;
        KIRQL irql;
        KeAcquireSpinLock(&g_StateLock, &irql);
        if (req->Remove) {
            for (ULONG i = 0; i < GUARDIAN_PROTECT_CAP; i++) {
                if (g_Protected[i] == req->Pid) g_Protected[i] = 0;
            }
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
            BOOLEAN have = FALSE;
            for (ULONG i = 0; i < GUARDIAN_PROTECT_CAP; i++) {
                if (g_Protected[i] == req->Pid) { have = TRUE; break; }
            }
            if (have) {
                status = STATUS_SUCCESS;
            } else {
                for (ULONG i = 0; i < GUARDIAN_PROTECT_CAP; i++) {
                    if (g_Protected[i] == 0) { g_Protected[i] = req->Pid; status = STATUS_SUCCESS; break; }
                }
            }
            if (NT_SUCCESS(status)) g_ProtectionArmed = TRUE;
        }
        KeReleaseSpinLock(&g_StateLock, irql);
        break;
    }

    case IOCTL_GUARDIAN_SET_TARGETING: {
        if (inLen < sizeof(GUARDIAN_TARGETING)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        KIRQL irql;
        KeAcquireSpinLock(&g_StateLock, &irql);
        RtlCopyMemory(&g_Targeting, buf, sizeof(GUARDIAN_TARGETING));
        g_Targeting.ImageNames[GUARDIAN_MAX_IMAGE_RULES - 1][GUARDIAN_RULE_NAME_LEN - 1] = L'\0';
        KeReleaseSpinLock(&g_StateLock, irql);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_GUARDIAN_SET_INJECTION: {
        if (inLen < sizeof(GUARDIAN_INJECTION)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        KIRQL irql;
        KeAcquireSpinLock(&g_StateLock, &irql);
        RtlCopyMemory(&g_Injection, buf, sizeof(GUARDIAN_INJECTION));
        g_Injection.DllPathX64[259] = L'\0';
        g_Injection.DllPathX86[259] = L'\0';
        g_InjectionConfigured = TRUE;
        KeReleaseSpinLock(&g_StateLock, irql);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_GUARDIAN_CLEAR_ALL:
        GuardianClearAll();
        status = STATUS_SUCCESS;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ---------------------------------------------------------------------------
// Entry / unload
// ---------------------------------------------------------------------------

VOID GuardianUnload(_In_ PDRIVER_OBJECT DriverObject) {
    if (g_ObHandle) {
        ObUnRegisterCallbacks(g_ObHandle);
        g_ObHandle = NULL;
    }
    if (g_CmOn) {
        CmUnRegisterCallback(g_CmCookie);
        g_CmOn = FALSE;
    }
    if (g_ProcessNotifyOn) {
        PsSetCreateProcessNotifyRoutineEx(GuardianProcessNotify, TRUE);
        g_ProcessNotifyOn = FALSE;
    }
    if (g_ThreadNotifyOn) {
        PsRemoveCreateThreadNotifyRoutine(GuardianThreadNotify);
        g_ThreadNotifyOn = FALSE;
    }
    if (g_ImageNotifyOn) {
        PsRemoveLoadImageNotifyRoutine(GuardianImageNotify);
        g_ImageNotifyOn = FALSE;
    }
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, GUARDIAN_SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    DbgPrint("SandboxGuard: unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&g_StateLock);
    RtlZeroMemory(g_Ring, sizeof(g_Ring));
    RtlZeroMemory(g_Procs, sizeof(g_Procs));
    RtlZeroMemory(g_Protected, sizeof(g_Protected));
    RtlZeroMemory(&g_Targeting, sizeof(g_Targeting));
    RtlZeroMemory(&g_Injection, sizeof(g_Injection));

    UNICODE_STRING devName, symName;
    RtlInitUnicodeString(&devName, GUARDIAN_DEVICE_NAME);
    RtlInitUnicodeString(&symName, GUARDIAN_SYMLINK_NAME);

    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                                     FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SandboxGuard: IoCreateDevice failed 0x%x\n", status);
        return status;
    }
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SandboxGuard: IoCreateSymbolicLink failed 0x%x\n", status);
        IoDeleteDevice(devObj);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = GuardianCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = GuardianCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = GuardianDeviceControl;
    DriverObject->DriverUnload = GuardianUnload;

    // --- job 1: Ob callbacks (process + thread). Altitude is a registration
    // detail for Ob callbacks; any well-formed numeric string works.
    OB_OPERATION_REGISTRATION obOps[2] = { 0 };
    obOps[0].ObjectType = PsProcessType;
    obOps[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOps[0].PreOperation = GuardianObPreCallback;
    obOps[1].ObjectType = PsThreadType;
    obOps[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOps[1].PreOperation = GuardianObPreCallback;

    OB_CALLBACK_REGISTRATION obReg = { 0 };
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 2;
    RtlInitUnicodeString(&obReg.Altitude, L"300000");
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = obOps;

    status = ObRegisterCallbacks(&obReg, &g_ObHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SandboxGuard: ObRegisterCallbacks failed 0x%x\n", status);
        goto fail;
    }

    // --- job 2: Cm callback.
    {
        UNICODE_STRING cmAltitude;
        RtlInitUnicodeString(&cmAltitude, L"300001");
        // NB: parameter order is (Function, Altitude, Driver, Context,
        // Cookie, Reserved) -- Context BEFORE Cookie. Getting this wrong
        // compiles fine (PVOID) and bugchecks 0x7E in DriverEntry on a NULL
        // cookie write.
        status = CmRegisterCallbackEx(GuardianCmCallback, &cmAltitude, DriverObject,
                                      NULL, &g_CmCookie, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("SandboxGuard: CmRegisterCallbackEx failed 0x%x\n", status);
            goto fail;
        }
        g_CmOn = TRUE;
    }

    // --- process + thread notify (lineage / targeting / injection).
    status = PsSetCreateProcessNotifyRoutineEx(GuardianProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SandboxGuard: PsSetCreateProcessNotifyRoutineEx failed 0x%x\n", status);
        goto fail;
    }
    g_ProcessNotifyOn = TRUE;

    status = PsSetCreateThreadNotifyRoutine(GuardianThreadNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SandboxGuard: PsSetCreateThreadNotifyRoutine failed 0x%x\n", status);
        goto fail;
    }
    g_ThreadNotifyOn = TRUE;

    // --- job 5: image-load notify (module remap).
    status = PsSetLoadImageNotifyRoutine(GuardianImageNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SandboxGuard: PsSetLoadImageNotifyRoutine failed 0x%x\n", status);
        goto fail;
    }
    g_ImageNotifyOn = TRUE;

    DbgPrint("SandboxGuard: loaded (A1a: protect + remap + injection placement)\n");
    return STATUS_SUCCESS;

fail:
    GuardianUnload(DriverObject);
    return status;
}
