// SandboxGuard.sys -- guardian driver for the Hyper-V malware sandbox.
//
// A0 spike scope (this file grows into the full WS-A driver):
//   - device \\.\SandboxGuard with IOCTL ping (handshake) + drain (event ring)
//   - PsSetCreateProcessNotifyRoutineEx logging every process create/exit
//     (image name, pid, parent pid, WoW64 flag) into a fixed ring buffer
//
// Proves, before any protection/injection code exists: the driver loads under
// the golden image's CI policy (testsigned), the process-notify callback
// registers and fires, and a user-mode client can reach the driver via IOCTL.
//
// Rules (hold for the full driver too): documented callbacks only, no
// undocumented structures, no IRQL games beyond spinlock-protected ring
// access. A bug here is a guest BSOD -- keep it tiny.

// ntifs.h (not ntddk.h): process-notify + helpers live there.
#include <ntifs.h>
#include <Ntstrsafe.h>
#include "guardian_ioctl.h"

// MSDN-documented and exported by ntoskrnl since Vista, but the 26100 WDK
// omits the prototype from its headers -- declare it ourselves.
NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process);

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD GuardianUnload;

// ---------------------------------------------------------------------------
// Event ring
// ---------------------------------------------------------------------------

#define GUARDIAN_RING_CAP 512

static GUARDIAN_PROC_EVENT g_Ring[GUARDIAN_RING_CAP];
static volatile LONG g_RingSeq = 0;   // monotonically increasing; index = (seq-1) % CAP
static KSPIN_LOCK g_RingLock;
static BOOLEAN g_NotifyRegistered = FALSE;

static void RingPush(ULONG pid, ULONG parentPid, ULONG isCreate, ULONG isWow64,
                     PCUNICODE_STRING imageName) {
    KIRQL irql;
    KeAcquireSpinLock(&g_RingLock, &irql);

    LONG seq = InterlockedIncrement(&g_RingSeq);
    GUARDIAN_PROC_EVENT* e = &g_Ring[(seq - 1) % GUARDIAN_RING_CAP];
    RtlZeroMemory(e, sizeof(*e));
    KeQuerySystemTime(&e->Timestamp);
    e->Sequence = (ULONG)seq;
    e->ProcessId = pid;
    e->ParentProcessId = parentPid;
    e->IsCreate = isCreate;
    e->IsWow64 = isWow64;
    if (imageName && imageName->Buffer) {
        SIZE_T chars = imageName->Length / sizeof(WCHAR);
        if (chars >= RTL_NUMBER_OF(e->ImageName)) chars = RTL_NUMBER_OF(e->ImageName) - 1;
        RtlCopyMemory(e->ImageName, imageName->Buffer, chars * sizeof(WCHAR));
    }

    KeReleaseSpinLock(&g_RingLock, irql);
}

// ---------------------------------------------------------------------------
// Process notify: log every create/exit. This callback is also where the A1
// injection-placement job (APC -> LoadLibraryW) will hook in; the spike only
// records.
// ---------------------------------------------------------------------------

static VOID GuardianProcessNotify(_In_ PEPROCESS Process, _In_ HANDLE ProcessId,
                                  _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (CreateInfo != NULL) {
        RingPush((ULONG)(ULONG_PTR)ProcessId,
                 (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId,
                 /*isCreate=*/1,
                 PsGetProcessWow64Process(Process) != NULL ? 1 : 0,
                 CreateInfo->ImageFileName);
    } else {
        RingPush((ULONG)(ULONG_PTR)ProcessId, 0, /*isCreate=*/0, 0, NULL);
    }
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

static NTSTATUS GuardianDeviceControl(_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_GUARDIAN_PING: {
        // Handshake: fixed signature so a guest client can tell "driver
        // present and ours" apart from "something else owns the name".
        static const ULONG64 kPong = GUARDIAN_PING_SIGNATURE;
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG64)) {
            *(ULONG64*)Irp->AssociatedIrp.SystemBuffer = kPong;
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
        ULONG outCap = stack->Parameters.DeviceIoControl.OutputBufferLength / sizeof(GUARDIAN_PROC_EVENT);
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (inLen < sizeof(ULONG) || outCap == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ULONG lastSeen = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
        GUARDIAN_PROC_EVENT* out = (GUARDIAN_PROC_EVENT*)Irp->AssociatedIrp.SystemBuffer;

        KIRQL irql;
        KeAcquireSpinLock(&g_RingLock, &irql);
        LONG head = g_RingSeq;
        // Oldest seq still in the ring (ring overwrites oldest first).
        LONG oldest = (head > GUARDIAN_RING_CAP) ? (head - GUARDIAN_RING_CAP + 1) : 1;
        LONG from = (LONG)lastSeen + 1;
        if (from < oldest) from = oldest;
        ULONG n = 0;
        for (LONG s = from; s <= head && n < outCap; s++, n++) {
            RtlCopyMemory(&out[n], &g_Ring[(s - 1) % GUARDIAN_RING_CAP], sizeof(GUARDIAN_PROC_EVENT));
        }
        KeReleaseSpinLock(&g_RingLock, irql);

        info = (ULONG_PTR)n * sizeof(GUARDIAN_PROC_EVENT);
        status = STATUS_SUCCESS;
        break;
    }
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
    if (g_NotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(GuardianProcessNotify, TRUE);
        g_NotifyRegistered = FALSE;
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

    KeInitializeSpinLock(&g_RingLock);
    RtlZeroMemory(g_Ring, sizeof(g_Ring));

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

    status = PsSetCreateProcessNotifyRoutineEx(GuardianProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SandboxGuard: PsSetCreateProcessNotifyRoutineEx failed 0x%x\n", status);
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(devObj);
        return status;
    }
    g_NotifyRegistered = TRUE;

    DbgPrint("SandboxGuard: loaded (A0 spike: process-notify logging)\n");
    return STATUS_SUCCESS;
}
