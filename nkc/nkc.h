/*
 * NK conformance drivers: the part every one of them shares.
 *
 * A conformance driver exercises a few kernel routines and writes down
 * what it observed as a list of 32-bit values. The same binary is loaded
 * on real Windows and on NK; the two lists must be identical. That is
 * all a driver here is for, so each is as small as it can be:
 *
 *     #define NKC_DEVICE L"\\Device\\NkcIrql"
 *     #include "nkc.h"
 *     static void NkcRun(NKC_LOG *Log) { NkcPut(Log, KeGetCurrentIrql()); }
 *
 * The driver creates one device. A device-control request with code
 * NKC_IOCTL_RUN (buffered) runs NkcRun in the caller's thread, at
 * PASSIVE_LEVEL, and returns the values it logged, followed by NKC_END.
 * What each value means is written next to the NkcPut that logs it.
 *
 * A driver that defines NKC_CONTROL before including this file also
 * provides NkcControl, which is given every other device-control code
 * and returns the status the request completes with. One that defines
 * NKC_IRP_CONTROL instead provides NkcIrpControl, which is given every
 * other device-control request itself: to complete, or not, and to
 * return the dispatch routine's status for.
 *
 * A driver that defines NKC_LISTS as a number has that many lists and
 * also provides NkcRunList. List 0 is NkcRun's; list n, for n from 1,
 * is what NkcRunList(n, Log) logs, and answers the code NKC_IOCTL_LIST(n),
 * which is NKC_IOCTL_RUN + 4n. A driver splits its facts this way when
 * some of them rest on a contract nobody documents: if Windows stops at
 * one of those, the other lists are still to be had.
 *
 * A driver that defines NKC_SETUP also provides NkcSetup and NkcTeardown.
 * DriverEntry calls NkcSetup once the device exists and the dispatch
 * routines above are in place, so it may add entries of its own to the
 * driver's MajorFunction table; if it fails, the device is deleted and
 * DriverEntry fails with its status. The unload routine calls
 * NkcTeardown first, while the device still exists.
 *
 * Rules for NkcRun, so that the list is the same on every machine, on
 * both architectures and with any number of processors:
 *   - log facts (an IRQL, a return value, a count), never addresses,
 *     times or anything that depends on scheduling;
 *   - use only documented routines, the way a driver is meant to; the
 *     one exception is the marked set in nkc-undoc.h;
 *   - leave nothing behind: IRQL, locks and allocations as found.
 *
 * This file is NK's, not Microsoft's. It includes only <ntddk.h>.
 */

#include <ntddk.h>

#define NKC_IOCTL_LIST(n) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + (n), METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NKC_IOCTL_RUN NKC_IOCTL_LIST(0)
#define NKC_END 0x4E4B4321u /* "!CKN": the list is complete */
#define NKC_TAG 'ckNN'

typedef struct _NKC_LOG {
    ULONG *Values;
    ULONG Capacity;
    ULONG Count;
} NKC_LOG;

/* Log one value. Past the end of the caller's buffer it only counts. */
static VOID NkcPut(NKC_LOG *Log, ULONG Value)
{
    if (Log->Count < Log->Capacity) {
        Log->Values[Log->Count] = Value;
    }
    Log->Count++;
}

static VOID NkcRun(NKC_LOG *Log);
#ifdef NKC_LISTS
static VOID NkcRunList(ULONG List, NKC_LOG *Log);
#else
#define NKC_LISTS 1
#endif
#ifdef NKC_CONTROL
static NTSTATUS NkcControl(ULONG Code);
#endif
#ifdef NKC_IRP_CONTROL
static NTSTATUS NkcIrpControl(PIRP Irp, ULONG Code);
#endif
#ifdef NKC_SETUP
static NTSTATUS NkcSetup(PDRIVER_OBJECT Driver, PDEVICE_OBJECT Device);
static VOID NkcTeardown(PDRIVER_OBJECT Driver, PDEVICE_OBJECT Device);
#endif

/* The driver's one device, for the routines that want a device object. */
static PDEVICE_OBJECT NkcDeviceObject;

#ifdef NKC_THREADS
/*
 * Helper threads, for drivers that define NKC_THREADS before including
 * this file. NkcStart creates a system thread and returns the thread
 * object, referenced; NkcJoin waits for it to end and lets go of it.
 */
static PVOID NkcStart(PKSTART_ROUTINE Routine, PVOID Context)
{
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Handle;
    PVOID Thread = NULL;

    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(PsCreateSystemThread(&Handle, THREAD_ALL_ACCESS, &Attributes, NULL, NULL,
                                         Routine, Context))) {
        return NULL;
    }
    if (!NT_SUCCESS(ObReferenceObjectByHandle(Handle, THREAD_ALL_ACCESS, *PsThreadType,
                                              KernelMode, &Thread, NULL))) {
        Thread = NULL;
    }
    ZwClose(Handle);
    return Thread;
}

static VOID NkcJoin(PVOID Thread)
{
    if (Thread != NULL) {
        KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(Thread);
    }
}

/* Sleep for `Ms` milliseconds. */
static VOID NkcSleep(LONG Ms)
{
    LARGE_INTEGER Interval;

    Interval.QuadPart = -(LONGLONG)Ms * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &Interval);
}

/* Sleep until *Count reaches Wanted, for at most two seconds, then a
 * little longer in case it would overshoot; return what it reached. */
static LONG NkcSettle(volatile LONG *Count, LONG Wanted)
{
    ULONG Tries;

    for (Tries = 0; Tries < 200 && *Count < Wanted; Tries++) {
        NkcSleep(10);
    }
    NkcSleep(30);
    return *Count;
}

/*
 * Make a list on a system thread instead of the thread that asked for
 * it. The request's thread is its sender's: on Windows a thread of a
 * user process, with that process's token and handle table and with
 * user mode as its previous mode. A list about the System process, its
 * token, or handles in its table is made here, so that it does not
 * depend on who asked. NkcOnSystemThread runs Routine(Log) on a thread
 * of its own and waits for it to end; FALSE, and nothing logged, if the
 * thread could not be created.
 */
typedef VOID NKC_LIST_ROUTINE(NKC_LOG *Log);

typedef struct _NKC_ON_THREAD {
    NKC_LIST_ROUTINE *Routine;
    NKC_LOG *Log;
} NKC_ON_THREAD;

static KSTART_ROUTINE NkcOnThreadStart;

static VOID NkcOnThreadStart(PVOID Context)
{
    NKC_ON_THREAD *On = (NKC_ON_THREAD *)Context;

    On->Routine(On->Log);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static BOOLEAN NkcOnSystemThread(NKC_LIST_ROUTINE *Routine, NKC_LOG *Log)
{
    NKC_ON_THREAD On;
    PVOID Thread;

    On.Routine = Routine;
    On.Log = Log;
    Thread = NkcStart(NkcOnThreadStart, &On);
    if (Thread == NULL) {
        return FALSE;
    }
    NkcJoin(Thread);
    return TRUE;
}
#endif

static NTSTATUS NkcComplete(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS NkcCreateClose(PDEVICE_OBJECT Device, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Device);
    return NkcComplete(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS NkcDeviceControl(PDEVICE_OBJECT Device, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Code = Stack->Parameters.DeviceIoControl.IoControlCode;
    /* Which list the code asks for; a code below the first gives a
     * number past the last. */
    ULONG List = (Code - NKC_IOCTL_RUN) / 4;
    NKC_LOG Log;

    UNREFERENCED_PARAMETER(Device);
    if (List >= NKC_LISTS || Code != NKC_IOCTL_LIST(List)) {
#if defined(NKC_IRP_CONTROL)
        return NkcIrpControl(Irp, Code);
#elif defined(NKC_CONTROL)
        return NkcComplete(Irp, NkcControl(Code), 0);
#else
        return NkcComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
#endif
    }
    Log.Values = (ULONG *)Irp->AssociatedIrp.SystemBuffer;
    Log.Capacity = Stack->Parameters.DeviceIoControl.OutputBufferLength / sizeof(ULONG);
    Log.Count = 0;
#if NKC_LISTS > 1
    if (List != 0) {
        NkcRunList(List, &Log);
    } else
#endif
    {
        NkcRun(&Log);
    }
    NkcPut(&Log, NKC_END);
    if (Log.Count > Log.Capacity) {
        /* Say how much room the list needs rather than return part of it. */
        return NkcComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    return NkcComplete(Irp, STATUS_SUCCESS, Log.Count * sizeof(ULONG));
}

static VOID NkcUnload(PDRIVER_OBJECT Driver)
{
#ifdef NKC_SETUP
    NkcTeardown(Driver, NkcDeviceObject);
#endif
    IoDeleteDevice(Driver->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING Name;
    PDEVICE_OBJECT Device;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);
    RtlInitUnicodeString(&Name, NKC_DEVICE);
    Status = IoCreateDevice(Driver, 0, &Name, FILE_DEVICE_UNKNOWN, 0, FALSE, &Device);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    NkcDeviceObject = Device;
    Driver->MajorFunction[IRP_MJ_CREATE] = NkcCreateClose;
    Driver->MajorFunction[IRP_MJ_CLOSE] = NkcCreateClose;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NkcDeviceControl;
    Driver->DriverUnload = NkcUnload;
#ifdef NKC_SETUP
    Status = NkcSetup(Driver, Device);
    if (!NT_SUCCESS(Status)) {
        NkcDeviceObject = NULL;
        IoDeleteDevice(Device);
        return Status;
    }
#endif
    return STATUS_SUCCESS;
}
