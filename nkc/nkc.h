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

#define NKC_IOCTL_RUN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
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
    NKC_LOG Log;

    UNREFERENCED_PARAMETER(Device);
    if (Stack->Parameters.DeviceIoControl.IoControlCode != NKC_IOCTL_RUN) {
        return NkcComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    Log.Values = (ULONG *)Irp->AssociatedIrp.SystemBuffer;
    Log.Capacity = Stack->Parameters.DeviceIoControl.OutputBufferLength / sizeof(ULONG);
    Log.Count = 0;
    NkcRun(&Log);
    NkcPut(&Log, NKC_END);
    if (Log.Count > Log.Capacity) {
        /* Say how much room the list needs rather than return part of it. */
        return NkcComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    return NkcComplete(Irp, STATUS_SUCCESS, Log.Count * sizeof(ULONG));
}

static VOID NkcUnload(PDRIVER_OBJECT Driver)
{
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
    return STATUS_SUCCESS;
}
