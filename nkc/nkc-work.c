/*
 * Conformance: work items.
 *
 * Queueing work to a system worker thread, from a thread and from a
 * DPC, and what the routine sees when it runs.
 */

#define NKC_DEVICE L"\\Device\\NkcWork"
#include "nkc.h"

typedef struct _NKC_WORK_STATE {
    KEVENT Done;
    PVOID Caller;
    PIO_WORKITEM Item;
    WORK_QUEUE_ITEM Old;
    volatile LONG Runs;
    volatile LONG Irql;     /* IRQL the routine runs at */
    volatile LONG IsOther;  /* 1 if it runs in another thread */
    volatile LONG DeviceOk; /* 1 if it is given the device */
} NKC_WORK_STATE;

static IO_WORKITEM_ROUTINE NkcWork;
static WORKER_THREAD_ROUTINE NkcOldWork;
static KDEFERRED_ROUTINE NkcQueueFromDpc;

static VOID NkcSeen(NKC_WORK_STATE *State)
{
    State->Irql = KeGetCurrentIrql();
    State->IsOther = (PsGetCurrentThread() != State->Caller);
    InterlockedIncrement(&State->Runs);
    KeSetEvent(&State->Done, IO_NO_INCREMENT, FALSE);
}

static VOID NkcWork(PDEVICE_OBJECT Device, PVOID Context)
{
    NKC_WORK_STATE *State = (NKC_WORK_STATE *)Context;

    State->DeviceOk = (Device == NkcDeviceObject);
    NkcSeen(State);
}

static VOID NkcOldWork(PVOID Context)
{
    NkcSeen((NKC_WORK_STATE *)Context);
}

static VOID NkcQueueFromDpc(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    NKC_WORK_STATE *State = (NKC_WORK_STATE *)Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    IoQueueWorkItem(State->Item, NkcWork, DelayedWorkQueue, State);
}

/* Wait up to two seconds for the routine to say it ran. */
static ULONG NkcAwait(NKC_WORK_STATE *State)
{
    LARGE_INTEGER Limit;

    Limit.QuadPart = -2000 * 10000;
    return (ULONG)KeWaitForSingleObject(&State->Done, Executive, KernelMode, FALSE, &Limit);
}

static VOID NkcRun(NKC_LOG *Log)
{
    NKC_WORK_STATE State;
    KDPC Dpc;

    RtlZeroMemory(&State, sizeof(State));
    KeInitializeEvent(&State.Done, SynchronizationEvent, FALSE);
    State.Caller = PsGetCurrentThread();

    /* 1: a work item is allocated. */
    State.Item = IoAllocateWorkItem(NkcDeviceObject);
    NkcPut(Log, State.Item != NULL ? 1 : 0);
    if (State.Item == NULL) {
        return;
    }

    /* 0, 1, 0, 1, 1: queued from a thread, the routine runs once, at
     * PASSIVE_LEVEL, in another thread, and is given the device. */
    State.Irql = -1;
    IoQueueWorkItem(State.Item, NkcWork, DelayedWorkQueue, &State);
    NkcPut(Log, NkcAwait(&State));
    NkcPut(Log, (ULONG)State.Runs);
    NkcPut(Log, (ULONG)State.Irql);
    NkcPut(Log, (ULONG)State.IsOther);
    NkcPut(Log, (ULONG)State.DeviceOk);

    /* 0, 2: the same item can be queued again once its routine has run. */
    IoQueueWorkItem(State.Item, NkcWork, DelayedWorkQueue, &State);
    NkcPut(Log, NkcAwait(&State));
    NkcPut(Log, (ULONG)State.Runs);

    /* 0, 3, 0: queued from a DPC, at DISPATCH_LEVEL, the routine still
     * runs at PASSIVE_LEVEL. */
    State.Irql = -1;
    KeInitializeDpc(&Dpc, NkcQueueFromDpc, &State);
    KeInsertQueueDpc(&Dpc, NULL, NULL);
    NkcPut(Log, NkcAwait(&State));
    NkcPut(Log, (ULONG)State.Runs);
    NkcPut(Log, (ULONG)State.Irql);
    IoFreeWorkItem(State.Item);

    /* 0, 4, 0, 1: the older interface, an item the driver itself owns,
     * runs its routine the same way. */
    State.Irql = -1;
    State.IsOther = -1;
#pragma warning(push)
#pragma warning(disable : 4996) /* ExQueueWorkItem is deprecated, and still used */
    ExInitializeWorkItem(&State.Old, NkcOldWork, &State);
    ExQueueWorkItem(&State.Old, DelayedWorkQueue);
#pragma warning(pop)
    NkcPut(Log, NkcAwait(&State));
    NkcPut(Log, (ULONG)State.Runs);
    NkcPut(Log, (ULONG)State.Irql);
    NkcPut(Log, (ULONG)State.IsOther);

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
