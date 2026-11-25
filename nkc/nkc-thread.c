/*
 * Conformance: system threads.
 *
 * Creating a system thread, what it sees when it runs, referencing it
 * through its handle, waiting for it to end, and what it is afterwards.
 */

#define NKC_DEVICE L"\\Device\\NkcThread"
#include "nkc.h"

typedef struct _NKC_THREAD_STATE {
    KEVENT Go;
    PVOID Creator;
    volatile LONG Ran;
    volatile LONG Irql;    /* IRQL the thread starts at */
    volatile LONG IsOther; /* 1 if it is not the creating thread */
    volatile LONG Context; /* 1 if it was given its context */
} NKC_THREAD_STATE;

static KSTART_ROUTINE NkcThread;

static VOID NkcThread(PVOID Context)
{
    NKC_THREAD_STATE *State = (NKC_THREAD_STATE *)Context;

    State->Irql = KeGetCurrentIrql();
    State->IsOther = (PsGetCurrentThread() != State->Creator);
    State->Context = 1;
    KeWaitForSingleObject(&State->Go, Executive, KernelMode, FALSE, NULL);
    InterlockedIncrement(&State->Ran);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NkcRun(NKC_LOG *Log)
{
    NKC_THREAD_STATE State;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Handle = NULL;
    PVOID Thread = NULL;
    PVOID Wrong = NULL;
    LARGE_INTEGER Limit;
    NTSTATUS Status;

    RtlZeroMemory(&State, sizeof(State));
    KeInitializeEvent(&State.Go, NotificationEvent, FALSE);
    State.Creator = PsGetCurrentThread();
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    /* 0: a system thread is created. */
    Status = PsCreateSystemThread(&Handle, THREAD_ALL_ACCESS, &Attributes, NULL, NULL, NkcThread,
                                  &State);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    /* 0xC0000024, 1: its handle is not a handle to an event, and no
     * object comes back. */
    Status = ObReferenceObjectByHandle(Handle, 0, *ExEventObjectType, KernelMode, &Wrong, NULL);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Wrong == NULL ? 1 : 0);

    /* 0, 0: it is a handle to a thread; then the handle can go. */
    Status = ObReferenceObjectByHandle(Handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
                                       &Thread, NULL);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, (ULONG)ZwClose(Handle));
    if (!NT_SUCCESS(Status)) {
        KeSetEvent(&State.Go, IO_NO_INCREMENT, FALSE);
        return;
    }

    /* 0x102: the thread has not ended (it waits to be told to), so a
     * wait for it with a time limit times out. */
    Limit.QuadPart = -100 * 10000;
    NkcPut(Log, (ULONG)KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, &Limit));

    /* 0: told to go, it ends, and a wait for it returns. */
    KeSetEvent(&State.Go, IO_NO_INCREMENT, FALSE);
    NkcPut(Log, (ULONG)KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL));

    /* 1, 0, 1, 1: it ran once, started at PASSIVE_LEVEL, was another
     * thread than its creator, and had its context. */
    NkcPut(Log, (ULONG)State.Ran);
    NkcPut(Log, (ULONG)State.Irql);
    NkcPut(Log, (ULONG)State.IsOther);
    NkcPut(Log, (ULONG)State.Context);

    /* 0: ended but still referenced, it is still an object, signalled. */
    Limit.QuadPart = 0;
    NkcPut(Log, (ULONG)KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, &Limit));
    ObDereferenceObject(Thread);

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
