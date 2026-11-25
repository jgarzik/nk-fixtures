/*
 * Conformance: mutexes, fast mutexes and critical regions.
 *
 * Ownership, recursion and what the routines report; what holding each
 * does to the IRQL and to APC delivery; and what a second thread sees.
 */

#define NKC_DEVICE L"\\Device\\NkcMutex"
#define NKC_THREADS
#include "nkc.h"

typedef struct _NKC_MUTEX_STATE {
    KMUTEX Mutex;
    FAST_MUTEX Fast;
    volatile LONG Mutex1; /* what the other thread got from the mutex */
    volatile LONG Fast1;  /* and from the fast mutex */
} NKC_MUTEX_STATE;

static KSTART_ROUTINE NkcOther;

/* Another thread tries for both without waiting, and lets go of what it
 * got. */
static VOID NkcOther(PVOID Context)
{
    NKC_MUTEX_STATE *State = (NKC_MUTEX_STATE *)Context;
    LARGE_INTEGER None;
    NTSTATUS Status;

    None.QuadPart = 0;
    Status = KeWaitForSingleObject(&State->Mutex, Executive, KernelMode, FALSE, &None);
    State->Mutex1 = (LONG)Status;
    if (Status == STATUS_SUCCESS) {
        KeReleaseMutex(&State->Mutex, FALSE);
    }
    if (ExTryToAcquireFastMutex(&State->Fast)) {
        State->Fast1 = 1;
        ExReleaseFastMutex(&State->Fast);
    } else {
        State->Fast1 = 0;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NkcRun(NKC_LOG *Log)
{
    NKC_MUTEX_STATE State;

    RtlZeroMemory(&State, sizeof(State));
    KeInitializeMutex(&State.Mutex, 0);
    ExInitializeFastMutex(&State.Fast);

    /* Mutex.
     * 1, 1: free, it reads 1. APCs are disabled already: the I/O manager
     * calls a dispatch routine inside a critical region, and every
     * "APCs disabled?" answer below is 1 for that reason alone.
     * 0, 0, 1: taken, it reads 0.
     * 0, -1: its owner may take it again; it then reads -1. */
    NkcPut(Log, (ULONG)KeReadStateMutex(&State.Mutex));
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);
    NkcPut(Log, (ULONG)KeWaitForSingleObject(&State.Mutex, Executive, KernelMode, FALSE, NULL));
    NkcPut(Log, (ULONG)KeReadStateMutex(&State.Mutex));
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);
    NkcPut(Log, (ULONG)KeWaitForSingleObject(&State.Mutex, Executive, KernelMode, FALSE, NULL));
    NkcPut(Log, (ULONG)KeReadStateMutex(&State.Mutex));

    /* Fast mutex.
     * 1: taking it raises the IRQL to APC_LEVEL. */
    ExAcquireFastMutex(&State.Fast);
    NkcPut(Log, KeGetCurrentIrql());

    /* 0x102, 0: another thread gets neither while they are held. */
    State.Mutex1 = -1;
    State.Fast1 = -1;
    NkcJoin(NkcStart(NkcOther, &State));
    NkcPut(Log, (ULONG)State.Mutex1);
    NkcPut(Log, (ULONG)State.Fast1);

    /* 0: releasing the fast mutex restores the IRQL. */
    ExReleaseFastMutex(&State.Fast);
    NkcPut(Log, KeGetCurrentIrql());

    /* -1, 0, 1, 1: each release reports the state before; after as many
     * releases as takings it is free. */
    NkcPut(Log, (ULONG)KeReleaseMutex(&State.Mutex, FALSE));
    NkcPut(Log, (ULONG)KeReleaseMutex(&State.Mutex, FALSE));
    NkcPut(Log, (ULONG)KeReadStateMutex(&State.Mutex));
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);

    /* 0, 1: now another thread gets both. */
    State.Mutex1 = -1;
    State.Fast1 = -1;
    NkcJoin(NkcStart(NkcOther, &State));
    NkcPut(Log, (ULONG)State.Mutex1);
    NkcPut(Log, (ULONG)State.Fast1);

    /* Critical region.
     * 1, 0: inside one APCs are disabled, and the IRQL is not raised.
     * 0: the unsafe fast-mutex routines, meant for use inside one, do
     * not raise it either.
     * 1: outside this one, the dispatch routine is still inside the I/O
     * manager's. */
    KeEnterCriticalRegion();
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);
    NkcPut(Log, KeGetCurrentIrql());
    ExAcquireFastMutexUnsafe(&State.Fast);
    NkcPut(Log, KeGetCurrentIrql());
    ExReleaseFastMutexUnsafe(&State.Fast);
    KeLeaveCriticalRegion();
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
