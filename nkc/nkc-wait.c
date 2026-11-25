/*
 * Conformance: waiting on one object.
 *
 * Events of both kinds, a semaphore and a timer as things to wait on,
 * time limits, and how many waiters one signal lets through.
 */

#define NKC_DEVICE L"\\Device\\NkcWait"
#define NKC_THREADS
#include "nkc.h"

#define NKC_WAITERS 3

typedef struct _NKC_WAIT_STATE {
    KEVENT Event;
    volatile LONG Woke;
} NKC_WAIT_STATE;

static KSTART_ROUTINE NkcWaiter;

static VOID NkcWaiter(PVOID Context)
{
    NKC_WAIT_STATE *State = (NKC_WAIT_STATE *)Context;

    KeWaitForSingleObject(&State->Event, Executive, KernelMode, FALSE, NULL);
    InterlockedIncrement(&State->Woke);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Wait with no time: report the object's state without blocking. */
static ULONG NkcPoll(PVOID Object)
{
    LARGE_INTEGER None;

    None.QuadPart = 0;
    return (ULONG)KeWaitForSingleObject(Object, Executive, KernelMode, FALSE, &None);
}

static VOID NkcRun(NKC_LOG *Log)
{
    NKC_WAIT_STATE State;
    KSEMAPHORE Semaphore;
    KTIMER Timer;
    PVOID Threads[NKC_WAITERS];
    LARGE_INTEGER Limit;
    ULONG i;

    /* Notification event.
     * 0, 0x102: not signalled, and a wait with no time says so.
     * 0, 1: setting it reports the state before, each time.
     * 0, 0: set, it lets every wait through and stays set.
     * 1, 0: resetting reports the state before, and clears it. */
    KeInitializeEvent(&State.Event, NotificationEvent, FALSE);
    NkcPut(Log, (ULONG)KeReadStateEvent(&State.Event));
    NkcPut(Log, NkcPoll(&State.Event));
    NkcPut(Log, (ULONG)KeSetEvent(&State.Event, IO_NO_INCREMENT, FALSE));
    NkcPut(Log, (ULONG)KeSetEvent(&State.Event, IO_NO_INCREMENT, FALSE));
    NkcPut(Log, NkcPoll(&State.Event));
    NkcPut(Log, NkcPoll(&State.Event));
    NkcPut(Log, (ULONG)KeResetEvent(&State.Event));
    NkcPut(Log, (ULONG)KeReadStateEvent(&State.Event));

    /* Synchronization event, created set.
     * 0, 0x102, 0: one wait takes it; the next finds it gone. */
    KeInitializeEvent(&State.Event, SynchronizationEvent, TRUE);
    NkcPut(Log, NkcPoll(&State.Event));
    NkcPut(Log, NkcPoll(&State.Event));
    NkcPut(Log, (ULONG)KeReadStateEvent(&State.Event));

    /* 0x102: a wait with a time limit on something never signalled. */
    Limit.QuadPart = -50 * 10000;
    NkcPut(Log, (ULONG)KeWaitForSingleObject(&State.Event, Executive, KernelMode, FALSE, &Limit));

    /* 0, 3: three threads wait on a notification event; none gets
     * through before it is set, and one setting lets all three through. */
    KeInitializeEvent(&State.Event, NotificationEvent, FALSE);
    State.Woke = 0;
    for (i = 0; i < NKC_WAITERS; i++) {
        Threads[i] = NkcStart(NkcWaiter, &State);
    }
    NkcSleep(50);
    NkcPut(Log, (ULONG)State.Woke);
    KeSetEvent(&State.Event, IO_NO_INCREMENT, FALSE);
    for (i = 0; i < NKC_WAITERS; i++) {
        NkcJoin(Threads[i]);
    }
    NkcPut(Log, (ULONG)State.Woke);

    /* 0, 1, 2, 3: on a synchronization event, each setting lets exactly
     * one of three waiting threads through. */
    KeInitializeEvent(&State.Event, SynchronizationEvent, FALSE);
    State.Woke = 0;
    for (i = 0; i < NKC_WAITERS; i++) {
        Threads[i] = NkcStart(NkcWaiter, &State);
    }
    NkcSleep(50);
    NkcPut(Log, (ULONG)State.Woke);
    for (i = 1; i <= NKC_WAITERS; i++) {
        KeSetEvent(&State.Event, IO_NO_INCREMENT, FALSE);
        NkcPut(Log, (ULONG)NkcSettle(&State.Woke, (LONG)i));
    }
    for (i = 0; i < NKC_WAITERS; i++) {
        NkcJoin(Threads[i]);
    }

    /* Semaphore with a count of 2 and a limit of 5.
     * 2: its count.
     * 0, 0, 0x102: two waits take the two; a third finds none.
     * 0, 3: releasing three reports the count before, and adds them. */
    KeInitializeSemaphore(&Semaphore, 2, 5);
    NkcPut(Log, (ULONG)KeReadStateSemaphore(&Semaphore));
    NkcPut(Log, NkcPoll(&Semaphore));
    NkcPut(Log, NkcPoll(&Semaphore));
    NkcPut(Log, NkcPoll(&Semaphore));
    NkcPut(Log, (ULONG)KeReleaseSemaphore(&Semaphore, IO_NO_INCREMENT, 3, FALSE));
    NkcPut(Log, (ULONG)KeReadStateSemaphore(&Semaphore));

    /* Timer with no DPC.
     * 0x102: not yet due, a wait with no time says so.
     * 0, 1: a wait for it returns when it goes off, and it is then
     * signalled. */
    KeInitializeTimer(&Timer);
    Limit.QuadPart = -20 * 10000;
    KeSetTimer(&Timer, Limit, NULL);
    NkcPut(Log, NkcPoll(&Timer));
    NkcPut(Log, (ULONG)KeWaitForSingleObject(&Timer, Executive, KernelMode, FALSE, NULL));
    NkcPut(Log, KeReadStateTimer(&Timer) ? 1 : 0);

    /* 0: a delay returns success. */
    Limit.QuadPart = -20 * 10000;
    NkcPut(Log, (ULONG)KeDelayExecutionThread(KernelMode, FALSE, &Limit));

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
