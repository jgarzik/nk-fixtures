/*
 * Conformance: waiting on several objects at once.
 *
 * Wait-any and wait-all over events: which object a wait reports, what
 * it uses up, and that wait-all takes all or nothing.
 */

#define NKC_DEVICE L"\\Device\\NkcWaitN"
#define NKC_THREADS
#include "nkc.h"

#define NKC_OBJECTS 4

typedef struct _NKC_WAITN_STATE {
    KEVENT Events[NKC_OBJECTS];
    ULONG First; /* the event the helper sets first */
    ULONG Count; /* how many it sets, in rising order */
} NKC_WAITN_STATE;

static KSTART_ROUTINE NkcSetter;

/* After a pause, set `Count` events from `First` up, a pause apart. */
static VOID NkcSetter(PVOID Context)
{
    NKC_WAITN_STATE *State = (NKC_WAITN_STATE *)Context;
    ULONG i;

    for (i = 0; i < State->Count; i++) {
        NkcSleep(20);
        KeSetEvent(&State->Events[State->First + i], IO_NO_INCREMENT, FALSE);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static ULONG NkcWait(NKC_WAITN_STATE *State, ULONG Count, WAIT_TYPE Type, BOOLEAN Block)
{
    PVOID Objects[NKC_OBJECTS];
    KWAIT_BLOCK Blocks[NKC_OBJECTS];
    LARGE_INTEGER None;
    ULONG i;

    for (i = 0; i < Count; i++) {
        Objects[i] = &State->Events[i];
    }
    None.QuadPart = 0;
    return (ULONG)KeWaitForMultipleObjects(Count, Objects, Type, Executive, KernelMode, FALSE,
                                           Block ? NULL : &None, Blocks);
}

/* The states of the first `Count` events as bits, event 0 lowest. */
static ULONG NkcStates(NKC_WAITN_STATE *State, ULONG Count)
{
    ULONG Bits = 0;
    ULONG i;

    for (i = 0; i < Count; i++) {
        if (KeReadStateEvent(&State->Events[i]) != 0) {
            Bits |= 1u << i;
        }
    }
    return Bits;
}

static VOID NkcRun(NKC_LOG *Log)
{
    NKC_WAITN_STATE State;
    PVOID Thread;
    ULONG i;

    for (i = 0; i < NKC_OBJECTS; i++) {
        KeInitializeEvent(&State.Events[i], SynchronizationEvent, FALSE);
    }

    /* Wait-any over three events, without blocking.
     * 0x102: none is set.
     * 1, 0: with event 1 set, the wait reports 1 and uses it up.
     * 0, 4: with 2 and 0 set, it reports the lowest, 0, and leaves 2. */
    NkcPut(Log, NkcWait(&State, 3, WaitAny, FALSE));
    KeSetEvent(&State.Events[1], IO_NO_INCREMENT, FALSE);
    NkcPut(Log, NkcWait(&State, 3, WaitAny, FALSE));
    NkcPut(Log, NkcStates(&State, 3));
    KeSetEvent(&State.Events[2], IO_NO_INCREMENT, FALSE);
    KeSetEvent(&State.Events[0], IO_NO_INCREMENT, FALSE);
    NkcPut(Log, NkcWait(&State, 3, WaitAny, FALSE));
    NkcPut(Log, NkcStates(&State, 3));

    /* Wait-all over three events, without blocking.
     * 0x102, 4: with only event 2 set it fails and takes nothing.
     * 0, 0: with all three set it succeeds and uses up all three. */
    NkcPut(Log, NkcWait(&State, 3, WaitAll, FALSE));
    NkcPut(Log, NkcStates(&State, 3));
    KeSetEvent(&State.Events[0], IO_NO_INCREMENT, FALSE);
    KeSetEvent(&State.Events[1], IO_NO_INCREMENT, FALSE);
    NkcPut(Log, NkcWait(&State, 3, WaitAll, FALSE));
    NkcPut(Log, NkcStates(&State, 3));

    /* 3, 0: a blocking wait-any over four events returns when another
     * thread sets event 3, reporting 3 and using it up. */
    State.First = 3;
    State.Count = 1;
    Thread = NkcStart(NkcSetter, &State);
    NkcPut(Log, NkcWait(&State, 4, WaitAny, TRUE));
    NkcJoin(Thread);
    NkcPut(Log, NkcStates(&State, 4));

    /* 0, 0: a blocking wait-all over four events returns only when
     * another thread has set all four, one after another, and uses up
     * all four. */
    State.First = 0;
    State.Count = 4;
    Thread = NkcStart(NkcSetter, &State);
    NkcPut(Log, NkcWait(&State, 4, WaitAll, TRUE));
    NkcJoin(Thread);
    NkcPut(Log, NkcStates(&State, 4));

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
