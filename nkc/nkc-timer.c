/*
 * Conformance: kernel timers with a DPC.
 *
 * Setting, re-setting and cancelling a timer, what its DPC sees, the
 * timer's signalled state, and a periodic timer.
 */

#define NKC_DEVICE L"\\Device\\NkcTimer"
#include "nkc.h"

typedef struct _NKC_TIMER_STATE {
    volatile LONG Runs;
    volatile LONG Irql;
} NKC_TIMER_STATE;

static KDEFERRED_ROUTINE NkcTimerRoutine;

static VOID NkcTimerRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    NKC_TIMER_STATE *State = (NKC_TIMER_STATE *)Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    State->Irql = KeGetCurrentIrql();
    InterlockedIncrement(&State->Runs);
}

/* Wait, without blocking, for `Wanted` runs; give up after two seconds. */
static LONG NkcAwait(NKC_TIMER_STATE *State, LONG Wanted)
{
    ULONG Tries;

    for (Tries = 0; Tries < 2000 && State->Runs < Wanted; Tries++) {
        KeStallExecutionProcessor(1000);
    }
    return State->Runs;
}

static VOID NkcStallMs(ULONG Ms)
{
    while (Ms-- != 0) {
        KeStallExecutionProcessor(1000);
    }
}

/* A relative due time, in the 100 ns units timers use. */
static LARGE_INTEGER NkcMs(LONG Ms)
{
    LARGE_INTEGER Due;

    Due.QuadPart = -(LONGLONG)Ms * 10000;
    return Due;
}

static VOID NkcRun(NKC_LOG *Log)
{
    NKC_TIMER_STATE State = { 0, -1 };
    KTIMER Timer;
    KDPC Dpc;
    LONG Seen;

    KeInitializeTimer(&Timer);
    KeInitializeDpc(&Dpc, NkcTimerRoutine, &State);

    /* 0: a new timer is not signalled. */
    NkcPut(Log, KeReadStateTimer(&Timer) ? 1 : 0);

    /* 0, 1, 2, 1: setting an idle timer reports it was not queued; its DPC
     * runs once, at DISPATCH_LEVEL; the timer is then signalled. */
    NkcPut(Log, KeSetTimer(&Timer, NkcMs(20), &Dpc) ? 1 : 0);
    NkcPut(Log, (ULONG)NkcAwait(&State, 1));
    NkcPut(Log, (ULONG)State.Irql);
    NkcPut(Log, KeReadStateTimer(&Timer) ? 1 : 0);

    /* 0, 0, 1, 0: setting it again clears the signal; setting a queued
     * timer reports that it was queued. */
    NkcPut(Log, KeSetTimer(&Timer, NkcMs(60000), &Dpc) ? 1 : 0);
    NkcPut(Log, KeReadStateTimer(&Timer) ? 1 : 0);
    NkcPut(Log, KeSetTimer(&Timer, NkcMs(60000), &Dpc) ? 1 : 0);
    NkcPut(Log, KeReadStateTimer(&Timer) ? 1 : 0);

    /* 1, 0, 1: cancelling a queued timer succeeds once, and its DPC does
     * not run. */
    NkcPut(Log, KeCancelTimer(&Timer) ? 1 : 0);
    NkcPut(Log, KeCancelTimer(&Timer) ? 1 : 0);
    NkcStallMs(50);
    NkcPut(Log, (ULONG)State.Runs);

    /* 0, 1, 1: a timer cancelled before it is due never fires. */
    NkcPut(Log, KeSetTimer(&Timer, NkcMs(40), &Dpc) ? 1 : 0);
    NkcPut(Log, KeCancelTimer(&Timer) ? 1 : 0);
    NkcStallMs(100);
    NkcPut(Log, (ULONG)State.Runs);

    /* 0, 1: a due time already past fires at once. */
    NkcPut(Log, KeSetTimer(&Timer, NkcMs(0), &Dpc) ? 1 : 0);
    NkcPut(Log, NkcAwait(&State, 2) == 2 ? 1 : 0);

    /* 0, 1, 1, 1: a periodic timer keeps firing until cancelled, and
     * then stops. */
    NkcPut(Log, KeSetTimerEx(&Timer, NkcMs(10), 10, &Dpc) ? 1 : 0);
    NkcPut(Log, NkcAwait(&State, 5) >= 5 ? 1 : 0);
    NkcPut(Log, KeCancelTimer(&Timer) ? 1 : 0);
    NkcStallMs(40);
    Seen = State.Runs;
    NkcStallMs(100);
    NkcPut(Log, State.Runs == Seen ? 1 : 0);

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
