/*
 * Conformance: deferred procedure calls.
 *
 * Queueing a DPC from PASSIVE_LEVEL and from DISPATCH_LEVEL, what the
 * routine sees when it runs, queueing one twice, and removing one.
 */

#define NKC_DEVICE L"\\Device\\NkcDpc"
#include "nkc.h"

typedef struct _NKC_DPC_STATE {
    volatile LONG Runs;
    volatile LONG Irql;      /* IRQL seen by the routine */
    volatile LONG Arguments; /* 1 if context and both arguments arrived */
} NKC_DPC_STATE;

static KDEFERRED_ROUTINE NkcDpcRoutine;

static VOID NkcDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    NKC_DPC_STATE *State = (NKC_DPC_STATE *)Context;

    UNREFERENCED_PARAMETER(Dpc);
    State->Irql = KeGetCurrentIrql();
    State->Arguments = (Arg1 == (PVOID)(ULONG_PTR)0x1111 && Arg2 == (PVOID)(ULONG_PTR)0x2222);
    InterlockedIncrement(&State->Runs);
}

/* Wait, without blocking, for the routine to have run `Wanted` times.
 * Gives up after a second; returns the count seen. */
static LONG NkcAwait(NKC_DPC_STATE *State, LONG Wanted)
{
    ULONG Tries;

    for (Tries = 0; Tries < 1000 && State->Runs < Wanted; Tries++) {
        KeStallExecutionProcessor(1000);
    }
    return State->Runs;
}

static VOID NkcRun(NKC_LOG *Log)
{
    NKC_DPC_STATE State = { 0, -1, 0 };
    KDPC Dpc;
    KIRQL Old;

    KeInitializeDpc(&Dpc, NkcDpcRoutine, &State);

    /* 1, 1, 2, 1: queued from PASSIVE_LEVEL, a DPC is accepted, runs once,
     * at DISPATCH_LEVEL, with its context and arguments. */
    NkcPut(Log, KeInsertQueueDpc(&Dpc, (PVOID)(ULONG_PTR)0x1111, (PVOID)(ULONG_PTR)0x2222) ? 1 : 0);
    NkcPut(Log, (ULONG)NkcAwait(&State, 1));
    NkcPut(Log, (ULONG)State.Irql);
    NkcPut(Log, (ULONG)State.Arguments);

    /* 1, 0, 1: at DISPATCH_LEVEL a DPC is accepted once; a second insert
     * of the same DPC while it waits is refused; and it does not run
     * while the level stays raised. */
    KeRaiseIrql(DISPATCH_LEVEL, &Old);
    NkcPut(Log, KeInsertQueueDpc(&Dpc, (PVOID)(ULONG_PTR)0x1111, (PVOID)(ULONG_PTR)0x2222) ? 1 : 0);
    NkcPut(Log, KeInsertQueueDpc(&Dpc, (PVOID)(ULONG_PTR)0x1111, (PVOID)(ULONG_PTR)0x2222) ? 1 : 0);
    KeStallExecutionProcessor(2000);
    NkcPut(Log, (ULONG)State.Runs);
    KeLowerIrql(Old);

    /* 2: lowering the level lets it run, once. */
    NkcPut(Log, (ULONG)NkcAwait(&State, 2));

    /* 1, 0, 2: a waiting DPC can be removed, once, and then never runs. */
    KeRaiseIrql(DISPATCH_LEVEL, &Old);
    KeInsertQueueDpc(&Dpc, (PVOID)(ULONG_PTR)0x1111, (PVOID)(ULONG_PTR)0x2222);
    NkcPut(Log, KeRemoveQueueDpc(&Dpc) ? 1 : 0);
    NkcPut(Log, KeRemoveQueueDpc(&Dpc) ? 1 : 0);
    KeLowerIrql(Old);
    KeStallExecutionProcessor(20000);
    NkcPut(Log, (ULONG)State.Runs);

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
