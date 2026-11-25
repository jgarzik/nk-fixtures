/*
 * Conformance: IRQL and spin locks.
 *
 * What a driver sees when it raises and lowers the IRQL, takes spin
 * locks of each kind, and allocates pool at DISPATCH_LEVEL.
 */

#define NKC_DEVICE L"\\Device\\NkcIrql"
#include "nkc.h"

static VOID NkcRun(NKC_LOG *Log)
{
    KIRQL Old, Old2;
    KSPIN_LOCK Lock;
    KLOCK_QUEUE_HANDLE Handle;
    PVOID Block;

    /* 0: a device-control request arrives at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());

    /* 0, 1: raising to APC_LEVEL reports the old level and takes effect. */
    KeRaiseIrql(APC_LEVEL, &Old);
    NkcPut(Log, Old);
    NkcPut(Log, KeGetCurrentIrql());

    /* 1, 2: and from there to DISPATCH_LEVEL. */
    KeRaiseIrql(DISPATCH_LEVEL, &Old2);
    NkcPut(Log, Old2);
    NkcPut(Log, KeGetCurrentIrql());

    /* 1, 0: lowering goes back the way it came. */
    KeLowerIrql(Old2);
    NkcPut(Log, KeGetCurrentIrql());
    KeLowerIrql(Old);
    NkcPut(Log, KeGetCurrentIrql());

    /* 0, 2, 0: KeRaiseIrqlToDpcLevel returns the level it left. */
    Old = KeRaiseIrqlToDpcLevel();
    NkcPut(Log, Old);
    NkcPut(Log, KeGetCurrentIrql());
    KeLowerIrql(Old);
    NkcPut(Log, KeGetCurrentIrql());

    /* 0, 15, 0: all the way to HIGH_LEVEL and back. */
    KeRaiseIrql(HIGH_LEVEL, &Old);
    NkcPut(Log, Old);
    NkcPut(Log, KeGetCurrentIrql());
    KeLowerIrql(Old);
    NkcPut(Log, KeGetCurrentIrql());

    /* 0, 2, 0: an ordinary spin lock raises to DISPATCH_LEVEL while held. */
    KeInitializeSpinLock(&Lock);
    KeAcquireSpinLock(&Lock, &Old);
    NkcPut(Log, Old);
    NkcPut(Log, KeGetCurrentIrql());
    KeReleaseSpinLock(&Lock, Old);
    NkcPut(Log, KeGetCurrentIrql());

    /* 2, 2, 0: taken at DISPATCH_LEVEL it leaves the level alone. */
    KeRaiseIrql(DISPATCH_LEVEL, &Old);
    KeAcquireSpinLockAtDpcLevel(&Lock);
    NkcPut(Log, KeGetCurrentIrql());
    KeReleaseSpinLockFromDpcLevel(&Lock);
    NkcPut(Log, KeGetCurrentIrql());
    KeLowerIrql(Old);
    NkcPut(Log, KeGetCurrentIrql());

    /* 1, 0, 1: a try succeeds on a free lock and fails on a held one. */
    KeRaiseIrql(DISPATCH_LEVEL, &Old);
    NkcPut(Log, KeTryToAcquireSpinLockAtDpcLevel(&Lock) ? 1 : 0);
    NkcPut(Log, KeTryToAcquireSpinLockAtDpcLevel(&Lock) ? 1 : 0);
    KeReleaseSpinLockFromDpcLevel(&Lock);
    NkcPut(Log, KeTryToAcquireSpinLockAtDpcLevel(&Lock) ? 1 : 0);
    KeReleaseSpinLockFromDpcLevel(&Lock);
    KeLowerIrql(Old);

    /* 0, 2, 0: a queued spin lock keeps the old level in its handle. */
    KeAcquireInStackQueuedSpinLock(&Lock, &Handle);
    NkcPut(Log, Handle.OldIrql);
    NkcPut(Log, KeGetCurrentIrql());
    KeReleaseInStackQueuedSpinLock(&Handle);
    NkcPut(Log, KeGetCurrentIrql());

    /* 1, 0x5A: non-paged pool can be allocated and used at DISPATCH_LEVEL. */
    KeRaiseIrql(DISPATCH_LEVEL, &Old);
    Block = ExAllocatePoolWithTag(NonPagedPool, 64, NKC_TAG);
    NkcPut(Log, Block != NULL ? 1 : 0);
    if (Block != NULL) {
        RtlFillMemory(Block, 64, 0x5A);
        NkcPut(Log, ((UCHAR *)Block)[63]);
        ExFreePoolWithTag(Block, NKC_TAG);
    } else {
        NkcPut(Log, 0);
    }
    KeLowerIrql(Old);

    /* 0: and the driver leaves the level as it found it. */
    NkcPut(Log, KeGetCurrentIrql());
}
