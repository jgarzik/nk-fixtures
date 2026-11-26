/*
 * Conformance: the executive's locks, lists, timers and pool variants.
 *
 * Push locks, sequenced singly linked lists, lookaside lists, executive
 * resources (ERESOURCE), executive timers, ExUuidCreate, and the pool
 * routines that take a priority or charge quota.
 *
 * The list is in that order, one routine of this file per group. A
 * comment before each group of NkcPut calls says what Windows is
 * predicted to answer; where the prediction is a guess it says so.
 *
 * What is never logged: a lock word while a thread waits on it (it is
 * then an address), a list header's second quadword (an address), a
 * UUID's time or node. Of a lock word with waiters only the low four
 * bits are logged; of a list header only the first quadword's low half:
 * the depth, and the low 16 bits of the sequence number.
 *
 * Where another thread must be seen to wait, the driver sleeps until
 * that thread says it is about to ask, then a little longer, and logs
 * that it has not been let in. Nothing else here depends on timing.
 *
 * Of the undocumented routines in nkc-undoc.h this driver uses the six
 * push-lock routines, and __C_specific_handler (one __try).
 *
 * The lookaside lists' allocate and free are code from the kit's headers,
 * compiled into this driver: what they show of a kernel is the fields it
 * initialised and its list routines.
 */

/* ExTryToAcquireResourceExclusiveLite is declared for file systems. The
 * pool routines here are the ones Microsoft's drivers of this Windows
 * import; a newer kit's advice to use others is not wanted. */
#include <ntifs.h>
#pragma warning(disable : 4996)

#define NKC_DEVICE L"\\Device\\NkcEx"
#define NKC_THREADS
#include "nkc.h"
#include "nkc-undoc.h"

#define NKC_MARK 0xE8000000u
#define MARK(n) NkcPut(Log, NKC_MARK | (n))

/* Always zero, and the compiler cannot know it. */
static volatile ULONG NkcZero;

static ULONG NkcBool(BOOLEAN Value)
{
    /* A BOOLEAN is one byte: whatever else the register held is not it. */
    return (ULONG)(UCHAR)Value;
}

/* What a helper thread is asked to do, and what it saw. */
typedef struct _NKC_HELPER {
    ULONG Mode;
    volatile LONG Stage; /* 1: about to ask for what may make it wait */
    volatile LONG Got;   /* 1: it was let in */
    ULONG Tried[2];      /* answers of requests that do not wait */
    KEVENT Go;           /* set by NkcRun: let go and end */
} NKC_HELPER;

static VOID NkcHelperInit(NKC_HELPER *Helper, ULONG Mode)
{
    RtlZeroMemory(Helper, sizeof(*Helper));
    Helper->Mode = Mode;
    Helper->Tried[0] = Helper->Tried[1] = 0xEEEEEEEE;
    KeInitializeEvent(&Helper->Go, NotificationEvent, FALSE);
}

static VOID NkcHelperWaitGo(NKC_HELPER *Helper)
{
    KeWaitForSingleObject(&Helper->Go, Executive, KernelMode, FALSE, NULL);
}

/* ---- Push locks --------------------------------------------------------- */

static ULONG_PTR NkcPushLock;

/* The lock word when nobody waits: its low half, or all ones if the
 * high half is not zero. */
static ULONG NkcWord(VOID)
{
    ULONG_PTR Word = NkcPushLock;

    return (Word >> 32) != 0 ? 0xFFFFFFFF : (ULONG)Word;
}

#define NKC_PL_EXCLUSIVE 1 /* try, then acquire exclusive, release */
#define NKC_PL_SHARED 2    /* acquire shared, wait for Go, release */

static VOID NkcPushLockThread(PVOID Context)
{
    NKC_HELPER *Helper = (NKC_HELPER *)Context;

    KeEnterCriticalRegion();
    if (Helper->Mode == NKC_PL_EXCLUSIVE) {
        Helper->Tried[0] = NkcBool(ExTryAcquirePushLockExclusiveEx(&NkcPushLock, 0));
        if (Helper->Tried[0] != 0) {
            ExReleasePushLockExclusiveEx(&NkcPushLock, 0);
        }
        InterlockedExchange(&Helper->Stage, 1);
        ExAcquirePushLockExclusiveEx(&NkcPushLock, 0);
        InterlockedExchange(&Helper->Got, 1);
        NkcHelperWaitGo(Helper);
        ExReleasePushLockExclusiveEx(&NkcPushLock, 0);
    } else {
        InterlockedExchange(&Helper->Stage, 1);
        ExAcquirePushLockSharedEx(&NkcPushLock, 0);
        InterlockedExchange(&Helper->Got, 1);
        NkcHelperWaitGo(Helper);
        ExReleasePushLockSharedEx(&NkcPushLock, 0);
    }
    KeLeaveCriticalRegion();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NkcPushLocks(NKC_LOG *Log)
{
    NKC_HELPER Helper;
    PVOID Thread;

    MARK(0x10);
    NkcPushLock = 0;
    KeEnterCriticalRegion();

    /* 1: held exclusively, the word is the Locked bit alone.
     * 0, 1: it cannot be had again without waiting, and stays as it was.
     * 0: released. */
    ExAcquirePushLockExclusiveEx(&NkcPushLock, 0);
    NkcPut(Log, NkcWord());
    NkcPut(Log, NkcBool(ExTryAcquirePushLockExclusiveEx(&NkcPushLock, 0)));
    NkcPut(Log, NkcWord());
    ExReleasePushLockExclusiveEx(&NkcPushLock, 0);
    NkcPut(Log, NkcWord());

    /* 1, 1, 0: a free lock is had by trying; the release that is told
     * nothing about how the lock is held lets it go. */
    NkcPut(Log, NkcBool(ExTryAcquirePushLockExclusiveEx(&NkcPushLock, 0)));
    NkcPut(Log, NkcWord());
    ExReleasePushLockEx(&NkcPushLock, 0);
    NkcPut(Log, NkcWord());

    /* 0x11, 0x21: held shared once, then twice: the Locked bit, and the
     * number of holders from bit 4 up.
     * 0, 0x21: it cannot be had exclusively by trying.
     * 0x11, 0: let go once by the shared release, once by the plain one. */
    ExAcquirePushLockSharedEx(&NkcPushLock, 0);
    NkcPut(Log, NkcWord());
    ExAcquirePushLockSharedEx(&NkcPushLock, 0);
    NkcPut(Log, NkcWord());
    NkcPut(Log, NkcBool(ExTryAcquirePushLockExclusiveEx(&NkcPushLock, 0)));
    NkcPut(Log, NkcWord());
    ExReleasePushLockSharedEx(&NkcPushLock, 0);
    NkcPut(Log, NkcWord());
    ExReleasePushLockEx(&NkcPushLock, 0);
    NkcPut(Log, NkcWord());

    /* Held exclusively here, wanted exclusively by another thread.
     * 1, 0: that thread got as far as asking; trying gave it nothing.
     * 0: it has not been let in.
     * 3: the word's low bits are Locked and Waiting.
     * 1: released here, it is let in.
     * 0: and when it has let go the word is zero again. */
    MARK(0x11);
    ExAcquirePushLockExclusiveEx(&NkcPushLock, 0);
    NkcHelperInit(&Helper, NKC_PL_EXCLUSIVE);
    Thread = NkcStart(NkcPushLockThread, &Helper);
    if (Thread != NULL) {
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Stage, 1));
        NkcPut(Log, Helper.Tried[0]);
        NkcPut(Log, (ULONG)Helper.Got);
        NkcPut(Log, (ULONG)(NkcPushLock & 0xF));
        ExReleasePushLockExclusiveEx(&NkcPushLock, 0);
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Got, 1));
        KeSetEvent(&Helper.Go, IO_NO_INCREMENT, FALSE);
        NkcJoin(Thread);
    } else {
        ExReleasePushLockExclusiveEx(&NkcPushLock, 0);
    }
    NkcPut(Log, NkcWord());

    /* Held shared here, wanted shared by another thread.
     * 1, 0x21: it is let in at once: two holders.
     * 0x11, 0: it lets go, then this thread does. */
    MARK(0x12);
    ExAcquirePushLockSharedEx(&NkcPushLock, 0);
    NkcHelperInit(&Helper, NKC_PL_SHARED);
    Thread = NkcStart(NkcPushLockThread, &Helper);
    if (Thread != NULL) {
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Got, 1));
        NkcPut(Log, NkcWord());
        KeSetEvent(&Helper.Go, IO_NO_INCREMENT, FALSE);
        NkcJoin(Thread);
    }
    NkcPut(Log, NkcWord());
    ExReleasePushLockSharedEx(&NkcPushLock, 0);
    NkcPut(Log, NkcWord());

    /* Held shared here, wanted exclusively by another thread.
     * 1, 0: it asked, and trying gave it nothing.
     * 0, 3: it waits; Locked and Waiting (one holder: not MultipleShared).
     * 1, 0: let in when the holder lets go; zero when it has let go. */
    MARK(0x13);
    ExAcquirePushLockSharedEx(&NkcPushLock, 0);
    NkcHelperInit(&Helper, NKC_PL_EXCLUSIVE);
    Thread = NkcStart(NkcPushLockThread, &Helper);
    if (Thread != NULL) {
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Stage, 1));
        NkcPut(Log, Helper.Tried[0]);
        NkcPut(Log, (ULONG)Helper.Got);
        NkcPut(Log, (ULONG)(NkcPushLock & 0xF));
        ExReleasePushLockSharedEx(&NkcPushLock, 0);
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Got, 1));
        KeSetEvent(&Helper.Go, IO_NO_INCREMENT, FALSE);
        NkcJoin(Thread);
    } else {
        ExReleasePushLockSharedEx(&NkcPushLock, 0);
    }
    NkcPut(Log, NkcWord());

    /* Held exclusively here, wanted shared by another thread.
     * 1, 0, 3: it asked and waits; Locked and Waiting.
     * 1, 0x11: let in when the holder lets go, as the one shared holder.
     * 0: zero when it has let go. */
    MARK(0x14);
    ExAcquirePushLockExclusiveEx(&NkcPushLock, 0);
    NkcHelperInit(&Helper, NKC_PL_SHARED);
    Thread = NkcStart(NkcPushLockThread, &Helper);
    if (Thread != NULL) {
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Stage, 1));
        NkcPut(Log, (ULONG)Helper.Got);
        NkcPut(Log, (ULONG)(NkcPushLock & 0xF));
        ExReleasePushLockExclusiveEx(&NkcPushLock, 0);
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Got, 1));
        NkcPut(Log, NkcWord());
        KeSetEvent(&Helper.Go, IO_NO_INCREMENT, FALSE);
        NkcJoin(Thread);
    } else {
        ExReleasePushLockExclusiveEx(&NkcPushLock, 0);
    }
    NkcPut(Log, NkcWord());

    KeLeaveCriticalRegion();
}

/* ---- Sequenced singly linked lists -------------------------------------- */

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _NKC_ITEM {
    SLIST_ENTRY Entry;
    ULONG Number;
} NKC_ITEM;

#define NKC_STRESS 64

static SLIST_HEADER NkcList;
static KSPIN_LOCK NkcListLock; /* the Ex macros name one; 64-bit ignores it */
static NKC_ITEM NkcItems[3];
static NKC_ITEM NkcStress[2][NKC_STRESS];

/* The depth, and the low 16 bits of the sequence number above it. */
static ULONG NkcHeader(VOID)
{
    return (ULONG)NkcList.Alignment;
}

/* The number of the item an entry is in; 0 for no entry. */
static ULONG NkcNumber(PSLIST_ENTRY Entry)
{
    return Entry == NULL ? 0 : CONTAINING_RECORD(Entry, NKC_ITEM, Entry)->Number;
}

static VOID NkcListThread(PVOID Context)
{
    NKC_ITEM *Items = (NKC_ITEM *)Context;
    ULONG i;

    for (i = 0; i < NKC_STRESS; i++) {
        InterlockedPushEntrySList(&NkcList, &Items[i].Entry);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NkcLists(NKC_LOG *Log)
{
    PSLIST_ENTRY Entry;
    PVOID Thread;
    ULONG i, Count, Sum;

    MARK(0x20);
    KeInitializeSpinLock(&NkcListLock);
    for (i = 0; i < 3; i++) {
        NkcItems[i].Number = i + 1;
    }

    /* 0, 0, 0: an initialised list: depth, header, nothing to pop. */
    RtlFillMemory(&NkcList, sizeof(NkcList), 0xEE);
    InitializeSListHead(&NkcList);
    NkcPut(Log, ExQueryDepthSList(&NkcList));
    NkcPut(Log, NkcHeader());
    NkcPut(Log, NkcNumber(ExInterlockedPopEntrySList(&NkcList, &NkcListLock)));

    /* A push returns the entry that was first before it.
     * 0, 1, 0x00010001: the first push: depth 1, sequence 1.
     * 1, 2, 0x00020002: the second.
     * 2, 3, 0x00030003: the third. */
    for (i = 0; i < 3; i++) {
        Entry = ExInterlockedPushEntrySList(&NkcList, &NkcItems[i].Entry, &NkcListLock);
        NkcPut(Log, NkcNumber(Entry));
        NkcPut(Log, ExQueryDepthSList(&NkcList));
        NkcPut(Log, NkcHeader());
    }

    /* 3, 2, 0x00030002: a pop takes the last one pushed; the depth goes
     * down and the sequence number stays. */
    NkcPut(Log, NkcNumber(ExInterlockedPopEntrySList(&NkcList, &NkcListLock)));
    NkcPut(Log, ExQueryDepthSList(&NkcList));
    NkcPut(Log, NkcHeader());

    /* 2, 1, 0: a flush hands back the chain: the second item, which
     * leads to the first, which leads nowhere.
     * 0, 0x00030000: the list is empty, the sequence number kept. */
    Entry = ExInterlockedFlushSList(&NkcList);
    NkcPut(Log, NkcNumber(Entry));
    Entry = Entry == NULL ? NULL : Entry->Next;
    NkcPut(Log, NkcNumber(Entry));
    Entry = Entry == NULL ? NULL : Entry->Next;
    NkcPut(Log, NkcNumber(Entry));
    NkcPut(Log, ExQueryDepthSList(&NkcList));
    NkcPut(Log, NkcHeader());

    /* 0, 0, 0x00030000: nothing to flush, nothing to pop, nothing changed. */
    NkcPut(Log, NkcNumber(InterlockedFlushSList(&NkcList)));
    NkcPut(Log, NkcNumber(InterlockedPopEntrySList(&NkcList)));
    NkcPut(Log, NkcHeader());

    /* 0, 0x00040001: the sequence number goes on from where it was. */
    NkcPut(Log, NkcNumber(InterlockedPushEntrySList(&NkcList, &NkcItems[0].Entry)));
    NkcPut(Log, NkcHeader());
    InterlockedPopEntrySList(&NkcList);

    /* Two threads push 64 items each at once.
     * 128, 0x00840080: all are there: depth 128, sequence 4 + 128.
     * 128, 8256: popped one by one, each item comes back once (their
     * numbers, 1 to 128, add up to 8256).
     * 0, 0x00840000: empty. */
    for (i = 0; i < NKC_STRESS; i++) {
        NkcStress[0][i].Number = i + 1;
        NkcStress[1][i].Number = NKC_STRESS + i + 1;
    }
    Thread = NkcStart(NkcListThread, NkcStress[1]);
    for (i = 0; i < NKC_STRESS; i++) {
        InterlockedPushEntrySList(&NkcList, &NkcStress[0][i].Entry);
    }
    if (Thread == NULL) {
        /* No second thread: the list must still be left empty. */
        MARK(0xE0);
    }
    NkcJoin(Thread);
    NkcPut(Log, ExQueryDepthSList(&NkcList));
    NkcPut(Log, NkcHeader());
    Count = 0;
    Sum = 0;
    while ((Entry = InterlockedPopEntrySList(&NkcList)) != NULL) {
        Count++;
        Sum += NkcNumber(Entry);
    }
    NkcPut(Log, Count);
    NkcPut(Log, Sum);
    NkcPut(Log, ExQueryDepthSList(&NkcList));
    NkcPut(Log, NkcHeader());
}

/* ---- Lookaside lists ---------------------------------------------------- */

#define NKC_LOOK_TAG 'lkNN'

static PAGED_LOOKASIDE_LIST NkcPaged;
static NPAGED_LOOKASIDE_LIST NkcNPaged;

/* What the list's own allocate and free routines were called with. */
static volatile LONG NkcAllocCalls, NkcFreeCalls;
static ULONG NkcAllocType, NkcAllocTag;
static SIZE_T NkcAllocSize;

static PVOID NkcLookAllocate(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
{
    InterlockedIncrement(&NkcAllocCalls);
    NkcAllocType = (ULONG)PoolType;
    NkcAllocSize = NumberOfBytes;
    NkcAllocTag = Tag;
    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
}

static VOID NkcLookFree(PVOID Buffer)
{
    InterlockedIncrement(&NkcFreeCalls);
    ExFreePoolWithTag(Buffer, NKC_LOOK_TAG);
}

/* The fields a driver's inline code reads, and the counters: Size, Tag,
 * Type, Depth, MaximumDepth; then TotalAllocates, AllocateMisses,
 * TotalFrees, FreeMisses; then how many blocks the list keeps. */
static VOID NkcLookFields(NKC_LOG *Log, GENERAL_LOOKASIDE *L)
{
    NkcPut(Log, L->Size);
    NkcPut(Log, L->Tag);
    NkcPut(Log, (ULONG)L->Type);
    NkcPut(Log, L->Depth);
    NkcPut(Log, L->MaximumDepth);
}

static VOID NkcLookCounts(NKC_LOG *Log, GENERAL_LOOKASIDE *L)
{
    NkcPut(Log, L->TotalAllocates);
    NkcPut(Log, L->AllocateMisses);
    NkcPut(Log, L->TotalFrees);
    NkcPut(Log, L->FreeMisses);
    NkcPut(Log, ExQueryDepthSList(&L->ListHead));
}

static VOID NkcLookaside(NKC_LOG *Log)
{
    PVOID Block, Again;
    PVOID Blocks[6];
    ULONG i;

    MARK(0x30);

    /* A paged list of 64-byte blocks, no routines of its own.
     * 64, the tag, 1 (PagedPool), 4, 256: the fields.
     * 0, 0, 0, 0, 0: the counters, and an empty list.
     * 1, 1: it has an allocate and a free routine all the same. */
    RtlFillMemory(&NkcPaged, sizeof(NkcPaged), 0xEE);
    ExInitializePagedLookasideList(&NkcPaged, NULL, NULL, 0, 64, NKC_LOOK_TAG, 0);
    NkcLookFields(Log, &NkcPaged.L);
    NkcLookCounts(Log, &NkcPaged.L);
    NkcPut(Log, NkcPaged.L.Allocate != NULL ? 1 : 0);
    NkcPut(Log, NkcPaged.L.Free != NULL ? 1 : 0);

    /* 1; 1, 1, 0, 0, 0: the first allocation misses.
     * 1, 1, 1, 0, 1: freed, the block is kept.
     * 1; 2, 1, 1, 0, 0: the next allocation is that block. */
    Block = ExAllocateFromPagedLookasideList(&NkcPaged);
    NkcPut(Log, Block != NULL ? 1 : 0);
    NkcLookCounts(Log, &NkcPaged.L);
    if (Block != NULL) {
        ExFreeToPagedLookasideList(&NkcPaged, Block);
    }
    NkcLookCounts(Log, &NkcPaged.L);
    Again = ExAllocateFromPagedLookasideList(&NkcPaged);
    NkcPut(Log, Again != NULL && Again == Block ? 1 : 0);
    NkcLookCounts(Log, &NkcPaged.L);
    if (Again != NULL) {
        ExFreeToPagedLookasideList(&NkcPaged, Again);
    }

    /* Six blocks allocated, then all six freed.
     * 8, 6, 8, 2, 4: one came from the list and five missed; the list
     * keeps Depth (4) blocks and the other two frees miss.
     * 4: Depth is still what it was. */
    for (i = 0; i < 6; i++) {
        Blocks[i] = ExAllocateFromPagedLookasideList(&NkcPaged);
    }
    for (i = 0; i < 6; i++) {
        if (Blocks[i] != NULL) {
            ExFreeToPagedLookasideList(&NkcPaged, Blocks[i]);
        }
    }
    NkcLookCounts(Log, &NkcPaged.L);
    NkcPut(Log, NkcPaged.L.Depth);

    /* 0: deleted, the list keeps nothing. */
    ExDeletePagedLookasideList(&NkcPaged);
    NkcPut(Log, ExQueryDepthSList(&NkcPaged.L.ListHead));

    /* 24, the tag, 0x11, 4, 256: a paged list of 24-byte blocks, with a
     * pool flag (POOL_RAISE_IF_ALLOCATION_FAILURE) and a Depth argument
     * of 100: the size is kept as given, not rounded up (a guess), the
     * flag joins the type, the argument is ignored. */
    RtlFillMemory(&NkcPaged, sizeof(NkcPaged), 0xEE);
    ExInitializePagedLookasideList(&NkcPaged, NULL, NULL, POOL_RAISE_IF_ALLOCATION_FAILURE, 24,
                                   NKC_LOOK_TAG, 100);
    NkcLookFields(Log, &NkcPaged.L);
    ExDeletePagedLookasideList(&NkcPaged);

    /* 48, the tag, 0 (NonPagedPool), 4, 256; 0, 0, 0, 0, 0: a non-paged
     * list with routines of its own. */
    MARK(0x31);
    RtlFillMemory(&NkcNPaged, sizeof(NkcNPaged), 0xEE);
    ExInitializeNPagedLookasideList(&NkcNPaged, NkcLookAllocate, NkcLookFree, 0, 48, NKC_LOOK_TAG,
                                    0);
    NkcLookFields(Log, &NkcNPaged.L);
    NkcLookCounts(Log, &NkcNPaged.L);

    /* 1, 1; 0, 48, the tag: the miss calls the list's allocate routine
     * with the list's type, size and tag.
     * 0; 1, 1, 1, 0, 1: freed, the block is kept and the free routine
     * not called.
     * 1: deleting the list calls the free routine for the block kept.
     * 0: and the list keeps nothing. */
    Block = ExAllocateFromNPagedLookasideList(&NkcNPaged);
    NkcPut(Log, Block != NULL ? 1 : 0);
    NkcPut(Log, (ULONG)NkcAllocCalls);
    NkcPut(Log, NkcAllocType);
    NkcPut(Log, (ULONG)NkcAllocSize);
    NkcPut(Log, NkcAllocTag);
    if (Block != NULL) {
        ExFreeToNPagedLookasideList(&NkcNPaged, Block);
    }
    NkcPut(Log, (ULONG)NkcFreeCalls);
    NkcLookCounts(Log, &NkcNPaged.L);
    ExDeleteNPagedLookasideList(&NkcNPaged);
    NkcPut(Log, (ULONG)NkcFreeCalls);
    NkcPut(Log, ExQueryDepthSList(&NkcNPaged.L.ListHead));
    InterlockedExchange(&NkcAllocCalls, 0);
    InterlockedExchange(&NkcFreeCalls, 0);

    /* 0x200: a non-paged list asked for with POOL_NX_ALLOCATION has
     * that bit in its type. */
    RtlFillMemory(&NkcNPaged, sizeof(NkcNPaged), 0xEE);
    ExInitializeNPagedLookasideList(&NkcNPaged, NULL, NULL, 0x200 /* POOL_NX_ALLOCATION */, 48,
                                    NKC_LOOK_TAG, 0);
    NkcPut(Log, (ULONG)NkcNPaged.L.Type);
    ExDeleteNPagedLookasideList(&NkcNPaged);
}

/* ---- Executive resources ------------------------------------------------ */

static ERESOURCE NkcResource;

/* Is it held exclusively by this thread; how often is it held by this
 * thread at all; is the "owned exclusively" flag set. */
static VOID NkcHeld(NKC_LOG *Log)
{
    NkcPut(Log, NkcBool(ExIsResourceAcquiredExclusiveLite(&NkcResource)));
    NkcPut(Log, ExIsResourceAcquiredSharedLite(&NkcResource));
    NkcPut(Log, NkcResource.Flag & ResourceOwnedExclusive);
}

/* How many threads wait for it exclusively, and shared. */
static VOID NkcWaiters(NKC_LOG *Log)
{
    NkcPut(Log, ExGetExclusiveWaiterCount(&NkcResource));
    NkcPut(Log, ExGetSharedWaiterCount(&NkcResource));
}

#define NKC_RES_SHARED 1    /* try both ways, acquire shared, wait for Go, release */
#define NKC_RES_EXCLUSIVE 2 /* acquire exclusive, wait for Go, release */
#define NKC_RES_NEWCOMER 3  /* without waiting: shared, then shared starving exclusive */

static VOID NkcResourceThread(PVOID Context)
{
    NKC_HELPER *Helper = (NKC_HELPER *)Context;

    KeEnterCriticalRegion();
    switch (Helper->Mode) {
    case NKC_RES_SHARED:
        Helper->Tried[0] = NkcBool(ExAcquireResourceExclusiveLite(&NkcResource, FALSE));
        if (Helper->Tried[0] != 0) {
            ExReleaseResourceLite(&NkcResource);
        }
        Helper->Tried[1] = NkcBool(ExAcquireResourceSharedLite(&NkcResource, FALSE));
        if (Helper->Tried[1] != 0) {
            ExReleaseResourceLite(&NkcResource);
        }
        InterlockedExchange(&Helper->Stage, 1);
        ExAcquireResourceSharedLite(&NkcResource, TRUE);
        InterlockedExchange(&Helper->Got, 1);
        NkcHelperWaitGo(Helper);
        ExReleaseResourceLite(&NkcResource);
        break;
    case NKC_RES_EXCLUSIVE:
        InterlockedExchange(&Helper->Stage, 1);
        ExAcquireResourceExclusiveLite(&NkcResource, TRUE);
        InterlockedExchange(&Helper->Got, 1);
        NkcHelperWaitGo(Helper);
        ExReleaseResourceLite(&NkcResource);
        break;
    default:
        Helper->Tried[0] = NkcBool(ExAcquireResourceSharedLite(&NkcResource, FALSE));
        if (Helper->Tried[0] != 0) {
            ExReleaseResourceLite(&NkcResource);
        }
        Helper->Tried[1] = NkcBool(ExAcquireSharedStarveExclusive(&NkcResource, FALSE));
        if (Helper->Tried[1] != 0) {
            ExReleaseResourceLite(&NkcResource);
        }
        break;
    }
    KeLeaveCriticalRegion();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NkcResources(NKC_LOG *Log)
{
    NKC_HELPER Helper, Newcomer;
    PVOID Thread, Other;
    ULONG i;

    MARK(0x40);

    /* 0: initialised. 0, 0, 0; 0, 0: not held, nobody waits. */
    NkcPut(Log, (ULONG)ExInitializeResourceLite(&NkcResource));
    NkcHeld(Log);
    NkcWaiters(Log);
    KeEnterCriticalRegion();

    /* 1; 1, 1, 0x80: acquired exclusively.
     * 1; 1, 2, 0x80: again, by the thread that holds it.
     * 1; 1, 3, 0x80: and shared, which for its exclusive owner is one
     * more of the same.
     * 1; 1, 4, 0x80: without waiting, the same.
     * 1; 1, 5, 0x80: by the routine that only tries, the same. */
    NkcPut(Log, NkcBool(ExAcquireResourceExclusiveLite(&NkcResource, TRUE)));
    NkcHeld(Log);
    NkcPut(Log, NkcBool(ExAcquireResourceExclusiveLite(&NkcResource, TRUE)));
    NkcHeld(Log);
    NkcPut(Log, NkcBool(ExAcquireResourceSharedLite(&NkcResource, TRUE)));
    NkcHeld(Log);
    NkcPut(Log, NkcBool(ExAcquireResourceExclusiveLite(&NkcResource, FALSE)));
    NkcHeld(Log);
    NkcPut(Log, NkcBool(ExTryToAcquireResourceExclusiveLite(&NkcResource)));
    NkcHeld(Log);

    /* 1, 4, 0x80; 1, 3, 0x80; 1, 2, 0x80; 1, 1, 0x80; 0, 0, 0: released
     * as often as acquired, it is free. */
    for (i = 0; i < 5; i++) {
        ExReleaseResourceLite(&NkcResource);
        NkcHeld(Log);
    }

    /* 1; 0, 1, 0: acquired shared. 1; 0, 2, 0: and again.
     * 0: its shared holder cannot have it exclusively without waiting.
     * 0: nor by the routine that only tries.
     * 1; 0, 3, 0: shared, starving exclusive waiters, of which there
     * are none.
     * 1; 0, 4, 0: shared, yielding to exclusive waiters, likewise. */
    NkcPut(Log, NkcBool(ExAcquireResourceSharedLite(&NkcResource, TRUE)));
    NkcHeld(Log);
    NkcPut(Log, NkcBool(ExAcquireResourceSharedLite(&NkcResource, FALSE)));
    NkcHeld(Log);
    NkcPut(Log, NkcBool(ExAcquireResourceExclusiveLite(&NkcResource, FALSE)));
    NkcPut(Log, NkcBool(ExTryToAcquireResourceExclusiveLite(&NkcResource)));
    NkcPut(Log, NkcBool(ExAcquireSharedStarveExclusive(&NkcResource, TRUE)));
    NkcHeld(Log);
    NkcPut(Log, NkcBool(ExAcquireSharedWaitForExclusive(&NkcResource, TRUE)));
    NkcHeld(Log);

    /* 0, 3, 0; 0, 2, 0; 0, 1, 0; 0, 0, 0: released four times. */
    for (i = 0; i < 4; i++) {
        ExReleaseResourceLite(&NkcResource);
        NkcHeld(Log);
    }

    /* 1, 1, 0x80; then 0, 1, 0: exclusive access is converted to
     * shared. 0, 0, 0: released. */
    ExAcquireResourceExclusiveLite(&NkcResource, TRUE);
    NkcHeld(Log);
    ExConvertExclusiveToSharedLite(&NkcResource);
    NkcHeld(Log);
    ExReleaseResourceLite(&NkcResource);
    NkcHeld(Log);

    /* 1, 1, 0x80; 0, 0, 0: released for the thread that holds it, named
     * by ExGetCurrentResourceThread. The same for shared access:
     * 0, 1, 0; 0, 0, 0. */
    ExAcquireResourceExclusiveLite(&NkcResource, TRUE);
    NkcHeld(Log);
    ExReleaseResourceForThreadLite(&NkcResource, ExGetCurrentResourceThread());
    NkcHeld(Log);
    ExAcquireResourceSharedLite(&NkcResource, TRUE);
    NkcHeld(Log);
    ExReleaseResourceForThreadLite(&NkcResource, ExGetCurrentResourceThread());
    NkcHeld(Log);

    /* Held exclusively here; another thread wants it shared.
     * 1; 0, 0: it asked; without waiting it got it neither way.
     * 0; 0, 1: it waits, and is counted as a shared waiter.
     * 1; 0, 0: released here, it is let in; nobody waits.
     * 0, 0, 0: this thread holds nothing now.
     * 1; 0, 1, 0: but can share it with the other without waiting.
     * 0: and cannot have it exclusively.
     * 0, 0, 0: released here. */
    MARK(0x41);
    ExAcquireResourceExclusiveLite(&NkcResource, TRUE);
    NkcHelperInit(&Helper, NKC_RES_SHARED);
    Thread = NkcStart(NkcResourceThread, &Helper);
    if (Thread != NULL) {
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Stage, 1));
        NkcPut(Log, Helper.Tried[0]);
        NkcPut(Log, Helper.Tried[1]);
        NkcPut(Log, (ULONG)Helper.Got);
        NkcWaiters(Log);
        ExReleaseResourceLite(&NkcResource);
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Got, 1));
        NkcWaiters(Log);
        NkcHeld(Log);
        NkcPut(Log, NkcBool(ExAcquireResourceSharedLite(&NkcResource, FALSE)));
        NkcHeld(Log);
        NkcPut(Log, NkcBool(ExAcquireResourceExclusiveLite(&NkcResource, FALSE)));
        ExReleaseResourceLite(&NkcResource);
        NkcHeld(Log);
        KeSetEvent(&Helper.Go, IO_NO_INCREMENT, FALSE);
        NkcJoin(Thread);
    } else {
        ExReleaseResourceLite(&NkcResource);
    }

    /* Held shared here; another thread wants it exclusively.
     * 1, 0; 1, 0: it asked, and waits, counted as an exclusive waiter.
     * 1; 0, 2, 0: a thread that holds it shared gets it again without
     * waiting, whoever waits.
     * 0: but not by the routine that yields to exclusive waiters.
     * 0, 1: a third thread, which holds nothing, does not get it shared
     * without waiting; starving exclusive waiters, it does.
     * 0, 1, 0: this thread lets go once and still holds it once.
     * 1; 0, 0: lets go again, and the waiter is let in; nobody waits.
     * 0: this thread cannot share it now without waiting. */
    MARK(0x42);
    ExAcquireResourceSharedLite(&NkcResource, TRUE);
    NkcHelperInit(&Helper, NKC_RES_EXCLUSIVE);
    Thread = NkcStart(NkcResourceThread, &Helper);
    if (Thread != NULL) {
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Stage, 1));
        NkcPut(Log, (ULONG)Helper.Got);
        NkcWaiters(Log);
        NkcPut(Log, NkcBool(ExAcquireResourceSharedLite(&NkcResource, FALSE)));
        NkcHeld(Log);
        i = NkcBool(ExAcquireSharedWaitForExclusive(&NkcResource, FALSE));
        NkcPut(Log, i);
        if (i != 0) {
            ExReleaseResourceLite(&NkcResource);
        }
        NkcHelperInit(&Newcomer, NKC_RES_NEWCOMER);
        Other = NkcStart(NkcResourceThread, &Newcomer);
        NkcJoin(Other);
        NkcPut(Log, Newcomer.Tried[0]);
        NkcPut(Log, Newcomer.Tried[1]);
        ExReleaseResourceLite(&NkcResource);
        NkcHeld(Log);
        ExReleaseResourceLite(&NkcResource);
        NkcPut(Log, (ULONG)NkcSettle(&Helper.Got, 1));
        NkcWaiters(Log);
        i = NkcBool(ExAcquireResourceSharedLite(&NkcResource, FALSE));
        NkcPut(Log, i);
        if (i != 0) {
            ExReleaseResourceLite(&NkcResource);
        }
        KeSetEvent(&Helper.Go, IO_NO_INCREMENT, FALSE);
        NkcJoin(Thread);
    } else {
        ExReleaseResourceLite(&NkcResource);
    }

    /* 0; 0, 0, 0: reinitialised, it is as new. 0: deleted. */
    KeLeaveCriticalRegion();
    NkcPut(Log, (ULONG)ExReinitializeResourceLite(&NkcResource));
    NkcHeld(Log);
    NkcPut(Log, (ULONG)ExDeleteResourceLite(&NkcResource));
}

/* ---- Executive timers --------------------------------------------------- */

static volatile LONG NkcTimerCalls;
static volatile LONG NkcTimerIrql;    /* the IRQL of the last call */
static volatile LONG NkcTimerContext; /* 1: the last call was given its timer and context */
static PEX_TIMER NkcTimerExpected;

static VOID NkcTimerCallback(PEX_TIMER Timer, PVOID Context)
{
    InterlockedExchange(&NkcTimerIrql, (LONG)KeGetCurrentIrql());
    InterlockedExchange(&NkcTimerContext,
                        Timer == NkcTimerExpected && Context == (PVOID)&NkcTimerCalls ? 1 : 0);
    InterlockedIncrement(&NkcTimerCalls);
}

#define NKC_MS(n) (-(LONGLONG)(n) * 10000)

static VOID NkcTimers(NKC_LOG *Log)
{
    PEX_TIMER Timer, Waited;
    LARGE_INTEGER Timeout;
    LONG Before;

    MARK(0x50);
    InterlockedExchange(&NkcTimerCalls, 0);

    /* 1: a timer with a callback is allocated. */
    Timer = ExAllocateTimer(NkcTimerCallback, (PVOID)&NkcTimerCalls, 0);
    NkcTimerExpected = Timer;
    NkcPut(Log, Timer != NULL ? 1 : 0);
    if (Timer == NULL) {
        return;
    }

    /* 0: cancelling a timer never set says it was not set.
     * 0: setting it says it was not set before.
     * 1, 2, 1: it fires once, at DISPATCH_LEVEL, with its timer and
     * context.
     * 0: cancelled after it fired, it was not set. */
    NkcPut(Log, NkcBool(ExCancelTimer(Timer, NULL)));
    NkcPut(Log, NkcBool(ExSetTimer(Timer, NKC_MS(20), 0, NULL)));
    NkcPut(Log, (ULONG)NkcSettle(&NkcTimerCalls, 1));
    NkcPut(Log, (ULONG)NkcTimerIrql);
    NkcPut(Log, (ULONG)NkcTimerContext);
    NkcPut(Log, NkcBool(ExCancelTimer(Timer, NULL)));

    /* 0, 1: set for ten seconds from now, then set again: the second
     * call says it was set.
     * 1, 0: cancelled, it was set; cancelled again, it was not.
     * 1: and it has not fired a second time. */
    NkcPut(Log, NkcBool(ExSetTimer(Timer, NKC_MS(10000), 0, NULL)));
    NkcPut(Log, NkcBool(ExSetTimer(Timer, NKC_MS(10000), 0, NULL)));
    NkcPut(Log, NkcBool(ExCancelTimer(Timer, NULL)));
    NkcPut(Log, NkcBool(ExCancelTimer(Timer, NULL)));
    NkcSleep(30);
    NkcPut(Log, (ULONG)NkcTimerCalls);

    /* 0: set to fire after 10 ms and every 10 ms from then.
     * 1: it fires at least three times more.
     * 1: cancelled, it was set.
     * 1: and it fires no more. */
    NkcPut(Log, NkcBool(ExSetTimer(Timer, NKC_MS(10), -NKC_MS(10), NULL)));
    NkcPut(Log, NkcSettle(&NkcTimerCalls, 4) >= 4 ? 1 : 0);
    NkcPut(Log, NkcBool(ExCancelTimer(Timer, NULL)));
    NkcSleep(30);
    Before = NkcTimerCalls;
    NkcSleep(60);
    NkcPut(Log, NkcTimerCalls == Before ? 1 : 0);

    /* 0: deleted while not set (cancel and wait asked for): it was not
     * set. */
    NkcPut(Log, NkcBool(ExDeleteTimer(Timer, TRUE, TRUE, NULL)));

    /* 1, 0, 1: a second timer, set for ten seconds from now, deleted
     * with cancel and wait: it was set.
     * 1: its callback was never called. */
    Before = NkcTimerCalls;
    Timer = ExAllocateTimer(NkcTimerCallback, (PVOID)&NkcTimerCalls, 0);
    NkcTimerExpected = Timer;
    NkcPut(Log, Timer != NULL ? 1 : 0);
    if (Timer != NULL) {
        NkcPut(Log, NkcBool(ExSetTimer(Timer, NKC_MS(10000), 0, NULL)));
        NkcPut(Log, NkcBool(ExDeleteTimer(Timer, TRUE, TRUE, NULL)));
    }
    NkcSleep(30);
    NkcPut(Log, NkcTimerCalls == Before ? 1 : 0);

    /* A timer without a callback can be waited for.
     * 1, 0: allocated, set for 20 ms.
     * 0: the wait ends with STATUS_SUCCESS.
     * 0x102: waited for again without sleeping, it is no longer
     * signalled: satisfying a wait resets it.
     * 0: deleted. */
    MARK(0x51);
    Timeout.QuadPart = NKC_MS(5000);
    Waited = ExAllocateTimer(NULL, NULL, 0);
    NkcPut(Log, Waited != NULL ? 1 : 0);
    if (Waited != NULL) {
        NkcPut(Log, NkcBool(ExSetTimer(Waited, NKC_MS(20), 0, NULL)));
        NkcPut(Log, (ULONG)KeWaitForSingleObject(Waited, Executive, KernelMode, FALSE, &Timeout));
        Timeout.QuadPart = 0;
        NkcPut(Log, (ULONG)KeWaitForSingleObject(Waited, Executive, KernelMode, FALSE, &Timeout));
        NkcPut(Log, NkcBool(ExDeleteTimer(Waited, TRUE, TRUE, NULL)));
    }

    /* The same with EX_TIMER_NOTIFICATION.
     * 1, 0, 0: allocated, set, the wait ends.
     * 0: waited for again, it is still signalled.
     * 0, 0x102: set again for ten seconds from now, it is not.
     * 1: deleted with cancel: it was set. */
    Timeout.QuadPart = NKC_MS(5000);
    Waited = ExAllocateTimer(NULL, NULL, EX_TIMER_NOTIFICATION);
    NkcPut(Log, Waited != NULL ? 1 : 0);
    if (Waited != NULL) {
        NkcPut(Log, NkcBool(ExSetTimer(Waited, NKC_MS(20), 0, NULL)));
        NkcPut(Log, (ULONG)KeWaitForSingleObject(Waited, Executive, KernelMode, FALSE, &Timeout));
        Timeout.QuadPart = 0;
        NkcPut(Log, (ULONG)KeWaitForSingleObject(Waited, Executive, KernelMode, FALSE, &Timeout));
        NkcPut(Log, NkcBool(ExSetTimer(Waited, NKC_MS(10000), 0, NULL)));
        NkcPut(Log, (ULONG)KeWaitForSingleObject(Waited, Executive, KernelMode, FALSE, &Timeout));
        NkcPut(Log, NkcBool(ExDeleteTimer(Waited, TRUE, TRUE, NULL)));
    }

    /* 1, 0: a high-resolution timer is allocated, and deleted unset. */
    Waited = ExAllocateTimer(NkcTimerCallback, NULL, EX_TIMER_HIGH_RESOLUTION);
    NkcPut(Log, Waited != NULL ? 1 : 0);
    if (Waited != NULL) {
        NkcPut(Log, NkcBool(ExDeleteTimer(Waited, TRUE, TRUE, NULL)));
    }
}

/* ---- ExUuidCreate ------------------------------------------------------- */

/* The 60-bit time of a version-1 UUID. */
static ULONGLONG NkcUuidTime(const UUID *Uuid)
{
    return ((ULONGLONG)(Uuid->Data3 & 0x0FFF) << 48) | ((ULONGLONG)Uuid->Data2 << 32) |
           Uuid->Data1;
}

static VOID NkcUuids(NKC_LOG *Log)
{
    UUID First, Second;
    NTSTATUS Status;

    MARK(0x60);
    RtlZeroMemory(&First, sizeof(First));
    RtlZeroMemory(&Second, sizeof(Second));

    /* The status: 0 where the machine has a network adapter's address
     * to build on, 0x40020056 (RPC_NT_UUID_LOCAL_ONLY) where it has
     * not. This one fact depends on the machine. The same both times. */
    Status = ExUuidCreate(&First);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, (ULONG)ExUuidCreate(&Second));

    /* 1, 2: version 1; the variant bits are binary 10. */
    NkcPut(Log, (ULONG)(First.Data3 >> 12));
    NkcPut(Log, (ULONG)(First.Data4[0] >> 6));
    NkcPut(Log, (ULONG)(Second.Data3 >> 12));
    NkcPut(Log, (ULONG)(Second.Data4[0] >> 6));

    /* 0: the two differ. 1: the second's time is later than the first's.
     * 1, 1: clock sequence and node are the same in both. */
    NkcPut(Log, RtlCompareMemory(&First, &Second, sizeof(UUID)) == sizeof(UUID) ? 1 : 0);
    NkcPut(Log, NkcUuidTime(&Second) > NkcUuidTime(&First) ? 1 : 0);
    NkcPut(Log, First.Data4[0] == Second.Data4[0] && First.Data4[1] == Second.Data4[1] ? 1 : 0);
    NkcPut(Log, RtlCompareMemory(&First.Data4[2], &Second.Data4[2], 6) == 6 ? 1 : 0);

    /* 1: a UUID that is only locally unique has the top bit of its
     * node's first byte set; one built on an adapter's address is
     * logged as 1 too, whatever that bit. (A guess for the local case.) */
    NkcPut(Log, Status != RPC_NT_UUID_LOCAL_ONLY || (First.Data4[2] & 0x80) != 0 ? 1 : 0);
}

/* ---- Pool variants ------------------------------------------------------ */

#define NKC_POOL_TAG 'lpNN'

/* More than any pool holds: 64 TB. */
#define NKC_TOO_MUCH ((SIZE_T)1 << 46)

/* Is there a block, and is it aligned to `Mask` + 1; then free it. */
static VOID NkcBlock(NKC_LOG *Log, PVOID Block, ULONG_PTR Mask, SIZE_T Touch)
{
    NkcPut(Log, Block != NULL ? 1 : 0);
    if (Block != NULL) {
        NkcPut(Log, ((ULONG_PTR)Block & Mask) == 0 ? 1 : 0);
        if (Touch != 0) {
            RtlFillMemory(Block, Touch, 0x5A);
        }
        ExFreePool(Block);
    }
}

/* Allocate with a quota charge, and no flag that asks for NULL on
 * failure: log the exception's code, or 0 and whether there is a block. */
static DECLSPEC_NOINLINE VOID NkcQuotaRaise(NKC_LOG *Log, SIZE_T Bytes)
{
    PVOID Block = NULL;

    __try {
        if (NkcZero == 0) {
            Block = ExAllocatePoolWithQuotaTag(PagedPool, Bytes, NKC_POOL_TAG);
        }
        NkcPut(Log, 0);
        NkcPut(Log, Block != NULL ? 1 : 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        NkcPut(Log, (ULONG)GetExceptionCode());
    }
    if (Block != NULL) {
        ExFreePool(Block);
    }
}

static VOID NkcPools(NKC_LOG *Log)
{
    MARK(0x70);

    /* 1, 1: 64 bytes of non-paged pool at normal priority: a block,
     * aligned to 16 bytes.
     * 1, 1: a page and more of paged pool at high priority: aligned to
     * a page.
     * 1, 1: no bytes at low priority: a block all the same.
     * 0: more than there is: no block, and no exception. */
    NkcBlock(Log, ExAllocatePoolWithTagPriority(NonPagedPoolNx, 64, NKC_POOL_TAG,
                                                NormalPoolPriority),
             MEMORY_ALLOCATION_ALIGNMENT - 1, 64);
    NkcBlock(Log, ExAllocatePoolWithTagPriority(PagedPool, PAGE_SIZE + 64, NKC_POOL_TAG,
                                                HighPoolPriority),
             PAGE_SIZE - 1, PAGE_SIZE + 64);
    NkcBlock(Log, ExAllocatePoolWithTagPriority(NonPagedPoolNx, 0, NKC_POOL_TAG, LowPoolPriority),
             MEMORY_ALLOCATION_ALIGNMENT - 1, 0);
    NkcBlock(Log, ExAllocatePoolWithTagPriority(NonPagedPoolNx, NKC_TOO_MUCH, NKC_POOL_TAG,
                                                NormalPoolPriority),
             0, 0);

    /* 1, 1: 64 bytes charged to the current process's quota: a block,
     * aligned to 16 bytes. From non-paged pool the same: 1, 1.
     * 0: more than there is, with the flag that asks for NULL: no block.
     * 0, 1: without the flag, 64 bytes: no exception, a block.
     * 0xC000009A: without the flag, more than there is: the routine
     * raises STATUS_INSUFFICIENT_RESOURCES. */
    NkcBlock(Log, ExAllocatePoolWithQuotaTag(PagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE, 64,
                                             NKC_POOL_TAG),
             MEMORY_ALLOCATION_ALIGNMENT - 1, 64);
    NkcBlock(Log, ExAllocatePoolWithQuotaTag(NonPagedPoolNx | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE, 64,
                                             NKC_POOL_TAG),
             MEMORY_ALLOCATION_ALIGNMENT - 1, 64);
    NkcBlock(Log, ExAllocatePoolWithQuotaTag(PagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
                                             NKC_TOO_MUCH, NKC_POOL_TAG),
             0, 0);
    NkcQuotaRaise(Log, 64);
    NkcQuotaRaise(Log, NKC_TOO_MUCH);
}

static VOID NkcRun(NKC_LOG *Log)
{
    NkcPushLocks(Log);
    NkcLists(Log);
    NkcLookaside(Log);
    NkcResources(Log);
    NkcTimers(Log);
    NkcUuids(Log);
    NkcPools(Log);

    /* 0, 0: back at PASSIVE_LEVEL, with kernel APCs enabled again. */
    NkcPut(Log, KeGetCurrentIrql());
    NkcPut(Log, NkcBool(KeAreApcsDisabled()));
}
