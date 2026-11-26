/*
 * Conformance: the System process, its threads, and the host silo.
 *
 * Who a system thread is (process, ids, session), attaching to the
 * process it is already in, waiting on a handle, alerting a thread,
 * setting a thread's priority through its handle, quota charged to the
 * System process; and, in a second list, what the silo routines say on
 * a system with no container: there is one silo, the host, and it is
 * spelled NULL.
 *
 * Both lists are made on a system thread. The thread that sends the
 * request is a thread of some other process on Windows, and its process,
 * ids and session are that process's.
 *
 * List 0 (0x222000). Of nkc-undoc.h it uses PsGetCurrentProcess (the
 * export, which the kit covers with a macro), PsGetProcessSessionId,
 * PsGetThreadSessionId, PsChargeProcessPagedPoolQuota and
 * PsReturnProcessPagedPoolQuota.
 *
 * List 1 (0x222004): silos. Every routine is documented, in ntddk.h.
 * A context is made permanent only in the slot of a silo monitor,
 * because that is the one place it can be taken out of again: the host
 * silo never ends, PsFreeSiloContextSlot leaves what the host holds
 * where it is, and only PsUnregisterSiloMonitor empties the host's slot.
 *
 * Processor counts are logged as relations (more than none), ids as
 * relations except the System process's own, which is 4.
 */

#include <ntifs.h>

#define NKC_DEVICE L"\\Device\\NkcPs"
#define NKC_THREADS
#define NKC_LISTS 2
#include "nkc.h"
#include "nkc-undoc.h"

/* A wait that ends at once if it cannot be satisfied. */
static LARGE_INTEGER NkcNoTime;

/*
 * A thread beside the one that makes the list.
 */

typedef struct _NKC_PEER {
    KEVENT Ready;
    KEVENT Go;
    KEVENT Never;      /* never set */
    HANDLE ProcessId;
    HANDLE ThreadId;
    PVOID Process;
    LONG Mode;         /* what to do once ready: NKC_PEER_... */
    NTSTATUS First;    /* statuses of its waits */
    NTSTATUS Second;
} NKC_PEER;

#define NKC_PEER_IDLE 0    /* wait to be let go */
#define NKC_PEER_ALERTED 1 /* wait, alertable, for what never comes; twice */
#define NKC_PEER_LATER 2   /* wait to be let go, then once, alertable */

static KSTART_ROUTINE NkcPeer;

static VOID NkcPeer(PVOID Context)
{
    NKC_PEER *Peer = (NKC_PEER *)Context;

    Peer->ProcessId = PsGetCurrentProcessId();
    Peer->ThreadId = PsGetCurrentThreadId();
    Peer->Process = PsGetCurrentProcess();
    KeSetEvent(&Peer->Ready, IO_NO_INCREMENT, FALSE);
    if (Peer->Mode == NKC_PEER_ALERTED) {
        Peer->First = KeWaitForSingleObject(&Peer->Never, Executive, KernelMode, TRUE, NULL);
        Peer->Second = KeWaitForSingleObject(&Peer->Never, Executive, KernelMode, TRUE,
                                             &NkcNoTime);
    } else {
        KeWaitForSingleObject(&Peer->Go, Executive, KernelMode, FALSE, NULL);
        if (Peer->Mode == NKC_PEER_LATER) {
            Peer->First = KeWaitForSingleObject(&Peer->Never, Executive, KernelMode, TRUE,
                                                &NkcNoTime);
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Start a peer and wait until it has said who it is. The handle is a
 * kernel handle with every access; the object comes back referenced. */
static NTSTATUS NkcStartPeer(NKC_PEER *Peer, LONG Mode, PHANDLE Handle, PVOID *Thread)
{
    OBJECT_ATTRIBUTES Attributes;
    NTSTATUS Status;

    RtlZeroMemory(Peer, sizeof(*Peer));
    KeInitializeEvent(&Peer->Ready, NotificationEvent, FALSE);
    KeInitializeEvent(&Peer->Go, NotificationEvent, FALSE);
    KeInitializeEvent(&Peer->Never, NotificationEvent, FALSE);
    Peer->Mode = Mode;
    Peer->First = Peer->Second = (NTSTATUS)0xAAAAAAAA;
    *Handle = NULL;
    *Thread = NULL;
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = PsCreateSystemThread(Handle, THREAD_ALL_ACCESS, &Attributes, NULL, NULL, NkcPeer,
                                  Peer);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    Status = ObReferenceObjectByHandle(*Handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
                                       Thread, NULL);
    if (!NT_SUCCESS(Status)) {
        /* Nothing to wait on for its end but its own word. */
        KeSetEvent(&Peer->Go, IO_NO_INCREMENT, FALSE);
        ZwAlertThread(*Handle);
        ZwWaitForSingleObject(*Handle, FALSE, NULL);
        ZwClose(*Handle);
        *Handle = NULL;
        *Thread = NULL;
        return Status;
    }
    KeWaitForSingleObject(&Peer->Ready, Executive, KernelMode, FALSE, NULL);
    return STATUS_SUCCESS;
}

/* Let a peer go, wait for its end, and let go of it. */
static VOID NkcEndPeer(NKC_PEER *Peer, HANDLE Handle, PVOID Thread)
{
    KeSetEvent(&Peer->Go, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(Thread);
    ZwClose(Handle);
}

static VOID NkcIdentity(NKC_LOG *Log, NKC_PEER *Peer, PVOID PeerThread)
{
    PEPROCESS System = PsInitialSystemProcess;
    HANDLE ProcessId = PsGetCurrentProcessId();
    HANDLE ThreadId = PsGetCurrentThreadId();
    KAPC_STATE Apc;
    ULONG Major, Minor, Build;
    RTL_OSVERSIONINFOW Version;
    BOOLEAN Checked;

    /* 1, 1: a system thread's process is the System process, by either
     * name for "the current process". */
    NkcPut(Log, PsGetCurrentProcess() == System ? 1 : 0);
    NkcPut(Log, IoGetCurrentProcess() == System ? 1 : 0);

    /* 4: the System process's id. 1: PsGetProcessId agrees. */
    NkcPut(Log, (ULONG)(ULONG_PTR)ProcessId);
    NkcPut(Log, PsGetProcessId(System) == ProcessId ? 1 : 0);

    /* 1, 0: a thread has an id, a multiple of four like every id.
     * 1, 1: so does the System process; another system thread has the
     * same process id, the same process, and an id of its own. */
    NkcPut(Log, ThreadId != NULL ? 1 : 0);
    NkcPut(Log, (ULONG)((ULONG_PTR)ThreadId & 3));
    NkcPut(Log, Peer->ProcessId == ProcessId && Peer->Process == (PVOID)System ? 1 : 0);
    NkcPut(Log, Peer->ThreadId != ThreadId && Peer->ThreadId != NULL &&
                        ((ULONG_PTR)Peer->ThreadId & 3) == 0
                    ? 1
                    : 0);

    /* 1, 1: the process id of a thread, this one and the other. */
    NkcPut(Log, PsGetThreadProcessId(PsGetCurrentThread()) == ProcessId ? 1 : 0);
    NkcPut(Log, PsGetThreadProcessId((PETHREAD)PeerThread) == ProcessId ? 1 : 0);

    /* 0, 0, 0: the System process is in no session, which reads as
     * session 0; so are its threads. */
    NkcPut(Log, PsGetProcessSessionId(System));
    NkcPut(Log, PsGetThreadSessionId(PsGetCurrentThread()));
    NkcPut(Log, PsGetThreadSessionId((PETHREAD)PeerThread));

    /* 0, 10, 0, 1: not a checked build; version 10.0; the build number
     * RtlGetVersion gives. */
    Major = Minor = Build = 0xAAAAAAAA;
    RtlZeroMemory(&Version, sizeof(Version));
    Version.dwOSVersionInfoSize = sizeof(Version);
    RtlGetVersion(&Version);
#pragma warning(suppress : 4996) /* PsGetVersion is obsolete, and wpprecorder.sys calls it */
    Checked = PsGetVersion(&Major, &Minor, &Build, NULL);
    NkcPut(Log, Checked);
    NkcPut(Log, Major);
    NkcPut(Log, Minor);
    NkcPut(Log, Build == Version.dwBuildNumber ? 1 : 0);

    /* 1, 1: there is at least one processor, in all groups and in the
     * first; 1: and no more in the first than in all. */
    NkcPut(Log, KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) > 0 ? 1 : 0);
    NkcPut(Log, KeQueryActiveProcessorCountEx(0) > 0 ? 1 : 0);
    NkcPut(Log, KeQueryActiveProcessorCountEx(0) <= KeQueryActiveProcessorCountEx(
                                                        ALL_PROCESSOR_GROUPS)
                    ? 1
                    : 0);

    /* Attaching to the process the thread is in already. 1: the saved
     * state says so with a 1 where the process would be. 1, 0: still
     * the System process, still at PASSIVE_LEVEL. 1: and after. */
    RtlZeroMemory(&Apc, sizeof(Apc));
    KeStackAttachProcess((PKPROCESS)System, &Apc);
    NkcPut(Log, (ULONG_PTR)Apc.Process == 1 ? 1 : 0);
    NkcPut(Log, PsGetCurrentProcess() == System ? 1 : 0);
    NkcPut(Log, KeGetCurrentIrql());
    KeUnstackDetachProcess(&Apc);
    NkcPut(Log, PsGetCurrentProcess() == System ? 1 : 0);

    /* 0: the System process is charged no quota: any amount is fine,
     * and giving it back is as well. */
    NkcPut(Log, (ULONG)PsChargeProcessPagedPoolQuota(System, 4096));
    PsReturnProcessPagedPoolQuota(System, 4096);
}

static VOID NkcWaits(NKC_LOG *Log, HANDLE PeerHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Event = NULL;
    PVOID Object = NULL;
    LARGE_INTEGER Short;
    NTSTATUS Status;

    Short.QuadPart = -20 * 10000;
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    /* 0: an event, signalled, with no name. 0: a wait for it returns. */
    Status = ZwCreateEvent(&Event, EVENT_ALL_ACCESS, &Attributes, NotificationEvent, TRUE);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, (ULONG)ZwWaitForSingleObject(Event, FALSE, &NkcNoTime));
        Status = ObReferenceObjectByHandle(Event, EVENT_ALL_ACCESS, *ExEventObjectType,
                                           KernelMode, &Object, NULL);
        /* 0: the handle is to an event object. */
        NkcPut(Log, (ULONG)Status);
        if (NT_SUCCESS(Status)) {
            /* 0x102 (STATUS_TIMEOUT) twice: reset, a wait with no time
             * and one with 20 ms both time out. 0: set, a wait without
             * limit returns. */
            KeResetEvent((PRKEVENT)Object);
            NkcPut(Log, (ULONG)ZwWaitForSingleObject(Event, FALSE, &NkcNoTime));
            NkcPut(Log, (ULONG)ZwWaitForSingleObject(Event, FALSE, &Short));
            KeSetEvent((PRKEVENT)Object, IO_NO_INCREMENT, FALSE);
            NkcPut(Log, (ULONG)ZwWaitForSingleObject(Event, FALSE, NULL));
            ObDereferenceObject(Object);
        }
        /* 0xC0000024: an event is not a thread to be alerted. */
        NkcPut(Log, (ULONG)ZwAlertThread(Event));
        NkcPut(Log, (ULONG)ZwClose(Event));
    }

    /* 0; 0, 0x102: a synchronisation event, signalled, satisfies one
     * wait and is then not signalled. */
    Status = ZwCreateEvent(&Event, EVENT_ALL_ACCESS, &Attributes, SynchronizationEvent, TRUE);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, (ULONG)ZwWaitForSingleObject(Event, FALSE, &NkcNoTime));
        NkcPut(Log, (ULONG)ZwWaitForSingleObject(Event, FALSE, &NkcNoTime));
        ZwClose(Event);
    }

    /* 0x102: a thread that has not ended is not signalled.
     * 0xC0000008: null is not a handle to wait on. */
    NkcPut(Log, (ULONG)ZwWaitForSingleObject(PeerHandle, FALSE, &NkcNoTime));
    NkcPut(Log, (ULONG)ZwWaitForSingleObject(NULL, FALSE, &NkcNoTime));
}

static VOID NkcAlerts(NKC_LOG *Log)
{
    NKC_PEER *Peer;
    HANDLE Handle;
    PVOID Thread;
    NTSTATUS Status;

    Peer = (NKC_PEER *)ExAllocatePoolWithTag(NonPagedPool, sizeof(*Peer), NKC_TAG);
    if (Peer == NULL) {
        return;
    }

    /* 0: a thread in an alertable wait is alerted.
     * 0x101 (STATUS_ALERTED): that is what its wait returns.
     * 0x102: the alert is used up; its next alertable wait, for no
     * time, times out. */
    Status = NkcStartPeer(Peer, NKC_PEER_ALERTED, &Handle, &Thread);
    if (NT_SUCCESS(Status)) {
        NkcSleep(20);
        NkcPut(Log, (ULONG)ZwAlertThread(Handle));
        NkcEndPeer(Peer, Handle, Thread);
        NkcPut(Log, (ULONG)Peer->First);
        NkcPut(Log, (ULONG)Peer->Second);
    }

    /* 0: a thread in a wait that is not alertable is alerted. 0x102:
     * the wait goes on, the thread has not ended 20 ms later. 0x101:
     * the alert is kept for its next alertable wait, which it ends even
     * when that wait is for no time at all (a guess: the alert is
     * looked at before the time is). */
    Status = NkcStartPeer(Peer, NKC_PEER_LATER, &Handle, &Thread);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, (ULONG)ZwAlertThread(Handle));
        NkcSleep(20);
        NkcPut(Log, (ULONG)ZwWaitForSingleObject(Handle, FALSE, &NkcNoTime));
        NkcEndPeer(Peer, Handle, Thread);
        NkcPut(Log, (ULONG)Peer->First);
    }

    /* 0xC0000008: null is not a handle to a thread. */
    NkcPut(Log, (ULONG)ZwAlertThread(NULL));
    ExFreePoolWithTag(Peer, NKC_TAG);
}

static VOID NkcPriorities(NKC_LOG *Log, HANDLE Handle, PVOID Thread)
{
    KPRIORITY Priority;
    LONG Base;

    /* 8: a system thread that has only waited is at the System
     * process's base priority. */
    NkcPut(Log, (ULONG)KeSetPriorityThread((PKTHREAD)Thread, 9));

    /* 0, 10: its priority is set through its handle, and is then what
     * KeSetPriorityThread finds. */
    Priority = 10;
    NkcPut(Log, (ULONG)ZwSetInformationThread(Handle, ThreadPriority, &Priority,
                                              sizeof(Priority)));
    NkcPut(Log, (ULONG)KeSetPriorityThread((PKTHREAD)Thread, 9));

    /* 0xC000000D twice: 0 and 32 are not priorities a thread is set
     * to. 0xC0000004: nor is a priority two bytes long. */
    Priority = 0;
    NkcPut(Log, (ULONG)ZwSetInformationThread(Handle, ThreadPriority, &Priority,
                                              sizeof(Priority)));
    Priority = 32;
    NkcPut(Log, (ULONG)ZwSetInformationThread(Handle, ThreadPriority, &Priority,
                                              sizeof(Priority)));
    Priority = 10;
    NkcPut(Log, (ULONG)ZwSetInformationThread(Handle, ThreadPriority, &Priority, 2));

    /* 0, 9: a base priority one above the process's. Guesses: that the
     * thread's priority follows at once, and 0xC000000D for three
     * above, which is not one of the steps there are. */
    Base = 1;
    NkcPut(Log, (ULONG)ZwSetInformationThread(Handle, ThreadBasePriority, &Base, sizeof(Base)));
    NkcPut(Log, (ULONG)KeSetPriorityThread((PKTHREAD)Thread, 8));
    Base = 3;
    NkcPut(Log, (ULONG)ZwSetInformationThread(Handle, ThreadBasePriority, &Base, sizeof(Base)));
    Base = 0;
    ZwSetInformationThread(Handle, ThreadBasePriority, &Base, sizeof(Base));

    /* 0xC0000003 (STATUS_INVALID_INFO_CLASS): a class there is not.
     * 0xC0000008: null is not a handle to a thread. */
    Priority = 10;
    NkcPut(Log, (ULONG)ZwSetInformationThread(Handle, (THREADINFOCLASS)0x7FFF, &Priority,
                                              sizeof(Priority)));
    NkcPut(Log, (ULONG)ZwSetInformationThread(NULL, ThreadPriority, &Priority,
                                              sizeof(Priority)));
}

static VOID NkcSystem(NKC_LOG *Log)
{
    NKC_PEER *Peer;
    HANDLE Handle;
    PVOID Thread;
    NTSTATUS Status;

    Peer = (NKC_PEER *)ExAllocatePoolWithTag(NonPagedPool, sizeof(*Peer), NKC_TAG);
    if (Peer == NULL) {
        return;
    }
    /* 0: another system thread, to compare with and to act on. */
    Status = NkcStartPeer(Peer, NKC_PEER_IDLE, &Handle, &Thread);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcIdentity(Log, Peer, Thread);
        NkcWaits(Log, Handle);
        NkcPriorities(Log, Handle, Thread);
        NkcEndPeer(Peer, Handle, Thread);
        NkcAlerts(Log);
    }
    ExFreePoolWithTag(Peer, NKC_TAG);

    /* 0: at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}

static VOID NkcRun(NKC_LOG *Log)
{
    /* 1: in the sender's thread too, both names give one process. */
    NkcPut(Log, PsGetCurrentProcess() == IoGetCurrentProcess() ? 1 : 0);
    NkcOnSystemThread(NkcSystem, Log);
}

/*
 * List 1: silos.
 */

/* What the callbacks saw. */
static volatile LONG NkcCreateCalls;
static volatile LONG NkcTerminateCalls;
static volatile LONG NkcCleanupCalls;
static volatile LONG NkcCallbackFacts; /* NKC_SAW_... of the latest callback */
static PVOID NkcCleaned;               /* the context the latest clean-up was for */
static PVOID NkcMonitorThread;         /* the thread that starts the monitor */

#define NKC_SAW_HOST 1    /* the silo is the host silo, NULL */
#define NKC_SAW_PASSIVE 2 /* called at PASSIVE_LEVEL */
#define NKC_SAW_CALLER 4  /* called on the thread that started or ended the monitor */
#define NKC_SAW_SYSTEM 8  /* called in the System process */
#define NKC_CONTEXT_MARK 0x4E4B5053

static LONG NkcSaw(PESILO Silo)
{
    return (Silo == NULL ? NKC_SAW_HOST : 0) |
           (KeGetCurrentIrql() == PASSIVE_LEVEL ? NKC_SAW_PASSIVE : 0) |
           (PsGetCurrentThread() == NkcMonitorThread ? NKC_SAW_CALLER : 0) |
           (IoGetCurrentProcess() == PsInitialSystemProcess ? NKC_SAW_SYSTEM : 0);
}

static NTSTATUS NTAPI NkcSiloCreate(PESILO Silo)
{
    NkcCallbackFacts = NkcSaw(Silo);
    InterlockedIncrement(&NkcCreateCalls);
    return STATUS_SUCCESS;
}

static VOID NTAPI NkcSiloTerminate(PESILO Silo)
{
    NkcCallbackFacts = NkcSaw(Silo);
    InterlockedIncrement(&NkcTerminateCalls);
}

static VOID NTAPI NkcSiloCleanup(PVOID SiloContext)
{
    NkcCleaned = *(ULONG *)SiloContext == NKC_CONTEXT_MARK ? SiloContext : NULL;
    InterlockedIncrement(&NkcCleanupCalls);
}

/* 0 for the host silo, 3 for "this thread is attached to no silo and
 * uses its process's", which is how a thread starts out, 0xFF for
 * anything else. */
static ULONG NkcSiloCode(PESILO Silo)
{
    if (Silo == NULL) {
        return 0;
    }
    return (LONG_PTR)Silo == -3 ? 3 : 0xFF;
}

/* A context for the host silo with this driver's mark in it. */
static NTSTATUS NkcContext(POOL_TYPE Pool, PVOID *Context)
{
    NTSTATUS Status;

    *Context = NULL;
    Status = PsCreateSiloContext(NULL, sizeof(ULONGLONG), Pool, NkcSiloCleanup, Context);
    if (NT_SUCCESS(Status) && *Context != NULL) {
        *(ULONG *)*Context = NKC_CONTEXT_MARK;
    }
    return Status;
}

static VOID NkcMonitors(NKC_LOG *Log, ULONG OwnSlot)
{
    SILO_MONITOR_REGISTRATION Registration, Bad;
    UNICODE_STRING Name;
    PSILO_MONITOR Monitor = NULL;
    PVOID Context = NULL, Second = NULL, Found;
    ULONG Slot;
    LONG Cleanups;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, L"NkcPs");
    RtlZeroMemory(&Registration, sizeof(Registration));
    Registration.Version = SILO_MONITOR_REGISTRATION_VERSION;
    Registration.MonitorHost = TRUE;
    Registration.MonitorExistingSilos = TRUE;
    Registration.ComponentName = &Name;
    Registration.CreateCallback = NkcSiloCreate;
    Registration.TerminateCallback = NkcSiloTerminate;

    /* 0xC000000D twice: a registration of version 0, and one with no
     * callback at all. */
    Bad = Registration;
    Bad.Version = 0;
    Status = PsRegisterSiloMonitor(&Bad, &Monitor);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        PsUnregisterSiloMonitor(Monitor);
    }
    Bad = Registration;
    Bad.CreateCallback = NULL;
    Bad.TerminateCallback = NULL;
    Monitor = NULL;
    Status = PsRegisterSiloMonitor(&Bad, &Monitor);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        PsUnregisterSiloMonitor(Monitor);
    }

    /* 0, 0: registered; registering calls nothing. */
    Monitor = NULL;
    Status = PsRegisterSiloMonitor(&Registration, &Monitor);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, (ULONG)NkcCreateCalls);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    /* 1: the monitor has a slot of its own, another than the one this
     * list allocated. */
    Slot = PsGetSiloMonitorContextSlot(Monitor);
    NkcPut(Log, Slot != OwnSlot ? 1 : 0);

    /* 0, 1, 0xF: started, a monitor that watches the host has its
     * create callback called once, then and there: for the host silo,
     * at PASSIVE_LEVEL, on the starting thread, in the System process.
     * 0: the terminate callback is not called. */
    NkcCallbackFacts = 0;
    Status = PsStartSiloMonitor(Monitor);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, (ULONG)NkcCreateCalls);
    NkcPut(Log, (ULONG)NkcCallbackFacts);
    NkcPut(Log, (ULONG)NkcTerminateCalls);

    /* 0, 0: a context for the host silo, made permanent in the
     * monitor's slot. */
    Cleanups = NkcCleanupCalls;
    Status = NkcContext(NonPagedPoolNx, &Context);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, (ULONG)PsInsertPermanentSiloContext(NULL, Slot, Context));

        /* 0, 0xC00000BB (STATUS_NOT_SUPPORTED), 1: a second context
         * does not go where one is; let go of, it is cleaned up. */
        Status = NkcContext(NonPagedPoolNx, &Second);
        NkcPut(Log, (ULONG)Status);
        if (NT_SUCCESS(Status)) {
            NkcPut(Log, (ULONG)PsInsertPermanentSiloContext(NULL, Slot, Second));
            PsDereferenceSiloContext(Second);
            NkcPut(Log, (ULONG)(NkcCleanupCalls - Cleanups));
        }

        /* 0, 1: the slot gives the first context back. */
        Found = (PVOID)(ULONG_PTR)1;
        NkcPut(Log, (ULONG)PsGetPermanentSiloContext(NULL, Slot, &Found));
        NkcPut(Log, Found == Context ? 1 : 0);

        /* 0: the maker's reference dropped, the context stays: the slot
         * holds it. */
        Cleanups = NkcCleanupCalls;
        PsDereferenceSiloContext(Context);
        NkcPut(Log, (ULONG)(NkcCleanupCalls - Cleanups));
    }

    /* Unregistered. 1, 0xF: the terminate callback is called once, for
     * the host silo, as the create callback was. 1, 1: and the context
     * in the monitor's slot is cleaned up, that very one. */
    Cleanups = NkcCleanupCalls;
    NkcCleaned = NULL;
    NkcCallbackFacts = 0;
    PsUnregisterSiloMonitor(Monitor);
    NkcPut(Log, (ULONG)NkcTerminateCalls);
    NkcPut(Log, (ULONG)NkcCallbackFacts);
    NkcPut(Log, (ULONG)(NkcCleanupCalls - Cleanups));
    NkcPut(Log, Context != NULL && NkcCleaned == Context ? 1 : 0);

    /* 0, 0, then 1, 1 as before: a monitor that does not watch the host
     * is started and ended with no callback called. */
    Registration.MonitorHost = FALSE;
    Monitor = NULL;
    Status = PsRegisterSiloMonitor(&Registration, &Monitor);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, (ULONG)PsStartSiloMonitor(Monitor));
        PsUnregisterSiloMonitor(Monitor);
    }
    NkcPut(Log, (ULONG)NkcCreateCalls);
    NkcPut(Log, (ULONG)NkcTerminateCalls);
}

static VOID NkcSilos(NKC_LOG *Log)
{
    PESILO Silo, Previous, Inner;
    PVOID Context, Found;
    ULONG Slot = 0xFFFFFFFF;
    LONG Cleanups;
    NTSTATUS Status;

    NkcCreateCalls = 0;
    NkcTerminateCalls = 0;
    NkcCleanupCalls = 0;
    NkcMonitorThread = PsGetCurrentThread();

    /* 1, 1, 1, 1: a system thread is in the host silo, which is NULL,
     * and in no server silo; NULL is the host silo. */
    NkcPut(Log, PsGetCurrentSilo() == NULL ? 1 : 0);
    NkcPut(Log, PsGetCurrentServerSilo() == NULL ? 1 : 0);
    NkcPut(Log, PsIsHostSilo(NULL));
    NkcPut(Log, PsIsHostSilo(PsGetCurrentSilo()));

    /* 0xC000000D, 1: no job has no silo: the routine wants a job, and
     * leaves the caller's pointer alone. */
    Silo = (PESILO)(ULONG_PTR)1;
    NkcPut(Log, (ULONG)PsGetJobSilo(NULL, &Silo));
    NkcPut(Log, Silo == (PESILO)(ULONG_PTR)1 ? 1 : 0);

    /* Attaching the thread to the host silo. 3: what comes back to be
     * restored is not a silo but the mark of a thread attached to none
     * (-3). 1: attached, the current silo is the host. 0: attached
     * again, what comes back is the host. 1: detached twice, still the
     * host, by way of the process. 3: and the mark is back. */
    Previous = PsAttachSiloToCurrentThread(NULL);
    NkcPut(Log, NkcSiloCode(Previous));
    NkcPut(Log, PsGetCurrentSilo() == NULL ? 1 : 0);
    Inner = PsAttachSiloToCurrentThread(NULL);
    NkcPut(Log, NkcSiloCode(Inner));
    PsDetachSiloFromCurrentThread(Inner);
    PsDetachSiloFromCurrentThread(Previous);
    NkcPut(Log, PsGetCurrentSilo() == NULL ? 1 : 0);
    Previous = PsAttachSiloToCurrentThread(NULL);
    NkcPut(Log, NkcSiloCode(Previous));
    PsDetachSiloFromCurrentThread(Previous);

    /* 0xC000000D: a context is not made from NonPagedPool (it is made
     * from NonPagedPoolNx or PagedPool).
     * 0, 1, 1: made from NonPagedPoolNx and let go of, it is cleaned
     * up, once, and the callback is given the context.
     * 0, 1: the same from PagedPool. */
    /* The pool type by its number: the kit's headers turn the name
     * NonPagedPool into NonPagedPoolNx on ARM64. */
    Status = NkcContext((POOL_TYPE)0, &Context);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        PsDereferenceSiloContext(Context);
    }
    Cleanups = NkcCleanupCalls;
    Status = NkcContext(NonPagedPoolNx, &Context);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        PsDereferenceSiloContext(Context);
    }
    NkcPut(Log, (ULONG)(NkcCleanupCalls - Cleanups));
    NkcPut(Log, NT_SUCCESS(Status) && NkcCleaned == Context ? 1 : 0);
    Cleanups = NkcCleanupCalls;
    Status = NkcContext(PagedPool, &Context);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        PsDereferenceSiloContext(Context);
    }
    NkcPut(Log, (ULONG)(NkcCleanupCalls - Cleanups));

    /* 0: a slot. 0xC0000225 (STATUS_NOT_FOUND), 1: nothing is in it for
     * the host silo, and the caller's pointer is set to null.
     * 0xC000000D, a guess: a slot number there is not. */
    Status = PsAllocSiloContextSlot(0, &Slot);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        Found = (PVOID)(ULONG_PTR)1;
        NkcPut(Log, (ULONG)PsGetPermanentSiloContext(NULL, Slot, &Found));
        NkcPut(Log, Found == NULL ? 1 : 0);
        Found = (PVOID)(ULONG_PTR)1;
        NkcPut(Log, (ULONG)PsGetPermanentSiloContext(NULL, 0xFFFF, &Found));
    }

    NkcMonitors(Log, Slot);

    /* 0, 0xC000000D: the slot is freed, once. */
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, (ULONG)PsFreeSiloContextSlot(Slot));
        NkcPut(Log, (ULONG)PsFreeSiloContextSlot(Slot));
    }

    /* 0: at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}

static VOID NkcRunList(ULONG List, NKC_LOG *Log)
{
    UNREFERENCED_PARAMETER(List);
    NkcOnSystemThread(NkcSilos, Log);
}
