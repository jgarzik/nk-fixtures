/*
 * Conformance: objects, references and handles.
 *
 * What the reference routines return, referencing an object through a
 * handle (the right handle, the wrong type, no handle, more access than
 * the handle has, a kernel handle used for user mode), and the kernel's
 * shared store of security descriptors.
 *
 * Two lists.
 *
 * List 0 (0x222000) calls documented routines. It is made on a system
 * thread: a handle that is not a kernel handle is one of the current
 * process, and which process sends the request differs between systems.
 * On a system thread it is the System process.
 *
 * List 1 (0x222004) is the security-descriptor store, three routines of
 * nkc-undoc.h: ObLogSecurityDescriptor, ObReferenceSecurityDescriptor
 * and ObDereferenceSecurityDescriptor.
 *
 * A count of references is never logged, only the difference between
 * two: how many references an object has is the kernel's business. The
 * object counted is a device of this driver that has no name, so that
 * nothing else can be holding or dropping references meanwhile.
 *
 * Left out: object directories and symbolic links through
 * ZwCreateDirectoryObject and ZwOpenSymbolicLinkObject, ZwDuplicateObject,
 * ObQueryNameString and named events. Closing a handle twice is left out
 * as well: a kernel handle that is not one stops Windows.
 */

#include <ntifs.h>

#define NKC_DEVICE L"\\Device\\NkcOb"
#define NKC_THREADS
#define NKC_LISTS 2
#include "nkc.h"
#include "nkc-undoc.h"

/* Every access right a thread has. */
#define NKC_THREAD_ALL 0x1FFFFF
/* THREAD_SUSPEND_RESUME: a right a handle opened to wait does not have. */
#define NKC_THREAD_SUSPEND 0x2

typedef struct _NKC_IDLE {
    KEVENT Ready;
    KEVENT Go;
    PVOID Self; /* the thread, as it sees itself */
} NKC_IDLE;

static KSTART_ROUTINE NkcIdle;

/* A thread that says who it is and waits to be let go. */
static VOID NkcIdle(PVOID Context)
{
    NKC_IDLE *Idle = (NKC_IDLE *)Context;

    Idle->Self = PsGetCurrentThread();
    KeSetEvent(&Idle->Ready, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(&Idle->Go, Executive, KernelMode, FALSE, NULL);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Reference through a handle and log: the status, whether an object
 * came back, and the access the handle is said to have. A reference
 * taken is dropped again. Returns the object, no longer referenced, for
 * comparing. */
static PVOID NkcByHandle(NKC_LOG *Log, HANDLE Handle, ACCESS_MASK Desired, POBJECT_TYPE Type,
                         KPROCESSOR_MODE Mode)
{
    OBJECT_HANDLE_INFORMATION Information;
    PVOID Object = (PVOID)(ULONG_PTR)1;
    NTSTATUS Status;

    Information.HandleAttributes = 0xAAAAAAAA;
    Information.GrantedAccess = 0xAAAAAAAA;
    Status = ObReferenceObjectByHandleWithTag(Handle, Desired, Type, Mode, NKC_TAG, &Object,
                                              &Information);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Object == NULL ? 0 : 1);
    NkcPut(Log, Information.GrantedAccess);
    if (!NT_SUCCESS(Status)) {
        return NULL;
    }
    ObfDereferenceObjectWithTag(Object, NKC_TAG);
    return Object;
}

static VOID NkcCounts(NKC_LOG *Log)
{
    PDEVICE_OBJECT Device = NULL;
    LONG_PTR First, Second, Third, Fourth, Fifth, Last;
    NTSTATUS Status;

    /* 0: a device with no name, to count the references of. */
    Status = IoCreateDevice(NkcDeviceObject->DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE,
                            &Device);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    /* 1: each reference is one more, and ObfReferenceObject returns the
     * count it made. */
    First = ObfReferenceObject(Device);
    Second = ObfReferenceObject(Device);
    NkcPut(Log, (ULONG)(Second - First));

    /* 0: ObfDereferenceObject returns the count it left: what the first
     * reference had made. */
    Third = ObfDereferenceObject(Device);
    NkcPut(Log, (ULONG)(Third - First));

    /* 1, 0: the same with a tag; the tag changes no count. */
    Fourth = ObfReferenceObjectWithTag(Device, NKC_TAG);
    NkcPut(Log, (ULONG)(Fourth - Third));
    Fifth = ObfDereferenceObjectWithTag(Device, NKC_TAG);
    NkcPut(Log, (ULONG)(Fifth - Third));

    /* 1: a reference taken with a tag can be dropped without one.
     * 2: and so the count is where it began, two below the most. */
    ObfReferenceObjectWithTag(Device, NKC_TAG);
    NkcPut(Log, (ULONG)(ObfDereferenceObject(Device) - Third == 0 ? 1 : 0));
    Last = ObfDereferenceObject(Device);
    NkcPut(Log, (ULONG)(Second - Last));

    IoDeleteDevice(Device);
}

static VOID NkcHandles(NKC_LOG *Log)
{
    NKC_IDLE Idle;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Kernel = NULL, User = NULL, Wrong = NULL;
    PVOID Thread, Held = NULL;
    NTSTATUS Status;

    RtlZeroMemory(&Idle, sizeof(Idle));
    KeInitializeEvent(&Idle.Ready, NotificationEvent, FALSE);
    KeInitializeEvent(&Idle.Go, NotificationEvent, FALSE);
    InitializeObjectAttributes(&Attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    /* 0: a thread, and a kernel handle to it with every access. */
    Status = PsCreateSystemThread(&Kernel, NKC_THREAD_ALL, &Attributes, NULL, NULL, NkcIdle,
                                  &Idle);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status)) {
        return;
    }
    KeWaitForSingleObject(&Idle.Ready, Executive, KernelMode, FALSE, NULL);
    /* Held until the thread has ended: its state is on this stack. */
    Status = ObReferenceObjectByHandle(Kernel, NKC_THREAD_ALL, *PsThreadType, KernelMode, &Held,
                                       NULL);
    if (!NT_SUCCESS(Status)) {
        Held = NULL;
    }

    /* 0, 1, 0x1FFFFF; 1: the handle gives the thread itself, and has
     * the access it was created with. */
    Thread = NkcByHandle(Log, Kernel, NKC_THREAD_ALL, *PsThreadType, KernelMode);
    NkcPut(Log, Thread == Idle.Self ? 1 : 0);

    /* 0xC0000024 (STATUS_OBJECT_TYPE_MISMATCH), 0, 0xAAAAAAAA: it is
     * not a handle to an event. Guesses: the caller's pointer is set to
     * null, and the access is not reported, so that the caller's value
     * stays; the same in every refusal below. */
    NkcByHandle(Log, Kernel, 0, *ExEventObjectType, KernelMode);

    /* 0, 1, 0x1FFFFF: kernel mode may ask for no type in particular. */
    NkcByHandle(Log, Kernel, 0, NULL, KernelMode);

    /* 0xC0000008 (STATUS_INVALID_HANDLE), 0, 0xAAAAAAAA: a kernel handle
     * is no handle at all for user mode. */
    NkcByHandle(Log, Kernel, 0, *PsThreadType, UserMode);

    /* 0xC0000008, 0, 0xAAAAAAAA: nor is null a handle. */
    NkcByHandle(Log, NULL, 0, *PsThreadType, KernelMode);

    /* 0, 1, 0x1FFFFF; 1: the handle that means "this thread" gives this
     * thread, with every access.
     * 0xC0000024, 0, 0xAAAAAAAA: the one that means "this process" is
     * not a thread. */
    Thread = NkcByHandle(Log, NtCurrentThread(), 0, *PsThreadType, KernelMode);
    NkcPut(Log, Thread == (PVOID)PsGetCurrentThread() ? 1 : 0);
    NkcByHandle(Log, NtCurrentProcess(), 0, *PsThreadType, KernelMode);

    /* 0xC0000024: a thread is not opened as an event. */
    Status = ObOpenObjectByPointer(Idle.Self, OBJ_KERNEL_HANDLE, NULL, SYNCHRONIZE,
                                   *ExEventObjectType, KernelMode, &Wrong);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        ZwClose(Wrong);
    }

    /* 0: a second handle to the thread, in the System process's own
     * table and good for waiting only.
     * 1, 0: a kernel handle is a negative number, this one is not.
     * 0, 0: both are multiples of four. */
    Status = ObOpenObjectByPointer(Idle.Self, 0, NULL, SYNCHRONIZE, *PsThreadType, KernelMode,
                                   &User);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, (LONG_PTR)Kernel < 0 ? 1 : 0);
    NkcPut(Log, (LONG_PTR)User < 0 ? 1 : 0);
    NkcPut(Log, (ULONG)((ULONG_PTR)Kernel & 3));
    NkcPut(Log, (ULONG)((ULONG_PTR)User & 3));
    if (NT_SUCCESS(Status)) {
        /* 0, 1, 0x100000: user mode may have what the handle has.
         * 0, 1, 0x100000: or nothing in particular.
         * 0xC0000022 (STATUS_ACCESS_DENIED), 0, 0xAAAAAAAA: but no more.
         * 0, 1, 0x100000: kernel mode is not held to the handle's
         * access; the access reported is still the handle's. */
        NkcByHandle(Log, User, SYNCHRONIZE, *PsThreadType, UserMode);
        NkcByHandle(Log, User, 0, *PsThreadType, UserMode);
        NkcByHandle(Log, User, NKC_THREAD_SUSPEND, *PsThreadType, UserMode);
        NkcByHandle(Log, User, NKC_THREAD_SUSPEND, *PsThreadType, KernelMode);

        /* 0: closed. */
        NkcPut(Log, (ULONG)ZwClose(User));
    }

    /* 0: the kernel handle closed. 0: the thread, let go, ends; with
     * no handle left it is still an object while it is referenced. */
    NkcPut(Log, (ULONG)ZwClose(Kernel));
    KeSetEvent(&Idle.Go, IO_NO_INCREMENT, FALSE);
    if (Held != NULL) {
        NkcPut(Log, (ULONG)KeWaitForSingleObject(Held, Executive, KernelMode, FALSE, NULL));
        ObDereferenceObject(Held);
    } else {
        /* Without a reference there is nothing to wait on but time. */
        NkcSleep(200);
        NkcPut(Log, 0xFFFFFFFF);
    }
}

static VOID NkcObjects(NKC_LOG *Log)
{
    NkcCounts(Log);
    NkcHandles(Log);
    /* 0: at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}

static VOID NkcRun(NKC_LOG *Log)
{
    NkcOnSystemThread(NkcObjects, Log);
}

/*
 * List 1: the store of security descriptors.
 */

/* Room for a small self-relative descriptor, aligned as pool is. */
typedef union _NKC_SD_ROOM {
    ULONGLONG Align[8];
    UCHAR Bytes[64];
} NKC_SD_ROOM;

/* A self-relative descriptor with an owner, S-1-5-32-`Rid`, and nothing
 * else; its length. */
static ULONG NkcOwnedBy(NKC_SD_ROOM *Room, ULONG Rid)
{
    PISECURITY_DESCRIPTOR_RELATIVE Relative = (PISECURITY_DESCRIPTOR_RELATIVE)Room->Bytes;
    PUCHAR Sid = Room->Bytes + sizeof(*Relative);
    ULONG Sub[2];

    RtlZeroMemory(Room, sizeof(*Room));
    Relative->Revision = SECURITY_DESCRIPTOR_REVISION;
    Relative->Control = SE_SELF_RELATIVE;
    Relative->Owner = sizeof(*Relative);
    Sid[0] = SID_REVISION;
    Sid[1] = 2;
    Sid[7] = 5;
    Sub[0] = 32;
    Sub[1] = Rid;
    RtlCopyMemory(Sid + 8, Sub, sizeof(Sub));
    return sizeof(*Relative) + 8 + sizeof(Sub);
}

static ULONG NkcSameBytes(const VOID *A, const VOID *B, ULONG Length)
{
    const UCHAR *a = (const UCHAR *)A;
    const UCHAR *b = (const UCHAR *)B;
    ULONG i;

    for (i = 0; i < Length; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static VOID NkcRunList(ULONG List, NKC_LOG *Log)
{
    NKC_SD_ROOM One, Copy, Other;
    PSECURITY_DESCRIPTOR First = NULL, Second = NULL, Third = NULL, Fourth = NULL;
    ULONG Length;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(List);
    Length = NkcOwnedBy(&One, 0x4E4B);
    NkcOwnedBy(&Copy, 0x4E4B);
    NkcOwnedBy(&Other, 0x4E4C);

    /* 36: the descriptor's length. */
    NkcPut(Log, RtlLengthSecurityDescriptor(One.Bytes));

    /* 0: logged. 1: what comes back is not the caller's descriptor but
     * a copy of it; 1: byte for byte. */
    Status = ObLogSecurityDescriptor(One.Bytes, &First, 1);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status) || First == NULL) {
        return;
    }
    NkcPut(Log, First != (PSECURITY_DESCRIPTOR)One.Bytes ? 1 : 0);
    NkcPut(Log, NkcSameBytes(First, One.Bytes, Length));

    /* 0, 1: logged again, the same copy comes back. */
    Status = ObLogSecurityDescriptor(One.Bytes, &Second, 1);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Second == First ? 1 : 0);

    /* 0, 1: and for the same bytes at another address: the store goes
     * by what a descriptor says, not by where it is. */
    Status = ObLogSecurityDescriptor(Copy.Bytes, &Third, 1);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Third == First ? 1 : 0);

    /* 0, 1: a descriptor that says something else gets another. */
    Status = ObLogSecurityDescriptor(Other.Bytes, &Fourth, 1);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Fourth != First ? 1 : 0);

    /* 1: two more references taken and dropped, the copy is still
     * there, unchanged. */
    ObReferenceSecurityDescriptor(First, 2);
    ObDereferenceSecurityDescriptor(First, 2);
    NkcPut(Log, NkcSameBytes(First, One.Bytes, Length));

    /* Every reference logging gave is dropped: one each time. */
    if (Fourth != NULL) {
        ObDereferenceSecurityDescriptor(Fourth, 1);
    }
    if (Third != NULL) {
        ObDereferenceSecurityDescriptor(Third, 1);
    }
    if (Second != NULL) {
        ObDereferenceSecurityDescriptor(Second, 1);
    }
    ObDereferenceSecurityDescriptor(First, 1);

    /* 0: at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
