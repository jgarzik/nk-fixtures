/*
 * Conformance: an exception that crosses the kernel.
 *
 * A driver may call another through the kernel: IoCallDriver runs the
 * other driver's dispatch routine, and IoCompleteRequest, called there,
 * runs this driver's completion routine. This driver sends requests of
 * its own making to nkc-cross-b (load that one first) with a __try
 * around IoCallDriver, has an exception raised on the far side, and
 * logs what its own filter, __finally blocks and handler see, and in
 * what order, with the kernel's frames between the raise and the
 * handler. Whether the handler sees the exception at all is the first
 * thing the list says.
 *
 * The list is made of marks and facts, as in nkc-seh.c. A mark is
 * NKC_MARK | n; this driver's are below 0xB0, nkc-cross-b's from 0xB0
 * up, and marks from 0xE0 up are points that must not be reached. A
 * filter logs four values: its mark, then the exception's code, flags
 * and number of parameters.
 *
 * What is written next to each case is a prediction. It has not been
 * seen on Windows; the oracle's recording decides.
 *
 * Each request is an IRP from IoAllocateIrp with a completion routine
 * that keeps it (STATUS_MORE_PROCESSING_REQUIRED), so that this driver
 * frees it whatever became of it. A request whose dispatch routine
 * raised was never completed; nobody else holds it either.
 *
 * NKC_CROSS_DPC, a device-control code of this driver (0x222440), is
 * apart from the list, because it may stop the system: a DPC routine
 * raises while the thread that queued the DPC is inside a __try. The
 * request completes with 0xE04E4BC1 if that __try's handler got the
 * exception, with 0xE04E4BC0 if the raise came to nothing; on Windows it
 * may do neither, and the oracle then records the bugcheck.
 *
 * One request at a time: the DPC is one object, and a second request
 * that arrives while one is being served is refused. NKC_CROSS_DPC
 * completes with STATUS_DEVICE_BUSY then; the run request logs the mark
 * 0xEA alone, a point that must not be reached when the oracle, which
 * makes one request at a time, is the caller.
 *
 * Of the undocumented routines in nkc-undoc.h this driver uses the one
 * the compiler calls: __C_specific_handler.
 *
 * A test fixture: for a kernel under test and the reference machine it
 * is compared with. Never install it on a production system.
 */

#define NKC_DEVICE L"\\Device\\NkcCross"
#define NKC_CONTROL
#include "nkc.h"
#include "nkc-cross.h"

#define NKC_CROSS_DPC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NKC_DPC_CAUGHT NKC_STATUS(0xC1)
#define NKC_DPC_NOTHING NKC_STATUS(0xC0)

/* Always zero, and the compiler cannot know it: the raises below are not
 * known never to return. */
static volatile ULONG NkcZero;

/* The DPC outlives the request that queues it. It is initialised once,
 * by the first request that needs it (NkcDpcReady), and only one request
 * is served at a time (NkcBusy), so no two set it up or queue it at
 * once. */
static KDPC NkcDpc;
static volatile LONG NkcDpcReady;
static volatile LONG NkcBusy;

/* Take the driver for one request; FALSE if another has it. */
static BOOLEAN NkcEnter(VOID)
{
    return InterlockedCompareExchange(&NkcBusy, 1, 0) == 0;
}

static VOID NkcLeave(VOID)
{
    InterlockedExchange(&NkcBusy, 0);
}

static IO_COMPLETION_ROUTINE NkcDone;
static IO_COMPLETION_ROUTINE NkcRaisingDone;
static KDEFERRED_ROUTINE NkcDeferred;

static DECLSPEC_NOINLINE VOID NkcRaise(NTSTATUS Status)
{
    if (NkcZero == 0) {
        ExRaiseStatus(Status);
    }
}

/* A filter: log the mark and what the exception record says, then give
 * `Answer`. */
static DECLSPEC_NOINLINE LONG NkcFilter(NKC_LOG *Log, ULONG Mark, PEXCEPTION_POINTERS Info,
                                        LONG Answer)
{
    PEXCEPTION_RECORD Record = Info->ExceptionRecord;

    MARK(Mark);
    NkcPut(Log, (ULONG)Record->ExceptionCode);
    NkcPut(Log, Record->ExceptionFlags);
    NkcPut(Log, Record->NumberParameters);
    return Answer;
}

/* The completion routine of every request but one: log 0x0C and the
 * status the request was completed with, and keep the IRP. */
static NTSTATUS NkcDone(PDEVICE_OBJECT Device, PIRP Irp, PVOID Context)
{
    NKC_LOG *Log = (NKC_LOG *)Context;

    UNREFERENCED_PARAMETER(Device);
    MARK(0x0C);
    NkcPut(Log, (ULONG)Irp->IoStatus.Status);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* The completion routine that raises: 0x33, then NKC_STATUS(0x33). */
static NTSTATUS NkcRaisingDone(PDEVICE_OBJECT Device, PIRP Irp, PVOID Context)
{
    NKC_LOG *Log = (NKC_LOG *)Context;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Irp);
    MARK(0x33);
    NkcRaise(NKC_STATUS(0x33));
    MARK(0xE3);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* A request for nkc-cross-b: device control `Code`, with `Cross` for it
 * to log through, and `Done` to run when it is completed. */
static PIRP NkcRequest(PDEVICE_OBJECT Target, ULONG Code, NKC_CROSS *Cross,
                       PIO_COMPLETION_ROUTINE Done)
{
    PIRP Irp = IoAllocateIrp(Target->StackSize, FALSE);
    PIO_STACK_LOCATION Next;

    if (Irp == NULL) {
        return NULL;
    }
    Next = IoGetNextIrpStackLocation(Irp);
    Next->MajorFunction = IRP_MJ_DEVICE_CONTROL;
    Next->Parameters.DeviceIoControl.IoControlCode = Code;
    Next->Parameters.DeviceIoControl.Type3InputBuffer = Cross;
    IoSetCompletionRoutine(Irp, Done, Cross->Log, TRUE, TRUE, TRUE);
    return Irp;
}

/* Nothing raises.
 * 01; B0: the other driver's dispatch routine; 0C, 0: this driver's
 * completion routine, called from inside the other's IoCompleteRequest,
 * with the status the request was completed with; 0: what IoCallDriver
 * returns is the dispatch routine's status; 02. */
static DECLSPEC_NOINLINE VOID NkcQuiet(NKC_LOG *Log, PDEVICE_OBJECT Target, NKC_CROSS *Cross)
{
    PIRP Irp = NkcRequest(Target, NKC_CROSS_QUIET, Cross, NkcDone);

    if (Irp == NULL) {
        MARK(0xE0);
        return;
    }
    MARK(0x01);
    NkcPut(Log, (ULONG)IoCallDriver(Target, Irp));
    MARK(0x02);
    IoFreeIrp(Irp);
}

/* The other driver's dispatch routine raises.
 * 11; B1: down to the raise;
 * filter 12 (E04E4B31, 1, 0): the search for a handler passes
 * IoCallDriver and reaches this driver's __try;
 * 13, E04E4B31: the handler; 14.
 * The request was not completed: the completion routine's 0C is absent. */
static DECLSPEC_NOINLINE VOID NkcRaised(NKC_LOG *Log, PDEVICE_OBJECT Target, NKC_CROSS *Cross)
{
    PIRP Irp = NkcRequest(Target, NKC_CROSS_RAISE, Cross, NkcDone);

    if (Irp == NULL) {
        MARK(0xE0);
        return;
    }
    __try {
        MARK(0x11);
        IoCallDriver(Target, Irp);
        MARK(0xE1);
    } __except (NkcFilter(Log, 0x12, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x13);
        NkcPut(Log, (ULONG)GetExceptionCode());
    }
    MARK(0x14);
    IoFreeIrp(Irp);
}

/* __finally blocks on both sides of the kernel.
 * 21; B2: down to the raise;
 * filter 22 (E04E4B32, 1, 0): every filter is asked before anything is
 * unwound;
 * B3, 1: the other driver's __finally, the innermost, runs first;
 * 23, 1: then this driver's, on the near side of IoCallDriver;
 * 24: then the handler; 25. */
static DECLSPEC_NOINLINE VOID NkcFinally(NKC_LOG *Log, PDEVICE_OBJECT Target, NKC_CROSS *Cross)
{
    PIRP Irp = NkcRequest(Target, NKC_CROSS_FINALLY, Cross, NkcDone);

    if (Irp == NULL) {
        MARK(0xE0);
        return;
    }
    __try {
        __try {
            MARK(0x21);
            IoCallDriver(Target, Irp);
            MARK(0xE2);
        } __finally {
            MARK(0x23);
            NkcPut(Log, AbnormalTermination() ? 1 : 0);
        }
    } __except (NkcFilter(Log, 0x22, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x24);
    }
    MARK(0x25);
    IoFreeIrp(Irp);
}

/* This driver's completion routine raises, two kernel routines deep:
 * IoCallDriver, the other driver's dispatch routine, IoCompleteRequest,
 * the completion routine.
 * 31; B4: the other driver, about to complete the request;
 * 33: the completion routine, which raises;
 * filter 32 (E04E4B33, 1, 0);
 * B6, 1: the other driver's __finally around its IoCompleteRequest;
 * 34, E04E4B33: the handler; 35. */
static DECLSPEC_NOINLINE VOID NkcCompletion(NKC_LOG *Log, PDEVICE_OBJECT Target,
                                            NKC_CROSS *Cross)
{
    PIRP Irp = NkcRequest(Target, NKC_CROSS_COMPLETE, Cross, NkcRaisingDone);

    if (Irp == NULL) {
        MARK(0xE0);
        return;
    }
    __try {
        MARK(0x31);
        IoCallDriver(Target, Irp);
        MARK(0xE4);
    } __except (NkcFilter(Log, 0x32, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x34);
        NkcPut(Log, (ULONG)GetExceptionCode());
    }
    MARK(0x35);
    IoFreeIrp(Irp);
}

static VOID NkcRun(NKC_LOG *Log)
{
    UNICODE_STRING Name;
    PFILE_OBJECT File;
    PDEVICE_OBJECT Target;
    NKC_CROSS Cross;
    NTSTATUS Status;

    if (!NkcEnter()) {
        MARK(0xEA);
        return;
    }

    /* 0: the other driver's device is there, and opens. */
    RtlInitUnicodeString(&Name, NKC_CROSS_DEVICE_B);
    Status = IoGetDeviceObjectPointer(&Name, FILE_READ_DATA, &File, &Target);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status)) {
        NkcLeave();
        return;
    }
    Cross.Magic = NKC_CROSS_MAGIC;
    Cross.Log = Log;

    NkcQuiet(Log, Target, &Cross);
    NkcRaised(Log, Target, &Cross);
    NkcFinally(Log, Target, &Cross);
    NkcCompletion(Log, Target, &Cross);

    /* 0, 0: after all of it this thread is at PASSIVE_LEVEL with APCs
     * enabled, as it began: nothing the kernel does around a dispatch
     * or a completion routine was left undone by the unwinds. */
    NkcPut(Log, KeGetCurrentIrql());
    NkcPut(Log, KeAreApcsDisabled() ? 1 : 0);

    ObDereferenceObject(File);
    NkcLeave();
}

static VOID NkcDeferred(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    NkcRaise(NKC_STATUS(0x41));
}

/* Queue a DPC that raises, at DISPATCH_LEVEL, and lower the IRQL inside
 * a __try: the DPC runs on this processor before KeLowerIrql is over,
 * with this thread, and this __try, beneath it. */
static DECLSPEC_NOINLINE NTSTATUS NkcDpcUnderTry(VOID)
{
    NTSTATUS Status;
    KIRQL Old;

    if (InterlockedCompareExchange(&NkcDpcReady, 1, 0) == 0) {
        KeInitializeDpc(&NkcDpc, NkcDeferred, NULL);
    }
    __try {
        KeRaiseIrql(DISPATCH_LEVEL, &Old);
        KeInsertQueueDpc(&NkcDpc, NULL, NULL);
        KeLowerIrql(Old);
        Status = NKC_DPC_NOTHING;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = NKC_DPC_CAUGHT;
    }
    return Status;
}

static NTSTATUS NkcControl(ULONG Code)
{
    NTSTATUS Status;

    if (Code != NKC_CROSS_DPC) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!NkcEnter()) {
        return STATUS_DEVICE_BUSY;
    }
    Status = NkcDpcUnderTry();
    NkcLeave();
    return Status;
}
