/*
 * Conformance: exceptions nothing handles, and a fault no __try catches.
 *
 * Unlike the other conformance drivers this one is for stopping the
 * system. Each device-control code below does one thing that Windows
 * answers with a bugcheck; the oracle records the bugcheck's code and
 * first parameter, and a kernel under test must stop the same way.
 *
 *   0x222400  NKC_FATAL_DISPATCH  ExRaiseStatus(0xE04E4B11), unhandled,
 *             in the dispatch routine: the requestor's thread, inside
 *             its device-control system call
 *   0x222404  NKC_FATAL_WORK      ExRaiseStatus(0xE04E4B12), unhandled,
 *             in a work item's routine: a system worker thread
 *   0x222408  NKC_FATAL_DPC       ExRaiseStatus(0xE04E4B13), unhandled,
 *             in a DPC routine: DISPATCH_LEVEL, whatever thread was running
 *   0x22240C  NKC_FATAL_KERNEL_READ  a read of the unmapped kernel
 *             address 0xFFFFF7804E4B0000 inside a __try whose filter
 *             accepts everything: a fault on a kernel address is not
 *             turned into an exception, so the filter is never asked
 *   0x222410  NKC_FATAL_THREAD    ExRaiseStatus(0xE04E4B15), unhandled,
 *             in a system thread the driver creates
 *
 * Each status is the driver's own, so the bugcheck's parameter says
 * which case stopped the system. No request is expected to complete. If
 * one does, the kernel got it wrong, and the status says how:
 * 0xE04E4BF0 the raise returned or was swallowed (the routine was given
 * two seconds); 0xE04E4BF1 the read of the kernel address returned;
 * 0xE04E4BF2 the __try caught the fault.
 *
 * The kernel address is in the 512 GiB slot that holds the shared user
 * data page (0xFFFFF78000000000 on both architectures), over a gigabyte
 * above that page. That nothing is mapped there on Windows is an
 * assumption; the oracle's transcript settles it, and status 0xE04E4BF1
 * instead of a bugcheck means another address has to be chosen.
 *
 * NKC_IOCTL_RUN works as in every conformance driver and returns an
 * empty list: there is nothing to observe without stopping.
 *
 * Of the undocumented routines in nkc-undoc.h this driver uses the one
 * the compiler calls: __C_specific_handler.
 */

#define NKC_DEVICE L"\\Device\\NkcSehFatal"
#define NKC_THREADS
#define NKC_CONTROL
#include "nkc.h"

#define NKC_FATAL(n) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900 + (n), METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NKC_FATAL_DISPATCH NKC_FATAL(0)
#define NKC_FATAL_WORK NKC_FATAL(1)
#define NKC_FATAL_DPC NKC_FATAL(2)
#define NKC_FATAL_KERNEL_READ NKC_FATAL(3)
#define NKC_FATAL_THREAD NKC_FATAL(4)

#define NKC_STATUS(n) ((NTSTATUS)(0xE04E4B00u | (n)))
#define NKC_SURVIVED NKC_STATUS(0xF0)
#define NKC_READ_RETURNED NKC_STATUS(0xF1)
#define NKC_READ_CAUGHT NKC_STATUS(0xF2)

#define NKC_UNMAPPED_KERNEL_ADDRESS ((ULONG_PTR)0xFFFFF7804E4B0000)

/* Always zero, and the compiler cannot know it: the raises below are not
 * known never to return, and the address is not a constant. */
static volatile ULONG NkcZero;

/* The DPC outlives the request that queues it. */
static KDPC NkcDpc;

static IO_WORKITEM_ROUTINE NkcWork;
static KDEFERRED_ROUTINE NkcDeferred;
static KSTART_ROUTINE NkcThread;

static DECLSPEC_NOINLINE VOID NkcRaise(NTSTATUS Status)
{
    if (NkcZero == 0) {
        ExRaiseStatus(Status);
    }
}

static VOID NkcWork(PDEVICE_OBJECT Device, PVOID Context)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Context);
    NkcRaise(NKC_STATUS(0x12));
}

static VOID NkcDeferred(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    NkcRaise(NKC_STATUS(0x13));
}

static VOID NkcThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    NkcRaise(NKC_STATUS(0x15));
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Read four bytes at `Address`. */
static DECLSPEC_NOINLINE ULONG NkcPeek(ULONG_PTR Address)
{
    volatile ULONG *Where = (volatile ULONG *)(Address + NkcZero);

    return *Where;
}

static DECLSPEC_NOINLINE NTSTATUS NkcKernelRead(VOID)
{
    NTSTATUS Status;

    __try {
        NkcPeek(NKC_UNMAPPED_KERNEL_ADDRESS);
        Status = NKC_READ_RETURNED;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = NKC_READ_CAUGHT;
    }
    return Status;
}

static NTSTATUS NkcControl(ULONG Code)
{
    PIO_WORKITEM Item;

    switch (Code) {
    case NKC_FATAL_DISPATCH:
        NkcRaise(NKC_STATUS(0x11));
        return NKC_SURVIVED;

    case NKC_FATAL_WORK:
        /* The item is not freed: its routine does not return. */
        Item = IoAllocateWorkItem(NkcDeviceObject);
        if (Item == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        IoQueueWorkItem(Item, NkcWork, DelayedWorkQueue, NULL);
        NkcSleep(2000);
        return NKC_SURVIVED;

    case NKC_FATAL_DPC:
        KeInitializeDpc(&NkcDpc, NkcDeferred, NULL);
        KeInsertQueueDpc(&NkcDpc, NULL, NULL);
        NkcSleep(2000);
        return NKC_SURVIVED;

    case NKC_FATAL_KERNEL_READ:
        return NkcKernelRead();

    case NKC_FATAL_THREAD:
        NkcJoin(NkcStart(NkcThread, NULL));
        return NKC_SURVIVED;

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

/* Nothing to log. */
static VOID NkcRun(NKC_LOG *Log)
{
    UNREFERENCED_PARAMETER(Log);
}
