/*
 * Conformance: the far side of an exception that crosses the kernel.
 *
 * This driver does what nkc-cross asks of it, in its dispatch routine:
 * complete a request, or raise an exception that nothing in this driver
 * handles. What is being observed is in nkc-cross.c: whether, and in
 * what order, a __try in the driver that sent the request sees an
 * exception raised here, with the kernel's IoCallDriver and
 * IoCompleteRequest between the two.
 *
 * The requests are nkc-cross's own (see nkc-cross.h). One from user
 * mode is refused before the address it carries is looked at; one from
 * kernel mode whose block does not begin with nkc-cross's magic value
 * is refused before anything else in the block is used.
 *
 * A test fixture: for a kernel under test and the reference machine it
 * is compared with. Never install it on a production system.
 *
 * NKC_IOCTL_RUN works as in every conformance driver and returns an
 * empty list: this driver logs into nkc-cross's.
 *
 * Of the undocumented routines in nkc-undoc.h this driver uses the one
 * the compiler calls: __C_specific_handler.
 */

#define NKC_DEVICE L"\\Device\\NkcCrossB"
#define NKC_IRP_CONTROL
#include "nkc.h"
#include "nkc-cross.h"

/* Always zero, and the compiler cannot know it: the raises below are not
 * known never to return. */
static volatile ULONG NkcZero;

static DECLSPEC_NOINLINE VOID NkcRaise(NTSTATUS Status)
{
    if (NkcZero == 0) {
        ExRaiseStatus(Status);
    }
}

/* B2, then the raise; B3 and 1 when the unwind passes: this __finally
 * runs as an abnormal termination. */
static DECLSPEC_NOINLINE NTSTATUS NkcFinallyRaise(NKC_LOG *Log, PIRP Irp)
{
    __try {
        MARK(0xB2);
        NkcRaise(NKC_STATUS(0x32));
        MARK(0xE8);
    } __finally {
        MARK(0xB3);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
    return NkcComplete(Irp, NKC_SURVIVED, 0);
}

/* B4, then IoCompleteRequest, which calls the sender's completion
 * routine; that routine raises, so B5 is not reached, and B6 and 1 are
 * logged when the unwind passes. */
static DECLSPEC_NOINLINE NTSTATUS NkcFinallyComplete(NKC_LOG *Log, PIRP Irp)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    __try {
        MARK(0xB4);
        Status = NkcComplete(Irp, STATUS_SUCCESS, 0);
        MARK(0xB5);
    } __finally {
        MARK(0xB6);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
    return Status;
}

static NTSTATUS NkcIrpControl(PIRP Irp, ULONG Code)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NKC_CROSS *Cross;
    NKC_LOG *Log;

    /* The request carries a kernel address, as it is (METHOD_NEITHER).
     * User mode may not name one: its request is refused here, with the
     * address not yet read out of the stack location, let alone
     * followed. Nothing above this line touches it. */
    if (Irp->RequestorMode != KernelMode) {
        return NkcComplete(Irp, STATUS_ACCESS_DENIED, 0);
    }
    /* A kernel caller is trusted to pass an address it can read; that
     * it is nkc-cross is told by the block's first field, which is
     * checked before the block's pointer is used. */
    Cross = (NKC_CROSS *)Stack->Parameters.DeviceIoControl.Type3InputBuffer;
    if (Cross == NULL || Cross->Magic != NKC_CROSS_MAGIC || Cross->Log == NULL) {
        return NkcComplete(Irp, STATUS_INVALID_PARAMETER, 0);
    }
    Log = Cross->Log;

    switch (Code) {
    case NKC_CROSS_QUIET:
        MARK(0xB0);
        return NkcComplete(Irp, STATUS_SUCCESS, 0);

    case NKC_CROSS_RAISE:
        MARK(0xB1);
        NkcRaise(NKC_STATUS(0x31));
        MARK(0xE9);
        return NkcComplete(Irp, NKC_SURVIVED, 0);

    case NKC_CROSS_FINALLY:
        return NkcFinallyRaise(Log, Irp);

    case NKC_CROSS_COMPLETE:
        return NkcFinallyComplete(Log, Irp);

    default:
        return NkcComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
}

/* Nothing to log. */
static VOID NkcRun(NKC_LOG *Log)
{
    UNREFERENCED_PARAMETER(Log);
}
