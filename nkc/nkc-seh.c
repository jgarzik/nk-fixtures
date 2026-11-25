/*
 * Conformance: structured exception handling, as a driver sees it.
 *
 * In what order filters, __finally blocks and handlers run; what a filter
 * is shown; what unwinding does to code that leaves a __try early; which
 * exceptions the kernel's own routines raise; and which memory faults
 * become exceptions.
 *
 * The list is made of marks and facts. A mark is NKC_MARK | n and says
 * "execution reached point n"; the marks in the list, in order, are the
 * order things ran in. Marks from 0xE0 up are points that must not be
 * reached. A filter logs four values: its mark, then the exception's
 * code, flags and number of parameters. An exception's address, and the
 * registers, are never logged.
 *
 * So that the compiler cannot work out what a __try will do and fold it
 * away: every raise goes through a routine that is never inlined and
 * that tests a volatile variable first (so it is not known never to
 * return), every function with a __try is itself never inlined, and
 * every constant that decides a path is mixed with that volatile zero.
 *
 * Of the undocumented routines in nkc-undoc.h this driver uses the two
 * the compiler calls: __C_specific_handler and _local_unwind.
 *
 * Left out on purpose: integer division by zero (MSVC for arm64 compiles
 * its own check and a breakpoint instruction, so what reaches the kernel
 * differs by architecture), floating-point registers, and continuing
 * execution from a filter (it needs an exception that can be continued,
 * which no documented routine raises, or a fault repaired by changing a
 * volatile register).
 */

#define NKC_DEVICE L"\\Device\\NkcSeh"
#include "nkc.h"

#define NKC_MARK 0x5E000000u
#define MARK(n) NkcPut(Log, NKC_MARK | (n))

/* Statuses of the driver's own, so that nothing else can have raised them. */
#define NKC_STATUS(n) ((NTSTATUS)(0xE04E4B00u | (n)))

/* Always zero, and the compiler cannot know it. */
static volatile ULONG NkcZero;

/* Raise `Status`. */
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

/* One scope: the body, the filter, the handler, and on after it.
 * 01; filter 02: E04E4B01, 1 (EXCEPTION_NONCONTINUABLE), 0; 03, with
 * GetExceptionCode() E04E4B01 and the IRQL the body ran at; 04. */
static DECLSPEC_NOINLINE VOID NkcOne(NKC_LOG *Log)
{
    __try {
        MARK(0x01);
        NkcRaise(NKC_STATUS(1));
        MARK(0xE1);
    } __except (NkcFilter(Log, 0x02, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x03);
        NkcPut(Log, (ULONG)GetExceptionCode());
        NkcPut(Log, KeGetCurrentIrql());
    }
    MARK(0x04);

    /* 05, 06, E04E4B02: a constant filter has no code to run; the
     * handler still knows the exception's code. */
    __try {
        MARK(0x05);
        NkcRaise(NKC_STATUS(2));
        MARK(0xE2);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        MARK(0x06);
        NkcPut(Log, (ULONG)GetExceptionCode());
    }

    /* 07, 08, 0: a __finally entered by falling off the end of its __try
     * is not an abnormal termination. */
    __try {
        MARK(0x07);
    } __finally {
        MARK(0x08);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
}

/* Three calls deep. The innermost function has a scope that finished
 * before the raise and takes no part, and a __finally. */
static DECLSPEC_NOINLINE VOID NkcDepth3(NKC_LOG *Log)
{
    __try {
        MARK(0x31);
    } __except (NkcFilter(Log, 0xE3, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0xE4);
    }
    __try {
        MARK(0x32);
        NkcRaise(NKC_STATUS(3));
        MARK(0xE5);
    } __finally {
        MARK(0x33);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
    MARK(0xE6);
}

/* The middle one declines the exception, and has a __finally around that. */
static DECLSPEC_NOINLINE VOID NkcDepth2(NKC_LOG *Log)
{
    __try {
        __try {
            MARK(0x21);
            NkcDepth3(Log);
            MARK(0xE7);
        } __except (NkcFilter(Log, 0x22, GetExceptionInformation(), EXCEPTION_CONTINUE_SEARCH)) {
            MARK(0xE8);
        }
        MARK(0xE9);
    } __finally {
        MARK(0x23);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
}

/* The outermost takes it.
 * 11, 21, 31, 32: down to the raise.
 * filter 22 (E04E4B03, 1, 0), filter 12 (the same): every filter is
 * asked, innermost first, before anything is unwound.
 * 33, 1, 23, 1: then the __finally blocks run, innermost first, each an
 * abnormal termination.
 * 13, E04E4B03, 14: then the handler, and on after it. */
static DECLSPEC_NOINLINE VOID NkcDepth1(NKC_LOG *Log)
{
    __try {
        MARK(0x11);
        NkcDepth2(Log);
        MARK(0xEA);
    } __except (NkcFilter(Log, 0x12, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x13);
        NkcPut(Log, (ULONG)GetExceptionCode());
    }
    MARK(0x14);
}

/* Scopes side by side and one inside another, in a single function. */
static DECLSPEC_NOINLINE VOID NkcScopes(NKC_LOG *Log)
{
    /* 41, filter 42 (E04E4B04, 1, 0), 43; 44, filter 45 (E04E4B05, 1, 0),
     * 46: each of two scopes in a row sees only its own exception. */
    __try {
        MARK(0x41);
        NkcRaise(NKC_STATUS(4));
        MARK(0xEB);
    } __except (NkcFilter(Log, 0x42, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x43);
    }
    __try {
        MARK(0x44);
        NkcRaise(NKC_STATUS(5));
        MARK(0xEC);
    } __except (NkcFilter(Log, 0x45, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x46);
    }

    /* 47, filter 48 (E04E4B06, 1, 0), filter 49 (the same), 4A, 1, 4B,
     * E04E4B06: the inner scope declines, the outer accepts, the
     * __finally between the raise and the handler runs before the
     * handler. */
    __try {
        __try {
            __try {
                MARK(0x47);
                NkcRaise(NKC_STATUS(6));
                MARK(0xED);
            } __finally {
                MARK(0x4A);
                NkcPut(Log, AbnormalTermination() ? 1 : 0);
            }
        } __except (NkcFilter(Log, 0x48, GetExceptionInformation(), EXCEPTION_CONTINUE_SEARCH)) {
            MARK(0xEE);
        }
    } __except (NkcFilter(Log, 0x49, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x4B);
        NkcPut(Log, (ULONG)GetExceptionCode());
    }
}

/* Leave a __try by return. */
static DECLSPEC_NOINLINE ULONG NkcReturnOut(NKC_LOG *Log)
{
    __try {
        MARK(0x57);
        if (NkcZero == 0) {
            return 0x59;
        }
        MARK(0xF1);
    } __finally {
        MARK(0x58);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
    return 0xF2;
}

/* Leaving a __try without an exception. */
static DECLSPEC_NOINLINE VOID NkcLeave(NKC_LOG *Log)
{
    /* 51, 52, 0, 53: __leave goes to the end of the __try; the
     * __finally runs, and it is not an abnormal termination. */
    __try {
        MARK(0x51);
        if (NkcZero == 0) {
            __leave;
        }
        MARK(0xEF);
    } __finally {
        MARK(0x52);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
    MARK(0x53);

    /* 54, 55, 1, 56, 1, 5A: goto out of two __try blocks runs both
     * __finally blocks, inner first, each an abnormal termination, and
     * then arrives. */
    __try {
        __try {
            MARK(0x54);
            if (NkcZero == 0) {
                goto Out;
            }
            MARK(0xF0);
        } __finally {
            MARK(0x55);
            NkcPut(Log, AbnormalTermination() ? 1 : 0);
        }
    } __finally {
        MARK(0x56);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
    MARK(0xF3);
Out:
    MARK(0x5A);

    /* 57, 58, 1, then 59: return out of a __try runs the __finally, an
     * abnormal termination, before the caller has the value. */
    NkcPut(Log, NkcReturnOut(Log));
}

static DECLSPEC_NOINLINE VOID NkcCollideInner(NKC_LOG *Log)
{
    __try {
        __try {
            MARK(0x61);
            NkcRaise(NKC_STATUS(7));
            MARK(0xF4);
        } __finally {
            MARK(0x62);
            NkcPut(Log, AbnormalTermination() ? 1 : 0);
            NkcRaise(NKC_STATUS(8));
            MARK(0xF5);
        }
    } __finally {
        MARK(0x63);
        NkcPut(Log, AbnormalTermination() ? 1 : 0);
    }
}

/* A raise inside a __finally that is running because of an unwind.
 * 61; filter 64 (E04E4B07, 1, 0) accepts the first exception; 62, 1: the
 * unwind runs the inner __finally, which raises the second;
 * filter 64 again, now E04E4B08: the second is offered to the same
 * scope, and accepted;
 * 63, 1: its unwind takes over where the first one stopped: the inner
 * __finally does not run again, the outer one runs once;
 * 65, E04E4B08, 66: the handler has the second exception; the first is
 * gone. */
static DECLSPEC_NOINLINE VOID NkcCollide(NKC_LOG *Log)
{
    __try {
        NkcCollideInner(Log);
        MARK(0xF6);
    } __except (NkcFilter(Log, 0x64, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x65);
        NkcPut(Log, (ULONG)GetExceptionCode());
    }
    MARK(0x66);
}

/* A filter that raises the first time it is asked, and declines after. */
static DECLSPEC_NOINLINE LONG NkcRaisingFilter(NKC_LOG *Log, ULONG *Asked,
                                               PEXCEPTION_POINTERS Info)
{
    NkcFilter(Log, 0x71, Info, 0);
    *Asked += 1;
    if (*Asked == 1) {
        NkcRaise(NKC_STATUS(10));
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DECLSPEC_NOINLINE VOID NkcNestInner(NKC_LOG *Log)
{
    ULONG Asked = 0;

    __try {
        NkcRaise(NKC_STATUS(9));
        MARK(0xF7);
    } __except (NkcRaisingFilter(Log, &Asked, GetExceptionInformation())) {
        MARK(0xF8);
    }
    MARK(0xF9);
}

/* A raise inside a filter.
 * filter 71 (E04E4B09, 1, 0): asked about the first exception, it raises
 * the second;
 * filter 71 again (E04E4B0A, and flags that say this is a nested call:
 * 0x11 is a guess): the search for the second passes the same scope,
 * since the first raise is still on the stack inside it;
 * filter 72 (E04E4B0A; flags 1 is a guess): the outer scope accepts;
 * 73, E04E4B0A, 74. */
static DECLSPEC_NOINLINE VOID NkcNest(NKC_LOG *Log)
{
    __try {
        NkcNestInner(Log);
        MARK(0xFA);
    } __except (NkcFilter(Log, 0x72, GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        MARK(0x73);
        NkcPut(Log, (ULONG)GetExceptionCode());
    }
    MARK(0x74);
}

/* Give back `Value`, in a way the compiler cannot see through. */
static DECLSPEC_NOINLINE ULONG NkcSame(ULONG Value)
{
    return Value + NkcZero;
}

/* Keep eight values busy across calls, so that they live in registers a
 * call preserves and this function has to save the caller's; then raise,
 * or not. */
static DECLSPEC_NOINLINE VOID NkcChurn(ULONG Seed, BOOLEAN Raise)
{
    ULONG A = Seed, B = Seed ^ 0x11111111, C = Seed + 0x2222, D = ~Seed;
    ULONG E = Seed * 5, F = Seed ^ 0x66666666, G = Seed + 0x7777, H = Seed * 9;
    ULONG I;

    for (I = 0; I < 4; I++) {
        A += NkcSame(B);
        B ^= NkcSame(C + I);
        C += NkcSame(D);
        D ^= NkcSame(E);
        E += NkcSame(F);
        F ^= NkcSame(G);
        G += NkcSame(H);
        H ^= NkcSame(A);
    }
    if (Raise) {
        NkcRaise(NKC_STATUS(11));
    }
    NkcSame(A ^ B ^ C ^ D ^ E ^ F ^ G ^ H);
}

/* Compute a checksum over eight values that are live across a __try in
 * which a callee, which reused their registers, may raise. */
static DECLSPEC_NOINLINE ULONG NkcKeep(ULONG Seed, BOOLEAN Raise)
{
    ULONG A = Seed, B = Seed * 3, C = Seed ^ 0x5A5A5A5A, D = Seed + 0x1234;
    ULONG E = ~Seed, F = Seed * 7, G = Seed ^ 0x0F0F0F0F, H = Seed + 0x4321;
    ULONG I;

    for (I = 0; I < 4; I++) {
        A += NkcSame(B ^ I);
        B ^= NkcSame(C);
        C += NkcSame(D);
        D ^= NkcSame(E);
        E += NkcSame(F);
        F ^= NkcSame(G);
        G += NkcSame(H);
        H ^= NkcSame(A);
    }
    __try {
        NkcChurn(NkcSame(Seed), Raise);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    for (I = 0; I < 4; I++) {
        A ^= NkcSame(H + I);
        B += NkcSame(A);
        C ^= NkcSame(B);
        D += NkcSame(C);
        E ^= NkcSame(D);
        F += NkcSame(E);
        G ^= NkcSame(F);
        H += NkcSame(G);
    }
    return A ^ B ^ C ^ D ^ E ^ F ^ G ^ H;
}

/* Have the kernel raise, and log what the filter is shown and what the
 * handler reads. */
static DECLSPEC_NOINLINE VOID NkcKernelRaises(NKC_LOG *Log, ULONG Kind)
{
    __try {
        switch (Kind + NkcZero) {
        case 0:
            ExRaiseStatus(STATUS_INVALID_PARAMETER);
            break;
        case 1:
            ExRaiseStatus(STATUS_BUFFER_OVERFLOW);
            break;
        case 2:
            ExRaiseStatus(STATUS_PENDING);
            break;
        case 3:
            ExRaiseAccessViolation();
            break;
        default:
            ExRaiseDatatypeMisalignment();
            break;
        }
        MARK(0xFB);
    } __except (NkcFilter(Log, 0x80 + Kind, GetExceptionInformation(),
                          EXCEPTION_EXECUTE_HANDLER)) {
        NkcPut(Log, (ULONG)GetExceptionCode());
    }
}

/* Everything above: exceptions raised by calling a routine. */
static DECLSPEC_NOINLINE VOID NkcSoftware(NKC_LOG *Log)
{
    ULONG Kind;

    NkcOne(Log);
    NkcDepth1(Log);
    NkcScopes(Log);
    NkcLeave(Log);
    NkcCollide(Log);
    NkcNest(Log);

    /* 1: the eight values come to the same checksum whether or not the
     * callee raised, so catching the exception put every register a call
     * preserves back as this function had it. */
    NkcPut(Log, NkcKeep(NkcSame(0x4E4B0001), (BOOLEAN)(NkcZero != 0)) ==
                    NkcKeep(NkcSame(0x4E4B0001), (BOOLEAN)(NkcZero == 0))
                    ? 1 : 0);

    /* Each: filter 80+n (code, flags, parameters), then the handler's
     * code again. ExRaiseStatus raises exactly the status it is given,
     * whatever its severity: C000000D, 80000005, 00000103.
     * ExRaiseAccessViolation: C0000005, with no parameters (unlike a
     * fault). ExRaiseDatatypeMisalignment: 80000002. Flags 1 throughout. */
    for (Kind = 0; Kind < 5; Kind++) {
        NkcKernelRaises(Log, Kind);
    }
}

typedef struct _NKC_SEEN {
    ULONG Code;       /* 0 if nothing was raised */
    ULONG Flags;
    ULONG Parameters; /* how many ExceptionInformation entries */
    ULONG Access;     /* the first: 0 for a read, 1 for a write */
    ULONG Address;    /* the second: where, low 32 bits */
} NKC_SEEN;

static DECLSPEC_NOINLINE LONG NkcSee(NKC_SEEN *Seen, PEXCEPTION_POINTERS Info)
{
    PEXCEPTION_RECORD Record = Info->ExceptionRecord;

    Seen->Code = (ULONG)Record->ExceptionCode;
    Seen->Flags = Record->ExceptionFlags;
    Seen->Parameters = Record->NumberParameters;
    if (Record->NumberParameters >= 2) {
        Seen->Access = (ULONG)Record->ExceptionInformation[0];
        Seen->Address = (ULONG)Record->ExceptionInformation[1];
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

/* Probe a range and log two values: the exception's code, or 0 if the
 * probe returned, and its number of parameters (0 when a routine raised
 * it, 2 when it is a memory fault). */
static DECLSPEC_NOINLINE VOID NkcProbe(NKC_LOG *Log, BOOLEAN Write, ULONG_PTR Address,
                                       SIZE_T Length, ULONG Alignment)
{
    NKC_SEEN Seen;

    RtlZeroMemory(&Seen, sizeof(Seen));
    __try {
        if (Write) {
            ProbeForWrite((PVOID)(Address + NkcZero), Length, Alignment);
        } else {
            ProbeForRead((PVOID)(Address + NkcZero), Length, Alignment);
        }
    } __except (NkcSee(&Seen, GetExceptionInformation())) {
    }
    NkcPut(Log, Seen.Code);
    NkcPut(Log, Seen.Parameters);
}

/* Addresses in the first 64 KiB, which no process has mapped. */
#define NKC_LOW_UNMAPPED ((ULONG_PTR)0x8000)
/* Not a multiple of 4. */
#define NKC_LOW_ODD ((ULONG_PTR)0x8001)

static DECLSPEC_NOINLINE VOID NkcProbes(NKC_LOG *Log)
{
    ULONG Local = 0;
    ULONG_PTR Kernel = (ULONG_PTR)&Local;
    ULONG_PTR Limit = (ULONG_PTR)MM_USER_PROBE_ADDRESS;

    /* Reading.
     * C0000005, 0: a kernel address is refused, by a raise, not a fault.
     * 80000002, 0: a misaligned one, with another status;
     * 80000002, 0: and alignment is looked at first (a guess);
     * 0, 0; 0, 0: nothing is checked when the length is zero.
     * 0, 0: a user address passes without being touched: nothing is
     * mapped there.
     * 0, 0: a range may end exactly at the limit;
     * C0000005, 0: but not one byte past it;
     * C0000005, 0: nor start at it. */
    NkcProbe(Log, FALSE, Kernel, sizeof(Local), 1);
    NkcProbe(Log, FALSE, NKC_LOW_ODD, 4, 4);
    NkcProbe(Log, FALSE, Kernel + 1, 4, 4);
    NkcProbe(Log, FALSE, Kernel, 0, 1);
    NkcProbe(Log, FALSE, NKC_LOW_ODD, 0, 4);
    NkcProbe(Log, FALSE, NKC_LOW_UNMAPPED, 16, 4);
    NkcProbe(Log, FALSE, Limit - 16, 16, 1);
    NkcProbe(Log, FALSE, Limit - 16, 17, 1);
    NkcProbe(Log, FALSE, Limit, 1, 1);

    /* Writing.
     * C0000005, 0; 80000002, 0; 0, 0; C0000005, 0: the same checks.
     * C0000005, 2: a probe for writing touches the range, and here that
     * is a fault (a guess: the status is certain, the 2 says it came
     * from the fault and not from a raise). */
    NkcProbe(Log, TRUE, Kernel, sizeof(Local), 1);
    NkcProbe(Log, TRUE, NKC_LOW_ODD, 4, 4);
    NkcProbe(Log, TRUE, Kernel, 0, 1);
    NkcProbe(Log, TRUE, Limit - 16, 17, 1);
    NkcProbe(Log, TRUE, NKC_LOW_UNMAPPED, 4, 4);
}

/* Read or write four bytes at `Address` inside a __try and log five
 * values: code, flags, number of parameters, which access it was, and
 * the low half of the address the fault reports. */
static DECLSPEC_NOINLINE VOID NkcTouch(NKC_LOG *Log, ULONG_PTR Address, BOOLEAN Write)
{
    volatile ULONG *Where = (volatile ULONG *)(Address + NkcZero);
    NKC_SEEN Seen;

    RtlZeroMemory(&Seen, sizeof(Seen));
    __try {
        if (Write) {
            *Where = 0x4E4B;
        } else {
            NkcSame(*Where);
        }
        Seen.Code = 0xFFFFFFFF; /* it was mapped: not what this test assumes */
    } __except (NkcSee(&Seen, GetExceptionInformation())) {
    }
    NkcPut(Log, Seen.Code);
    NkcPut(Log, Seen.Flags);
    NkcPut(Log, Seen.Parameters);
    NkcPut(Log, Seen.Access);
    NkcPut(Log, Seen.Address);
}

static VOID NkcRun(NKC_LOG *Log)
{
    FAST_MUTEX Fast;

    /* At PASSIVE_LEVEL. */
    NkcSoftware(Log);
    NkcProbes(Log);

    /* Memory faults below the user limit become exceptions a __try
     * catches. Each: C0000005, flags 0 (it can be continued), 2
     * parameters, the access, the address.
     * 0, 0: reading through a null pointer;
     * 1, 0: writing through one;
     * 0, 0x8000: reading an unmapped address. */
    NkcTouch(Log, 0, FALSE);
    NkcTouch(Log, 0, TRUE);
    NkcTouch(Log, NKC_LOW_UNMAPPED, FALSE);

    /* 1: holding a fast mutex, at APC_LEVEL.
     * Then the whole of NkcSoftware again, the same but for the IRQL the
     * first handler logs.
     * 1: every handler resumed at the IRQL of its __try.
     * 0: released, back at PASSIVE_LEVEL. */
    ExInitializeFastMutex(&Fast);
    ExAcquireFastMutex(&Fast);
    NkcPut(Log, KeGetCurrentIrql());
    NkcSoftware(Log);
    NkcPut(Log, KeGetCurrentIrql());
    ExReleaseFastMutex(&Fast);
    NkcPut(Log, KeGetCurrentIrql());
}
