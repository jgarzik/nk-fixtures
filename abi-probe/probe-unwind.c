/*
 * ABI probe, second table: the structures the unwinder and a language
 * handler (__C_specific_handler, a driver's __GSHandlerCheck) share.
 *
 * Microsoft's kernel headers only forward-declare DISPATCHER_CONTEXT and
 * do not define the function-table and scope-table records at all; a
 * driver's compiler-generated handlers read them all the same. They are
 * defined in <winnt.h>, which cannot be included together with
 * <ntifs.h>, so this file includes <windef.h> alone and keeps a table of
 * its own. It is compiled by the WDK with the driver's settings.
 */

#include <windef.h>
#include "probe.h"

#pragma comment(linker, "/include:NkAbiUnwindTable")

const NKABI_ENTRY NkAbiUnwindTable[] = {
    NKABI_BEGIN,

    /* One entry of an image's function table (.pdata). */
    SZ(RUNTIME_FUNCTION)
    OFF(RUNTIME_FUNCTION, BeginAddress)
    OFF(RUNTIME_FUNCTION, UnwindData)
#if defined(_M_AMD64)
    OFF(RUNTIME_FUNCTION, EndAddress)
    { "const UNW_FLAG_NHANDLER", UNW_FLAG_NHANDLER },
    { "const UNW_FLAG_EHANDLER", UNW_FLAG_EHANDLER },
    { "const UNW_FLAG_UHANDLER", UNW_FLAG_UHANDLER },
    { "const UNW_FLAG_CHAININFO", UNW_FLAG_CHAININFO },
#endif

    /* The scope table __C_specific_handler is given as handler data: a
     * count, then records. ScopeRecord[1] is the size of one record. */
    SZ(SCOPE_TABLE)
    OFF(SCOPE_TABLE, Count)
    OFF(SCOPE_TABLE, ScopeRecord)
    OFF(SCOPE_TABLE, ScopeRecord[0].BeginAddress)
    OFF(SCOPE_TABLE, ScopeRecord[0].EndAddress)
    OFF(SCOPE_TABLE, ScopeRecord[0].HandlerAddress)
    OFF(SCOPE_TABLE, ScopeRecord[0].JumpTarget)
    OFF(SCOPE_TABLE, ScopeRecord[1])

    /* What a language handler is given as its fourth argument. */
    SZ(DISPATCHER_CONTEXT)
    OFF(DISPATCHER_CONTEXT, ControlPc)
    OFF(DISPATCHER_CONTEXT, ImageBase)
    OFF(DISPATCHER_CONTEXT, FunctionEntry)
    OFF(DISPATCHER_CONTEXT, EstablisherFrame)
    OFF(DISPATCHER_CONTEXT, ContextRecord)
    OFF(DISPATCHER_CONTEXT, LanguageHandler)
    OFF(DISPATCHER_CONTEXT, HandlerData)
    OFF(DISPATCHER_CONTEXT, HistoryTable)
    OFF(DISPATCHER_CONTEXT, ScopeIndex)
#if defined(_M_AMD64)
    OFF(DISPATCHER_CONTEXT, TargetIp)
    OFF(DISPATCHER_CONTEXT, Fill0)
#elif defined(_M_ARM64)
    OFF(DISPATCHER_CONTEXT, TargetPc)
    OFF(DISPATCHER_CONTEXT, ControlPcIsUnwound)
    OFF(DISPATCHER_CONTEXT, NonVolatileRegisters)
    /* What NonVolatileRegisters points at: x19-x28 and fp, then d8-d15. */
    SZ(DISPATCHER_CONTEXT_NONVOLREG_ARM64)
    OFF(DISPATCHER_CONTEXT_NONVOLREG_ARM64, GpNvRegs)
    OFF(DISPATCHER_CONTEXT_NONVOLREG_ARM64, FpNvRegs)
#endif

    /* The cache of function-table look-ups a dispatcher context points at. */
    SZ(UNWIND_HISTORY_TABLE_ENTRY)
    OFF(UNWIND_HISTORY_TABLE_ENTRY, ImageBase)
    OFF(UNWIND_HISTORY_TABLE_ENTRY, FunctionEntry)
    SZ(UNWIND_HISTORY_TABLE)
    OFF(UNWIND_HISTORY_TABLE, Count)
    OFF(UNWIND_HISTORY_TABLE, LocalHint)
    OFF(UNWIND_HISTORY_TABLE, GlobalHint)
    OFF(UNWIND_HISTORY_TABLE, Search)
    OFF(UNWIND_HISTORY_TABLE, Once)
    OFF(UNWIND_HISTORY_TABLE, LowAddress)
    OFF(UNWIND_HISTORY_TABLE, HighAddress)
    OFF(UNWIND_HISTORY_TABLE, Entry)
    { "const UNWIND_HISTORY_TABLE_SIZE", UNWIND_HISTORY_TABLE_SIZE },

    /* Where a virtual unwind found each non-volatile register saved. */
    SZ(KNONVOLATILE_CONTEXT_POINTERS)
#if defined(_M_AMD64)
    OFF(KNONVOLATILE_CONTEXT_POINTERS, FloatingContext)
    OFF(KNONVOLATILE_CONTEXT_POINTERS, IntegerContext)
#elif defined(_M_ARM64)
    OFF(KNONVOLATILE_CONTEXT_POINTERS, X19)
    OFF(KNONVOLATILE_CONTEXT_POINTERS, Fp)
    OFF(KNONVOLATILE_CONTEXT_POINTERS, Lr)
    OFF(KNONVOLATILE_CONTEXT_POINTERS, D8)
#endif

    /* The two files must agree on these; a kernel can check that they do. */
    { "sizeof winnt CONTEXT", sizeof(CONTEXT) },
    { "sizeof winnt EXCEPTION_RECORD", sizeof(EXCEPTION_RECORD) },

    NKABI_END,
};
