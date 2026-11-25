/*
 * Conformance: a driver that must not load.
 *
 * Its import table asks nkc-lib.sys for NkcLibAbsent, which that library
 * does not export (nkc-libbad.def, a module definition written for this
 * purpose alone, says it does). A loader has to refuse the driver, and a
 * careful one names the library and the symbol. Nothing below runs.
 */

#define NKC_DEVICE L"\\Device\\NkcLibBad"
#include "nkc.h"
#include "nkc-lib.h"

DECLSPEC_IMPORT ULONG NkcLibAbsent(VOID);

static VOID NkcRun(NKC_LOG *Log)
{
    /* Never logged: 3, then whatever the missing routine would return. */
    NkcPut(Log, NkcLibAdd(1, 2));
    NkcPut(Log, NkcLibAbsent());
}
