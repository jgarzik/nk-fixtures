/*
 * Conformance: an export driver, the importing half.
 *
 * This driver's import table names nkc-lib.sys, so loading it loads the
 * library first. It imports everything the library exports and logs
 * what each import turns out to be.
 */

#define NKC_DEVICE L"\\Device\\NkcLibUser"
#include "nkc.h"
#include "nkc-lib.h"

static VOID NkcRun(NKC_LOG *Log)
{
    ULONG Old;

    /* 5: a function imported by name is the library's. */
    NkcPut(Log, NkcLibAdd(2, 3));

    /* 0x4F524437: so is one imported by ordinal alone. */
    NkcPut(Log, NkcLibByOrdinal());

    /* 0x44415441: an imported variable reads as the library set it up. */
    NkcPut(Log, NkcLibValue);

    /* 0x44415441, 0x4E4B0001: the library changes it, and returns what
     * was there; this driver sees the change, so both mean one variable. */
    Old = NkcLibSetValue(0x4E4B0001);
    NkcPut(Log, Old);
    NkcPut(Log, NkcLibValue);

    /* 0x4E4B0002, 0x44415441: and the library sees what this driver
     * writes. The variable is left as it was found. */
    NkcLibValue = 0x4E4B0002;
    NkcPut(Log, NkcLibSetValue(Old));
    NkcPut(Log, NkcLibValue);

    /* 1: the system has called the library's DllInitialize once, and
     * neither its DllUnload nor its entry point. */
    NkcPut(Log, NkcLibCounts());

    /* 0: at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
