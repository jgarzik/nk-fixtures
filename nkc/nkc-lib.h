/*
 * What nkc-lib.sys exports (nkc-lib.def) to the drivers that import it.
 *
 * This file is NK's, not Microsoft's.
 */

#pragma once

#ifdef NKC_LIB_BUILD
#define NKCLIBAPI
#else
#define NKCLIBAPI DECLSPEC_IMPORT
#endif

#define NKC_LIB_VALUE 0x44415441u   /* what NkcLibValue holds when the library is loaded */
#define NKC_LIB_ORDINAL 0x4F524437u /* what the ordinal-only function returns */

/* Exported by name: A + B. */
NKCLIBAPI ULONG NkcLibAdd(ULONG A, ULONG B);

/* Exported by ordinal 7 only; the library's export table has no name
 * for it. Returns NKC_LIB_ORDINAL. */
NKCLIBAPI ULONG NkcLibByOrdinal(VOID);

/* Exported data. */
NKCLIBAPI extern ULONG NkcLibValue;

/* Exported by name: store `Value` in NkcLibValue, return what was there. */
NKCLIBAPI ULONG NkcLibSetValue(ULONG Value);

/* Exported by name: how often the system has called into the library.
 * Bits 0-7 DllInitialize, bits 8-15 DllUnload, bits 16-23 DriverEntry. */
NKCLIBAPI ULONG NkcLibCounts(VOID);
