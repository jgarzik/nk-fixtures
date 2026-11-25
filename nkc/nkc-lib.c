/*
 * Conformance: an export driver, the library half.
 *
 * A kernel-mode library: other drivers import from it by naming it in
 * their import tables, and the system loads it when the first of them
 * loads. It is not started as a driver; the system calls DllInitialize
 * once after loading it and DllUnload before unloading it, when the last
 * importer has gone. See Microsoft's "Creating Export Drivers".
 *
 * It exports a function by name, one by ordinal only, a variable, a
 * function that changes the variable, and a function that reports how
 * often the system called DllInitialize, DllUnload and DriverEntry
 * (nkc-lib.def, nkc-lib.h). nkc-libuser.sys imports all of them and logs
 * what it gets; nkc-libbad.sys asks for one that does not exist.
 *
 * This file is NK's, not Microsoft's. It includes only <ntddk.h>.
 */

#include <ntddk.h>

#define NKC_LIB_BUILD
#include "nkc-lib.h"

ULONG NkcLibValue = NKC_LIB_VALUE;

static volatile LONG NkcLibInitialized;
static volatile LONG NkcLibUnloaded;
static volatile LONG NkcLibEntered;

NTSTATUS DllInitialize(PUNICODE_STRING RegistryPath);
NTSTATUS DllUnload(VOID);
DRIVER_INITIALIZE DriverEntry;

ULONG NkcLibAdd(ULONG A, ULONG B)
{
    return A + B;
}

ULONG NkcLibByOrdinal(VOID)
{
    return NKC_LIB_ORDINAL;
}

ULONG NkcLibSetValue(ULONG Value)
{
    return (ULONG)InterlockedExchange((volatile LONG *)&NkcLibValue, (LONG)Value);
}

ULONG NkcLibCounts(VOID)
{
    return ((ULONG)NkcLibInitialized & 0xFF) | (((ULONG)NkcLibUnloaded & 0xFF) << 8) |
           (((ULONG)NkcLibEntered & 0xFF) << 16);
}

NTSTATUS DllInitialize(PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    InterlockedIncrement(&NkcLibInitialized);
    return STATUS_SUCCESS;
}

/* Returning success lets the system unload the library. */
NTSTATUS DllUnload(VOID)
{
    InterlockedIncrement(&NkcLibUnloaded);
    return STATUS_SUCCESS;
}

/* The image's entry point. The system does not call it for a library; a
 * library started as a service by mistake refuses to stay. */
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(Driver);
    UNREFERENCED_PARAMETER(RegistryPath);
    InterlockedIncrement(&NkcLibEntered);
    return STATUS_NOT_SUPPORTED;
}
