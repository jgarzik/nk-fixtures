/*
 * NK conformance drivers nkc-cross and nkc-cross-b: what the two share.
 *
 * nkc-cross sends nkc-cross-b requests of its own making with
 * IoCallDriver. Each request's control code tells nkc-cross-b what to do
 * in its dispatch routine, and its Type3InputBuffer is the address of an
 * NKC_CROSS, through which nkc-cross-b logs into the list nkc-cross is
 * filling: both are kernel drivers, and the request is kernel mode's.
 * The block begins with NKC_CROSS_MAGIC, by which nkc-cross-b knows a
 * request of nkc-cross's from any other kernel caller's.
 *
 * A test fixture: for a kernel under test and the reference machine it
 * is compared with. Never install it on a production system.
 *
 * This file is NK's, not Microsoft's.
 */

#pragma once

#define NKC_CROSS_DEVICE_B L"\\Device\\NkcCrossB"

/* METHOD_NEITHER: the I/O manager passes Type3InputBuffer on as it is. */
#define NKC_CROSS(n) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900 + (n), METHOD_NEITHER, FILE_ANY_ACCESS)

/* Complete the request with STATUS_SUCCESS. */
#define NKC_CROSS_QUIET NKC_CROSS(0)
/* Raise NKC_STATUS(0x31) in the dispatch routine, completing nothing. */
#define NKC_CROSS_RAISE NKC_CROSS(1)
/* Raise NKC_STATUS(0x32) inside a __try with a __finally. */
#define NKC_CROSS_FINALLY NKC_CROSS(2)
/* Complete the request with STATUS_SUCCESS inside a __try with a
 * __finally; the sender's completion routine raises. */
#define NKC_CROSS_COMPLETE NKC_CROSS(3)

/* Statuses of the drivers' own, so that nothing else can have raised
 * them. */
#define NKC_STATUS(n) ((NTSTATUS)(0xE04E4B00u | (n)))
/* A request completes with this if a raise returned. */
#define NKC_SURVIVED NKC_STATUS(0xF0)

/* A mark says "execution reached point n"; the marks in the list, in
 * order, are the order things ran in. nkc-cross's marks are below 0xB0,
 * nkc-cross-b's from 0xB0 up; marks from 0xE0 up are points that must
 * not be reached. */
#define NKC_MARK 0x5E000000u
#define MARK(n) NkcPut(Log, NKC_MARK | (n))

/* "NKCX": the first field of every block nkc-cross sends. */
#define NKC_CROSS_MAGIC 0x58434B4Eu

typedef struct _NKC_CROSS {
    ULONG Magic;
    NKC_LOG *Log;
} NKC_CROSS;
