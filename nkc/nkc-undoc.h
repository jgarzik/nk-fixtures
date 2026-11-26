/*
 * NK conformance drivers: the marked set of undocumented routines.
 *
 * The rule in nkc.h is "use only documented routines". This file is the
 * one exception to it, and the only place a conformance driver may get a
 * prototype that Microsoft's headers do not give it.
 *
 * A routine belongs here when all of these hold:
 *   - ntoskrnl.exe of Windows 10 (19041-19045) exports it by name;
 *   - the WDK headers do not declare it (a routine they declare is used
 *     through them, never redeclared here);
 *   - a driver that ships in Windows imports it, so a kernel that runs
 *     Microsoft's drivers has to provide it anyway.
 *
 * Each entry names the routine, one inbox driver that imports it, and
 * the conformance drivers that call it. A driver includes this file
 * after nkc.h and says in its own header which entries it uses. Keep the
 * set as small as the drivers need: an entry nothing calls is removed.
 *
 * This file is NK's, not Microsoft's.
 *
 * 1. Routines the compiler calls. No prototype: MSVC emits the reference
 *    itself, so every driver with a __try imports them without naming
 *    them.
 *
 *    __C_specific_handler   imported by npfs.sys, msfs.sys, msrpc.sys
 *                           the language handler of every function with
 *                           a __try; used by nkc-seh, nkc-seh-fatal,
 *                           nkc-cross, nkc-cross-b, nkc-ex
 *    _local_unwind          imported by cng.sys, ntfs.sys, fastfat.sys
 *                           runs the __finally blocks a goto or a return
 *                           leaves a __try through; used by nkc-seh
 *
 * 2. Routines a driver calls by name. Prototypes follow.
 *
 *    Push locks. The lock is one pointer-sized word in the driver's
 *    memory, zero when free; the caller is in a critical region; Flags
 *    is 0 (EX_DEFAULT_PUSH_LOCK_FLAGS).
 *
 *    ExAcquirePushLockExclusiveEx     imported by npfs.sys, msrpc.sys
 *    ExAcquirePushLockSharedEx        imported by npfs.sys, msfs.sys
 *    ExReleasePushLockExclusiveEx     imported by npfs.sys, msrpc.sys
 *    ExReleasePushLockSharedEx        imported by npfs.sys, msfs.sys
 *    ExTryAcquirePushLockExclusiveEx  imported by npfs.sys
 *    ExReleasePushLockEx              imported by msrpc.sys
 *                                     all six used by nkc-ex
 *
 *    A kit that knows push locks defines EX_DEFAULT_PUSH_LOCK_FLAGS in
 *    <wdm.h> and declares the first four there; they are then used
 *    through it. The last two are declared here either way, the lock
 *    typed as the kit types it (a pointer-sized integer), so that a kit
 *    which declares them too sees the same declaration twice.
 */

#pragma once

#ifndef EX_DEFAULT_PUSH_LOCK_FLAGS
NTKERNELAPI VOID FASTCALL ExAcquirePushLockExclusiveEx(PULONG_PTR PushLock, ULONG Flags);
NTKERNELAPI VOID FASTCALL ExAcquirePushLockSharedEx(PULONG_PTR PushLock, ULONG Flags);
NTKERNELAPI VOID FASTCALL ExReleasePushLockExclusiveEx(PULONG_PTR PushLock, ULONG Flags);
NTKERNELAPI VOID FASTCALL ExReleasePushLockSharedEx(PULONG_PTR PushLock, ULONG Flags);
#endif
NTKERNELAPI BOOLEAN FASTCALL ExTryAcquirePushLockExclusiveEx(PULONG_PTR PushLock, ULONG Flags);
NTKERNELAPI VOID FASTCALL ExReleasePushLockEx(PULONG_PTR PushLock, ULONG Flags);
