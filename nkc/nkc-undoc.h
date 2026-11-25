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
 *                           a __try; used by nkc-seh, nkc-seh-fatal
 *    _local_unwind          imported by cng.sys, ntfs.sys, fastfat.sys
 *                           runs the __finally blocks a goto or a return
 *                           leaves a __try through; used by nkc-seh
 *
 * 2. Routines a driver calls by name. Prototypes follow.
 *
 *    (none)
 */

#pragma once
