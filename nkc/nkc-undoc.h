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
 * 2. Routines a driver calls by name. Prototypes follow, each with its
 *    entry.
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
 *
 * 3. Exports the kit's headers put a macro over. A driver that uses the
 *    kit's name calls some other routine and never the export, which
 *    Microsoft's own drivers import. The macro is taken off and the
 *    export declared.
 *
 * 4. Routines a driver that ships in Windows does not import but looks
 *    up by name at run time, with MmGetSystemRoutineAddress; a kernel
 *    that runs it is asked for them all the same. Only the type of the
 *    pointer is given: a conformance driver looks them up as well.
 */

#pragma once

/*
 * 2. Called by name.
 */

/* push locks: see above; used by nkc-ex. */
#ifndef EX_DEFAULT_PUSH_LOCK_FLAGS
NTKERNELAPI VOID FASTCALL ExAcquirePushLockExclusiveEx(PULONG_PTR PushLock, ULONG Flags);
NTKERNELAPI VOID FASTCALL ExAcquirePushLockSharedEx(PULONG_PTR PushLock, ULONG Flags);
NTKERNELAPI VOID FASTCALL ExReleasePushLockExclusiveEx(PULONG_PTR PushLock, ULONG Flags);
NTKERNELAPI VOID FASTCALL ExReleasePushLockSharedEx(PULONG_PTR PushLock, ULONG Flags);
#endif
NTKERNELAPI BOOLEAN FASTCALL ExTryAcquirePushLockExclusiveEx(PULONG_PTR PushLock, ULONG Flags);
NTKERNELAPI VOID FASTCALL ExReleasePushLockEx(PULONG_PTR PushLock, ULONG Flags);

/* imported by wpprecorder.sys (and, as NtQuerySystemInformation, by
 * msrpc.sys); used by nkc-etw. The class is a number: the kit's kernel
 * headers do not define SYSTEM_INFORMATION_CLASS. */
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass,
                                                 PVOID SystemInformation,
                                                 ULONG SystemInformationLength,
                                                 PULONG ReturnLength);

/* imported by npfs.sys and msfs.sys; used by nkc-ob. The kernel's shared
 * store of security descriptors: one is logged and a counted copy comes
 * back, the same copy for the same bytes. The descriptor logged is
 * self-relative. */
NTKERNELAPI NTSTATUS NTAPI ObLogSecurityDescriptor(PSECURITY_DESCRIPTOR InputSecurityDescriptor,
                                                   PSECURITY_DESCRIPTOR *OutputSecurityDescriptor,
                                                   ULONG RefBias);
NTKERNELAPI VOID NTAPI ObReferenceSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                     ULONG Count);
NTKERNELAPI VOID NTAPI ObDereferenceSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                       ULONG Count);

/* imported by npfs.sys and msfs.sys; used by nkc-ps. */
NTKERNELAPI ULONG NTAPI PsGetProcessSessionId(PEPROCESS Process);
NTKERNELAPI ULONG NTAPI PsGetThreadSessionId(PETHREAD Thread);

/* imported by msfs.sys; used by nkc-ps. */
NTKERNELAPI NTSTATUS NTAPI PsChargeProcessPagedPoolQuota(PEPROCESS Process, SIZE_T Amount);
NTKERNELAPI VOID NTAPI PsReturnProcessPagedPoolQuota(PEPROCESS Process, SIZE_T Amount);

/* imported by npfs.sys and msfs.sys; used by nkc-se. AuxData is room
 * the caller gives for a structure the kit does not define
 * (AUX_ACCESS_DATA, 0xE0 bytes on these builds); nkc-se gives more. */
NTKERNELAPI NTSTATUS NTAPI SeCreateAccessState(PACCESS_STATE AccessState, PVOID AuxData,
                                               ACCESS_MASK DesiredAccess,
                                               PGENERIC_MAPPING GenericMapping);
NTKERNELAPI VOID NTAPI SeDeleteAccessState(PACCESS_STATE AccessState);

/* imported by msrpc.sys; used by nkc-se. */
NTSYSAPI NTSTATUS NTAPI ZwImpersonateAnonymousToken(HANDLE ThreadHandle);

/*
 * 3. Behind a macro.
 */

/* imported by npfs.sys, msfs.sys; used by nkc-ps. The kit's
 * PsGetCurrentProcess is IoGetCurrentProcess. */
#undef PsGetCurrentProcess
NTKERNELAPI PEPROCESS NTAPI PsGetCurrentProcess(VOID);

/* imported by npfs.sys, msfs.sys; used by nkc-se. The kit's two are
 * ObDereferenceObject. */
#undef PsDereferencePrimaryToken
#undef PsDereferenceImpersonationToken
NTKERNELAPI VOID NTAPI PsDereferencePrimaryToken(PACCESS_TOKEN PrimaryToken);
NTKERNELAPI VOID NTAPI PsDereferenceImpersonationToken(PACCESS_TOKEN ImpersonationToken);

/*
 * 4. Looked up by name.
 */

/* looked up by wpprecorder.sys, and by the tracing start-up the kit
 * compiles into every driver that traces with WPP; used by nkc-etw.
 * A registration made with it is ended with EtwUnregister. */
typedef VOID NTAPI NKC_ETW_CLASSIC_CALLBACK(LPCGUID Guid, UCHAR ControlCode, PVOID EnableContext,
                                            PVOID CallbackContext);
typedef NTSTATUS NTAPI NKC_ETW_REGISTER_CLASSIC_PROVIDER(LPCGUID ProviderGuid, ULONG Type,
                                                         NKC_ETW_CLASSIC_CALLBACK *EnableCallback,
                                                         PVOID CallbackContext,
                                                         PREGHANDLE RegHandle);

/* looked up by wpprecorder.sys; it is what the kit's auxiliary library
 * (AuxKlibQueryModuleInformation) calls; used by nkc-etw. */
typedef NTSTATUS NTAPI NKC_RTL_QUERY_MODULE_INFORMATION(PULONG InformationLength,
                                                        ULONG SizePerModule,
                                                        PVOID InformationBuffer);
