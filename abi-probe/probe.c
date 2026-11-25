/*
 * ABI probe: records what Microsoft's own compiler and WDK headers say
 * about the size and layout of driver-visible kernel structures.
 *
 * This file is NK's, not Microsoft's, but it includes only <ntifs.h>
 * (which brings in <ntddk.h>; the security structures are declared there) and
 * is compiled by the WDK like any driver. The table below ends up as
 * plain data in the image; the fixture pipeline extracts it to a text
 * file. A kernel that claims Windows driver compatibility can then check
 * its own structure definitions against these numbers instead of against
 * its author's reading of the documentation.
 *
 * The driver is never meant to be loaded. DriverEntry exists so the image
 * is a well-formed driver and so the table is referenced.
 *
 * To add a fact, add a SZ() or OFF() line. Names are stable identifiers:
 * "sizeof <type>" and "offsetof <type> <member>". A structure the kernel
 * headers do not define goes in a file of its own with its own table, as
 * probe-unwind.c does; the pipeline reads every table in the image.
 */

#include <ntifs.h>
#include "probe.h"

/* Kept in the image even though nothing reads it at run time. */
#pragma comment(linker, "/include:NkAbiTable")

const NKABI_ENTRY NkAbiTable[] = {
    NKABI_BEGIN,

    SZ(UNICODE_STRING)
    OFF(UNICODE_STRING, MaximumLength)
    OFF(UNICODE_STRING, Buffer)
    SZ(LIST_ENTRY)
    SZ(IO_STATUS_BLOCK)
    OFF(IO_STATUS_BLOCK, Information)
    SZ(DISPATCHER_HEADER)
    OFF(DISPATCHER_HEADER, SignalState)
    OFF(DISPATCHER_HEADER, WaitListHead)
    SZ(KEVENT)
    SZ(KDEVICE_QUEUE)
    SZ(KDPC)
    SZ(WAIT_CONTEXT_BLOCK)
    SZ(KSPIN_LOCK)

    SZ(DRIVER_EXTENSION)
    OFF(DRIVER_EXTENSION, AddDevice)
    OFF(DRIVER_EXTENSION, ServiceKeyName)

    SZ(DRIVER_OBJECT)
    OFF(DRIVER_OBJECT, DeviceObject)
    OFF(DRIVER_OBJECT, Flags)
    OFF(DRIVER_OBJECT, DriverStart)
    OFF(DRIVER_OBJECT, DriverSize)
    OFF(DRIVER_OBJECT, DriverExtension)
    OFF(DRIVER_OBJECT, DriverName)
    OFF(DRIVER_OBJECT, FastIoDispatch)
    OFF(DRIVER_OBJECT, DriverInit)
    OFF(DRIVER_OBJECT, DriverStartIo)
    OFF(DRIVER_OBJECT, DriverUnload)
    OFF(DRIVER_OBJECT, MajorFunction)

    SZ(DEVICE_OBJECT)
    OFF(DEVICE_OBJECT, ReferenceCount)
    OFF(DEVICE_OBJECT, DriverObject)
    OFF(DEVICE_OBJECT, NextDevice)
    OFF(DEVICE_OBJECT, AttachedDevice)
    OFF(DEVICE_OBJECT, CurrentIrp)
    OFF(DEVICE_OBJECT, Flags)
    OFF(DEVICE_OBJECT, Characteristics)
    OFF(DEVICE_OBJECT, DeviceExtension)
    OFF(DEVICE_OBJECT, DeviceType)
    OFF(DEVICE_OBJECT, StackSize)
    OFF(DEVICE_OBJECT, Queue)
    OFF(DEVICE_OBJECT, AlignmentRequirement)
    OFF(DEVICE_OBJECT, DeviceQueue)
    OFF(DEVICE_OBJECT, Dpc)
    OFF(DEVICE_OBJECT, ActiveThreadCount)
    OFF(DEVICE_OBJECT, SecurityDescriptor)
    OFF(DEVICE_OBJECT, DeviceLock)
    OFF(DEVICE_OBJECT, SectorSize)
    OFF(DEVICE_OBJECT, DeviceObjectExtension)
    OFF(DEVICE_OBJECT, Reserved)

    SZ(FILE_OBJECT)
    OFF(FILE_OBJECT, DeviceObject)
    OFF(FILE_OBJECT, FsContext)
    OFF(FILE_OBJECT, PrivateCacheMap)
    OFF(FILE_OBJECT, FinalStatus)
    OFF(FILE_OBJECT, RelatedFileObject)
    OFF(FILE_OBJECT, Flags)
    OFF(FILE_OBJECT, FileName)
    OFF(FILE_OBJECT, CurrentByteOffset)
    OFF(FILE_OBJECT, Lock)
    OFF(FILE_OBJECT, Event)
    OFF(FILE_OBJECT, CompletionContext)
    OFF(FILE_OBJECT, IrpList)
    OFF(FILE_OBJECT, FileObjectExtension)

    SZ(IRP)
    OFF(IRP, MdlAddress)
    OFF(IRP, Flags)
    OFF(IRP, AssociatedIrp)
    OFF(IRP, ThreadListEntry)
    OFF(IRP, IoStatus)
    OFF(IRP, RequestorMode)
    OFF(IRP, PendingReturned)
    OFF(IRP, StackCount)
    OFF(IRP, CurrentLocation)
    OFF(IRP, Cancel)
    OFF(IRP, UserIosb)
    OFF(IRP, UserEvent)
    OFF(IRP, Overlay)
    OFF(IRP, CancelRoutine)
    OFF(IRP, UserBuffer)
    OFF(IRP, Tail)
    OFF(IRP, Tail.Overlay.DriverContext)
    OFF(IRP, Tail.Overlay.Thread)
    OFF(IRP, Tail.Overlay.ListEntry)
    OFF(IRP, Tail.Overlay.CurrentStackLocation)
    OFF(IRP, Tail.Overlay.OriginalFileObject)

    SZ(IO_STACK_LOCATION)
    OFF(IO_STACK_LOCATION, Control)
    OFF(IO_STACK_LOCATION, Parameters)
    OFF(IO_STACK_LOCATION, Parameters.Read.Length)
    OFF(IO_STACK_LOCATION, Parameters.Read.Key)
    OFF(IO_STACK_LOCATION, Parameters.Read.ByteOffset)
    OFF(IO_STACK_LOCATION, Parameters.DeviceIoControl.OutputBufferLength)
    OFF(IO_STACK_LOCATION, Parameters.DeviceIoControl.InputBufferLength)
    OFF(IO_STACK_LOCATION, Parameters.DeviceIoControl.IoControlCode)
    OFF(IO_STACK_LOCATION, Parameters.DeviceIoControl.Type3InputBuffer)
    OFF(IO_STACK_LOCATION, Parameters.Create.SecurityContext)
    OFF(IO_STACK_LOCATION, Parameters.Create.Options)
    OFF(IO_STACK_LOCATION, DeviceObject)
    OFF(IO_STACK_LOCATION, FileObject)
    OFF(IO_STACK_LOCATION, CompletionRoutine)
    OFF(IO_STACK_LOCATION, Context)

    SZ(MDL)
    OFF(MDL, Size)
    OFF(MDL, MdlFlags)
    OFF(MDL, Process)
    OFF(MDL, MappedSystemVa)
    OFF(MDL, StartVa)
    OFF(MDL, ByteCount)
    OFF(MDL, ByteOffset)

    SZ(FAST_IO_DISPATCH)
    SZ(IO_SECURITY_CONTEXT)
    OFF(IO_SECURITY_CONTEXT, DesiredAccess)

    /* Constants the kernel must agree on. */
    { "const IRP_MJ_MAXIMUM_FUNCTION", IRP_MJ_MAXIMUM_FUNCTION },
    { "const DISPATCH_LEVEL", DISPATCH_LEVEL },
    { "const HIGH_LEVEL", HIGH_LEVEL },
    { "const PAGE_SIZE", PAGE_SIZE },
    { "const MEMORY_ALLOCATION_ALIGNMENT", MEMORY_ALLOCATION_ALIGNMENT },
    { "const IO_TYPE_DEVICE", IO_TYPE_DEVICE },
    { "const IO_TYPE_DRIVER", IO_TYPE_DRIVER },
    { "const IO_TYPE_FILE", IO_TYPE_FILE },
    { "const IO_TYPE_IRP", IO_TYPE_IRP },

    /* Security: identifiers, access lists, descriptors, and the table of
     * well-known ones the kernel exports. */
    SZ(SID)
    OFF(SID, SubAuthorityCount)
    OFF(SID, IdentifierAuthority)
    OFF(SID, SubAuthority)
    SZ(ACL)
    OFF(ACL, AclSize)
    OFF(ACL, AceCount)
    SZ(ACE_HEADER)
    OFF(ACE_HEADER, AceSize)
    SZ(ACCESS_ALLOWED_ACE)
    OFF(ACCESS_ALLOWED_ACE, Mask)
    OFF(ACCESS_ALLOWED_ACE, SidStart)
    SZ(SECURITY_DESCRIPTOR)
    OFF(SECURITY_DESCRIPTOR, Control)
    OFF(SECURITY_DESCRIPTOR, Owner)
    OFF(SECURITY_DESCRIPTOR, Group)
    OFF(SECURITY_DESCRIPTOR, Sacl)
    OFF(SECURITY_DESCRIPTOR, Dacl)
    SZ(SECURITY_DESCRIPTOR_RELATIVE)
    OFF(SECURITY_DESCRIPTOR_RELATIVE, Owner)
    OFF(SECURITY_DESCRIPTOR_RELATIVE, Dacl)
    SZ(SE_EXPORTS)
    OFF(SE_EXPORTS, SeNullSid)
    OFF(SE_EXPORTS, SeWorldSid)
    OFF(SE_EXPORTS, SeLocalSystemSid)
    OFF(SE_EXPORTS, SeAliasAdminsSid)
    OFF(SE_EXPORTS, SeAnonymousLogonSid)
    OFF(SE_EXPORTS, SeUndockPrivilege)
    OFF(SE_EXPORTS, SeIUserSid)

    /* Named objects, the registry, cancel-safe queues. */
    SZ(OBJECT_ATTRIBUTES)
    OFF(OBJECT_ATTRIBUTES, ObjectName)
    OFF(OBJECT_ATTRIBUTES, Attributes)
    OFF(OBJECT_ATTRIBUTES, SecurityDescriptor)
    SZ(KEY_VALUE_PARTIAL_INFORMATION)
    OFF(KEY_VALUE_PARTIAL_INFORMATION, Type)
    OFF(KEY_VALUE_PARTIAL_INFORMATION, DataLength)
    OFF(KEY_VALUE_PARTIAL_INFORMATION, Data)
    SZ(IO_CSQ)
    OFF(IO_CSQ, CsqInsertIrp)
    OFF(IO_CSQ, CsqRemoveIrp)
    OFF(IO_CSQ, CsqPeekNextIrp)
    OFF(IO_CSQ, CsqAcquireLock)
    OFF(IO_CSQ, CsqReleaseLock)
    OFF(IO_CSQ, CsqCompleteCanceledIrp)
    OFF(IO_CSQ, ReservePointer)
    SZ(IO_CSQ_IRP_CONTEXT)
    OFF(IO_CSQ_IRP_CONTEXT, Irp)
    OFF(IO_CSQ_IRP_CONTEXT, Csq)

    /*
     * Exceptions: what a filter, a handler and a language handler are
     * given. The unwinder's own structures are in probe-unwind.c.
     */
    SZ(EXCEPTION_RECORD)
    OFF(EXCEPTION_RECORD, ExceptionCode)
    OFF(EXCEPTION_RECORD, ExceptionFlags)
    OFF(EXCEPTION_RECORD, ExceptionRecord)
    OFF(EXCEPTION_RECORD, ExceptionAddress)
    OFF(EXCEPTION_RECORD, NumberParameters)
    OFF(EXCEPTION_RECORD, ExceptionInformation)
    SZ(EXCEPTION_POINTERS)
    OFF(EXCEPTION_POINTERS, ExceptionRecord)
    OFF(EXCEPTION_POINTERS, ContextRecord)
    { "const EXCEPTION_MAXIMUM_PARAMETERS", EXCEPTION_MAXIMUM_PARAMETERS },
    { "const EXCEPTION_NONCONTINUABLE", EXCEPTION_NONCONTINUABLE },
    { "const EXCEPTION_UNWINDING", EXCEPTION_UNWINDING },
    { "const EXCEPTION_EXIT_UNWIND", EXCEPTION_EXIT_UNWIND },
    { "const EXCEPTION_STACK_INVALID", EXCEPTION_STACK_INVALID },
    { "const EXCEPTION_NESTED_CALL", EXCEPTION_NESTED_CALL },
    { "const EXCEPTION_TARGET_UNWIND", EXCEPTION_TARGET_UNWIND },
    { "const EXCEPTION_COLLIDED_UNWIND", EXCEPTION_COLLIDED_UNWIND },
    { "const EXCEPTION_SOFTWARE_ORIGINATE", EXCEPTION_SOFTWARE_ORIGINATE },
    { "const EXCEPTION_EXECUTE_HANDLER", (unsigned __int64)(__int64)EXCEPTION_EXECUTE_HANDLER },
    { "const EXCEPTION_CONTINUE_SEARCH", (unsigned __int64)(__int64)EXCEPTION_CONTINUE_SEARCH },
    { "const EXCEPTION_CONTINUE_EXECUTION", (unsigned __int64)(__int64)EXCEPTION_CONTINUE_EXECUTION },
    { "const ExceptionContinueExecution", ExceptionContinueExecution },
    { "const ExceptionContinueSearch", ExceptionContinueSearch },
    { "const ExceptionNestedException", ExceptionNestedException },
    { "const ExceptionCollidedUnwind", ExceptionCollidedUnwind },
    SZ(M128A)
    OFF(M128A, Low)
    OFF(M128A, High)

    /* The register context: every field, each architecture its own. */
    SZ(CONTEXT)
    OFF(CONTEXT, ContextFlags)
    { "const CONTEXT_CONTROL", CONTEXT_CONTROL },
    { "const CONTEXT_INTEGER", CONTEXT_INTEGER },
    { "const CONTEXT_FLOATING_POINT", CONTEXT_FLOATING_POINT },
    { "const CONTEXT_DEBUG_REGISTERS", CONTEXT_DEBUG_REGISTERS },
    { "const CONTEXT_FULL", CONTEXT_FULL },
    { "const CONTEXT_ALL", CONTEXT_ALL },
    { "const CONTEXT_UNWOUND_TO_CALL", CONTEXT_UNWOUND_TO_CALL },
    { "const CONTEXT_EXCEPTION_ACTIVE", CONTEXT_EXCEPTION_ACTIVE },
    { "const CONTEXT_SERVICE_ACTIVE", CONTEXT_SERVICE_ACTIVE },
    { "const CONTEXT_EXCEPTION_REQUEST", CONTEXT_EXCEPTION_REQUEST },
    { "const CONTEXT_EXCEPTION_REPORTING", CONTEXT_EXCEPTION_REPORTING },
#if defined(_M_AMD64)
    { "const CONTEXT_SEGMENTS", CONTEXT_SEGMENTS },
    { "const CONTEXT_XSTATE", CONTEXT_XSTATE },
    OFF(CONTEXT, P1Home)
    OFF(CONTEXT, P2Home)
    OFF(CONTEXT, P3Home)
    OFF(CONTEXT, P4Home)
    OFF(CONTEXT, P5Home)
    OFF(CONTEXT, P6Home)
    OFF(CONTEXT, MxCsr)
    OFF(CONTEXT, SegCs)
    OFF(CONTEXT, SegDs)
    OFF(CONTEXT, SegEs)
    OFF(CONTEXT, SegFs)
    OFF(CONTEXT, SegGs)
    OFF(CONTEXT, SegSs)
    OFF(CONTEXT, EFlags)
    OFF(CONTEXT, Dr0)
    OFF(CONTEXT, Dr1)
    OFF(CONTEXT, Dr2)
    OFF(CONTEXT, Dr3)
    OFF(CONTEXT, Dr6)
    OFF(CONTEXT, Dr7)
    OFF(CONTEXT, Rax)
    OFF(CONTEXT, Rcx)
    OFF(CONTEXT, Rdx)
    OFF(CONTEXT, Rbx)
    OFF(CONTEXT, Rsp)
    OFF(CONTEXT, Rbp)
    OFF(CONTEXT, Rsi)
    OFF(CONTEXT, Rdi)
    OFF(CONTEXT, R8)
    OFF(CONTEXT, R9)
    OFF(CONTEXT, R10)
    OFF(CONTEXT, R11)
    OFF(CONTEXT, R12)
    OFF(CONTEXT, R13)
    OFF(CONTEXT, R14)
    OFF(CONTEXT, R15)
    OFF(CONTEXT, Rip)
    OFF(CONTEXT, FltSave)
    OFF(CONTEXT, Header)
    OFF(CONTEXT, Legacy)
    OFF(CONTEXT, Xmm0)
    OFF(CONTEXT, Xmm1)
    OFF(CONTEXT, Xmm2)
    OFF(CONTEXT, Xmm3)
    OFF(CONTEXT, Xmm4)
    OFF(CONTEXT, Xmm5)
    OFF(CONTEXT, Xmm6)
    OFF(CONTEXT, Xmm7)
    OFF(CONTEXT, Xmm8)
    OFF(CONTEXT, Xmm9)
    OFF(CONTEXT, Xmm10)
    OFF(CONTEXT, Xmm11)
    OFF(CONTEXT, Xmm12)
    OFF(CONTEXT, Xmm13)
    OFF(CONTEXT, Xmm14)
    OFF(CONTEXT, Xmm15)
    OFF(CONTEXT, VectorRegister)
    OFF(CONTEXT, VectorControl)
    OFF(CONTEXT, DebugControl)
    OFF(CONTEXT, LastBranchToRip)
    OFF(CONTEXT, LastBranchFromRip)
    OFF(CONTEXT, LastExceptionToRip)
    OFF(CONTEXT, LastExceptionFromRip)
    /* The legacy floating-point save area inside it. */
    SZ(XSAVE_FORMAT)
    OFF(XSAVE_FORMAT, ControlWord)
    OFF(XSAVE_FORMAT, StatusWord)
    OFF(XSAVE_FORMAT, TagWord)
    OFF(XSAVE_FORMAT, ErrorOpcode)
    OFF(XSAVE_FORMAT, ErrorOffset)
    OFF(XSAVE_FORMAT, ErrorSelector)
    OFF(XSAVE_FORMAT, DataOffset)
    OFF(XSAVE_FORMAT, DataSelector)
    OFF(XSAVE_FORMAT, MxCsr)
    OFF(XSAVE_FORMAT, MxCsr_Mask)
    OFF(XSAVE_FORMAT, FloatRegisters)
    OFF(XSAVE_FORMAT, XmmRegisters)
    OFF(XSAVE_FORMAT, Reserved4)
#elif defined(_M_ARM64)
    { "const ARM64_MAX_BREAKPOINTS", ARM64_MAX_BREAKPOINTS },
    { "const ARM64_MAX_WATCHPOINTS", ARM64_MAX_WATCHPOINTS },
    OFF(CONTEXT, Cpsr)
    OFF(CONTEXT, X)
    OFF(CONTEXT, X0)
    OFF(CONTEXT, X1)
    OFF(CONTEXT, X2)
    OFF(CONTEXT, X3)
    OFF(CONTEXT, X4)
    OFF(CONTEXT, X5)
    OFF(CONTEXT, X6)
    OFF(CONTEXT, X7)
    OFF(CONTEXT, X8)
    OFF(CONTEXT, X9)
    OFF(CONTEXT, X10)
    OFF(CONTEXT, X11)
    OFF(CONTEXT, X12)
    OFF(CONTEXT, X13)
    OFF(CONTEXT, X14)
    OFF(CONTEXT, X15)
    OFF(CONTEXT, X16)
    OFF(CONTEXT, X17)
    OFF(CONTEXT, X18)
    OFF(CONTEXT, X19)
    OFF(CONTEXT, X20)
    OFF(CONTEXT, X21)
    OFF(CONTEXT, X22)
    OFF(CONTEXT, X23)
    OFF(CONTEXT, X24)
    OFF(CONTEXT, X25)
    OFF(CONTEXT, X26)
    OFF(CONTEXT, X27)
    OFF(CONTEXT, X28)
    OFF(CONTEXT, Fp)
    OFF(CONTEXT, Lr)
    OFF(CONTEXT, Sp)
    OFF(CONTEXT, Pc)
    OFF(CONTEXT, V)
    OFF(CONTEXT, Fpcr)
    OFF(CONTEXT, Fpsr)
    OFF(CONTEXT, Bcr)
    OFF(CONTEXT, Bvr)
    OFF(CONTEXT, Wcr)
    OFF(CONTEXT, Wvr)
    /* One vector register. */
    SZ(NEON128)
    OFF(NEON128, Low)
    OFF(NEON128, High)
#endif

    /* Executive: fast mutexes, resources, interlocked lists, lookaside lists. */
    SZ(FAST_MUTEX)
    OFF(FAST_MUTEX, Count)
    OFF(FAST_MUTEX, Owner)
    OFF(FAST_MUTEX, Contention)
    OFF(FAST_MUTEX, Event)
    OFF(FAST_MUTEX, OldIrql)
    SZ(OWNER_ENTRY)
    OFF(OWNER_ENTRY, OwnerThread)
    OFF(OWNER_ENTRY, TableSize)
    SZ(ERESOURCE)
    OFF(ERESOURCE, SystemResourcesList)
    OFF(ERESOURCE, OwnerTable)
    OFF(ERESOURCE, ActiveCount)
    OFF(ERESOURCE, Flag)
    OFF(ERESOURCE, WaiterPriority)
    OFF(ERESOURCE, SharedWaiters)
    OFF(ERESOURCE, ExclusiveWaiters)
    OFF(ERESOURCE, OwnerEntry)
    OFF(ERESOURCE, ActiveEntries)
    OFF(ERESOURCE, ContentionCount)
    OFF(ERESOURCE, NumberOfSharedWaiters)
    OFF(ERESOURCE, NumberOfExclusiveWaiters)
    OFF(ERESOURCE, Address)
    OFF(ERESOURCE, SpinLock)
    /* The list header's 16 bytes are bit fields: depth 16 bits, sequence
     * 48, then 4 reserved and the first entry's address without its low
     * four bits. The header says so in HeaderX64 and HeaderArm64 alike. */
    SZ(SLIST_HEADER)
    OFF(SLIST_HEADER, Alignment)
    OFF(SLIST_HEADER, Region)
    SZ(SLIST_ENTRY)
    SZ(GENERAL_LOOKASIDE)
    OFF(GENERAL_LOOKASIDE, ListHead)
    OFF(GENERAL_LOOKASIDE, Depth)
    OFF(GENERAL_LOOKASIDE, MaximumDepth)
    OFF(GENERAL_LOOKASIDE, TotalAllocates)
    OFF(GENERAL_LOOKASIDE, AllocateMisses)
    OFF(GENERAL_LOOKASIDE, TotalFrees)
    OFF(GENERAL_LOOKASIDE, FreeMisses)
    OFF(GENERAL_LOOKASIDE, Type)
    OFF(GENERAL_LOOKASIDE, Tag)
    OFF(GENERAL_LOOKASIDE, Size)
    OFF(GENERAL_LOOKASIDE, Allocate)
    OFF(GENERAL_LOOKASIDE, Free)
    OFF(GENERAL_LOOKASIDE, ListEntry)
    OFF(GENERAL_LOOKASIDE, LastTotalAllocates)
    OFF(GENERAL_LOOKASIDE, LastAllocateMisses)
    OFF(GENERAL_LOOKASIDE, Future)
    SZ(GENERAL_LOOKASIDE_POOL)
    SZ(NPAGED_LOOKASIDE_LIST)
    OFF(NPAGED_LOOKASIDE_LIST, L)
    SZ(PAGED_LOOKASIDE_LIST)
    OFF(PAGED_LOOKASIDE_LIST, L)
    SZ(LOOKASIDE_LIST_EX)
    OFF(LOOKASIDE_LIST_EX, L)

    /* Security: the subject, the state of an access check in progress,
     * and a client a server may impersonate. */
    SZ(LUID)
    SZ(LUID_AND_ATTRIBUTES)
    OFF(LUID_AND_ATTRIBUTES, Attributes)
    SZ(PRIVILEGE_SET)
    OFF(PRIVILEGE_SET, Control)
    OFF(PRIVILEGE_SET, Privilege)
    SZ(INITIAL_PRIVILEGE_SET)
    SZ(SECURITY_SUBJECT_CONTEXT)
    OFF(SECURITY_SUBJECT_CONTEXT, ClientToken)
    OFF(SECURITY_SUBJECT_CONTEXT, ImpersonationLevel)
    OFF(SECURITY_SUBJECT_CONTEXT, PrimaryToken)
    OFF(SECURITY_SUBJECT_CONTEXT, ProcessAuditId)
    SZ(ACCESS_STATE)
    OFF(ACCESS_STATE, OperationID)
    OFF(ACCESS_STATE, SecurityEvaluated)
    OFF(ACCESS_STATE, GenerateAudit)
    OFF(ACCESS_STATE, GenerateOnClose)
    OFF(ACCESS_STATE, PrivilegesAllocated)
    OFF(ACCESS_STATE, Flags)
    OFF(ACCESS_STATE, RemainingDesiredAccess)
    OFF(ACCESS_STATE, PreviouslyGrantedAccess)
    OFF(ACCESS_STATE, OriginalDesiredAccess)
    OFF(ACCESS_STATE, SubjectSecurityContext)
    OFF(ACCESS_STATE, SecurityDescriptor)
    OFF(ACCESS_STATE, AuxData)
    OFF(ACCESS_STATE, Privileges)
    OFF(ACCESS_STATE, AuditPrivileges)
    OFF(ACCESS_STATE, ObjectName)
    OFF(ACCESS_STATE, ObjectTypeName)
    SZ(SECURITY_QUALITY_OF_SERVICE)
    OFF(SECURITY_QUALITY_OF_SERVICE, ImpersonationLevel)
    OFF(SECURITY_QUALITY_OF_SERVICE, ContextTrackingMode)
    OFF(SECURITY_QUALITY_OF_SERVICE, EffectiveOnly)
    SZ(TOKEN_SOURCE)
    SZ(TOKEN_CONTROL)
    OFF(TOKEN_CONTROL, AuthenticationId)
    OFF(TOKEN_CONTROL, ModifiedId)
    OFF(TOKEN_CONTROL, TokenSource)
    SZ(SECURITY_CLIENT_CONTEXT)
    OFF(SECURITY_CLIENT_CONTEXT, SecurityQos)
    OFF(SECURITY_CLIENT_CONTEXT, ClientToken)
    OFF(SECURITY_CLIENT_CONTEXT, DirectlyAccessClientToken)
    OFF(SECURITY_CLIENT_CONTEXT, DirectAccessEffectiveOnly)
    OFF(SECURITY_CLIENT_CONTEXT, ServerIsRemote)
    OFF(SECURITY_CLIENT_CONTEXT, ClientTokenControl)

    /* Creating a file, and a named pipe. */
    OFF(IO_SECURITY_CONTEXT, SecurityQos)
    OFF(IO_SECURITY_CONTEXT, AccessState)
    OFF(IO_SECURITY_CONTEXT, FullCreateOptions)
    OFF(IO_STACK_LOCATION, Parameters.Create.FileAttributes)
    OFF(IO_STACK_LOCATION, Parameters.Create.ShareAccess)
    OFF(IO_STACK_LOCATION, Parameters.Create.EaLength)
    OFF(IO_STACK_LOCATION, Parameters.CreatePipe.SecurityContext)
    OFF(IO_STACK_LOCATION, Parameters.CreatePipe.Options)
    OFF(IO_STACK_LOCATION, Parameters.CreatePipe.ShareAccess)
    OFF(IO_STACK_LOCATION, Parameters.CreatePipe.Parameters)
    SZ(NAMED_PIPE_CREATE_PARAMETERS)
    OFF(NAMED_PIPE_CREATE_PARAMETERS, NamedPipeType)
    OFF(NAMED_PIPE_CREATE_PARAMETERS, ReadMode)
    OFF(NAMED_PIPE_CREATE_PARAMETERS, CompletionMode)
    OFF(NAMED_PIPE_CREATE_PARAMETERS, MaximumInstances)
    OFF(NAMED_PIPE_CREATE_PARAMETERS, InboundQuota)
    OFF(NAMED_PIPE_CREATE_PARAMETERS, OutboundQuota)
    OFF(NAMED_PIPE_CREATE_PARAMETERS, DefaultTimeout)
    OFF(NAMED_PIPE_CREATE_PARAMETERS, TimeoutSpecified)

    /* Object names, and what the registry's queries return. */
    OFF(OBJECT_ATTRIBUTES, Length)
    OFF(OBJECT_ATTRIBUTES, RootDirectory)
    OFF(OBJECT_ATTRIBUTES, SecurityQualityOfService)
    SZ(OBJECT_NAME_INFORMATION)
    OFF(OBJECT_NAME_INFORMATION, Name)
    SZ(KEY_BASIC_INFORMATION)
    OFF(KEY_BASIC_INFORMATION, LastWriteTime)
    OFF(KEY_BASIC_INFORMATION, TitleIndex)
    OFF(KEY_BASIC_INFORMATION, NameLength)
    OFF(KEY_BASIC_INFORMATION, Name)
    SZ(KEY_NODE_INFORMATION)
    OFF(KEY_NODE_INFORMATION, LastWriteTime)
    OFF(KEY_NODE_INFORMATION, TitleIndex)
    OFF(KEY_NODE_INFORMATION, ClassOffset)
    OFF(KEY_NODE_INFORMATION, ClassLength)
    OFF(KEY_NODE_INFORMATION, NameLength)
    OFF(KEY_NODE_INFORMATION, Name)
    SZ(KEY_FULL_INFORMATION)
    OFF(KEY_FULL_INFORMATION, LastWriteTime)
    OFF(KEY_FULL_INFORMATION, TitleIndex)
    OFF(KEY_FULL_INFORMATION, ClassOffset)
    OFF(KEY_FULL_INFORMATION, ClassLength)
    OFF(KEY_FULL_INFORMATION, SubKeys)
    OFF(KEY_FULL_INFORMATION, MaxNameLen)
    OFF(KEY_FULL_INFORMATION, MaxClassLen)
    OFF(KEY_FULL_INFORMATION, Values)
    OFF(KEY_FULL_INFORMATION, MaxValueNameLen)
    OFF(KEY_FULL_INFORMATION, MaxValueDataLen)
    OFF(KEY_FULL_INFORMATION, Class)
    SZ(KEY_NAME_INFORMATION)
    OFF(KEY_NAME_INFORMATION, NameLength)
    OFF(KEY_NAME_INFORMATION, Name)
    SZ(KEY_CACHED_INFORMATION)
    OFF(KEY_CACHED_INFORMATION, LastWriteTime)
    OFF(KEY_CACHED_INFORMATION, TitleIndex)
    OFF(KEY_CACHED_INFORMATION, SubKeys)
    OFF(KEY_CACHED_INFORMATION, MaxNameLen)
    OFF(KEY_CACHED_INFORMATION, Values)
    OFF(KEY_CACHED_INFORMATION, MaxValueNameLen)
    OFF(KEY_CACHED_INFORMATION, MaxValueDataLen)
    OFF(KEY_CACHED_INFORMATION, NameLength)
    SZ(KEY_WRITE_TIME_INFORMATION)
    SZ(KEY_VALUE_BASIC_INFORMATION)
    OFF(KEY_VALUE_BASIC_INFORMATION, TitleIndex)
    OFF(KEY_VALUE_BASIC_INFORMATION, Type)
    OFF(KEY_VALUE_BASIC_INFORMATION, NameLength)
    OFF(KEY_VALUE_BASIC_INFORMATION, Name)
    SZ(KEY_VALUE_FULL_INFORMATION)
    OFF(KEY_VALUE_FULL_INFORMATION, TitleIndex)
    OFF(KEY_VALUE_FULL_INFORMATION, Type)
    OFF(KEY_VALUE_FULL_INFORMATION, DataOffset)
    OFF(KEY_VALUE_FULL_INFORMATION, DataLength)
    OFF(KEY_VALUE_FULL_INFORMATION, NameLength)
    OFF(KEY_VALUE_FULL_INFORMATION, Name)
    OFF(KEY_VALUE_PARTIAL_INFORMATION, TitleIndex)
    SZ(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64)
    OFF(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, Type)
    OFF(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, DataLength)
    OFF(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, Data)
    SZ(KEY_VALUE_ENTRY)
    OFF(KEY_VALUE_ENTRY, ValueName)
    OFF(KEY_VALUE_ENTRY, DataLength)
    OFF(KEY_VALUE_ENTRY, DataOffset)
    OFF(KEY_VALUE_ENTRY, Type)
    { "const KeyBasicInformation", KeyBasicInformation },
    { "const KeyNodeInformation", KeyNodeInformation },
    { "const KeyFullInformation", KeyFullInformation },
    { "const KeyNameInformation", KeyNameInformation },
    { "const KeyCachedInformation", KeyCachedInformation },
    { "const KeyValueBasicInformation", KeyValueBasicInformation },
    { "const KeyValueFullInformation", KeyValueFullInformation },
    { "const KeyValuePartialInformation", KeyValuePartialInformation },
    { "const KeyValueFullInformationAlign64", KeyValueFullInformationAlign64 },
    { "const KeyValuePartialInformationAlign64", KeyValuePartialInformationAlign64 },
    SZ(RTL_QUERY_REGISTRY_TABLE)
    OFF(RTL_QUERY_REGISTRY_TABLE, QueryRoutine)
    OFF(RTL_QUERY_REGISTRY_TABLE, Flags)
    OFF(RTL_QUERY_REGISTRY_TABLE, Name)
    OFF(RTL_QUERY_REGISTRY_TABLE, EntryContext)
    OFF(RTL_QUERY_REGISTRY_TABLE, DefaultType)
    OFF(RTL_QUERY_REGISTRY_TABLE, DefaultData)
    OFF(RTL_QUERY_REGISTRY_TABLE, DefaultLength)

#if defined(_AMD64_)
    /*
     * Only the public head of the KPCR. The header's structure stops short
     * of the embedded KPRCB, so its size says nothing about where the PRCB
     * or the current-thread slot are.
     */
    SZ(KPCR)
    OFF(KPCR, Self)
    OFF(KPCR, CurrentPrcb)
    OFF(KPCR, Irql)
#endif

    NKABI_END,
};

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    /* The probe is data, not a driver: refuse to stay loaded. */
    return NkAbiTable[0].Value == sizeof(void *) ? STATUS_NOT_SUPPORTED : STATUS_UNSUCCESSFUL;
}
