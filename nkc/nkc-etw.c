/*
 * Conformance: trace providers, with nobody listening.
 *
 * What a driver that traces sees on a system where no trace session has
 * enabled it and no WMI consumer asks it anything: registering as an ETW
 * provider and writing events, registering its device with WMI and the
 * requests that brings, firing a WMI event, the callbacks kept for a
 * bugcheck, and the questions a tracing library asks the system when it
 * starts (which modules are loaded, is a debugger there, which version
 * is this).
 *
 * The GUIDs are this driver's own, so that no session of the system it
 * runs on has enabled them.
 *
 * Two lists.
 *
 * List 0 (0x222000) calls documented routines, and one from nkc-undoc.h:
 * ZwQuerySystemInformation. PsGetVersion it looks up, as wpprecorder.sys
 * does.
 *
 * List 1 (0x222004) is the start-up of WPP tracing as wpprecorder.sys
 * and the kit's tracing templates do it: six routines are looked up by
 * name with MmGetSystemRoutineAddress, and those found are called
 * through the pointer. Two of them are nkc-undoc.h's (part 4):
 * EtwRegisterClassicProvider and RtlQueryModuleInformation. The list
 * also holds what the ETW routines say to a registration handle of
 * zero. Every value is a 1 or a 0 where a routine was not found and so
 * not called: the length of the list does not depend on what is there.
 *
 * IRP_MJ_SYSTEM_CONTROL is this driver's own dispatch routine (NkcSetup
 * puts it in place). It writes down each request as it arrives, and
 * answers a registration query in one of two ways the list chooses.
 *
 * Not called: DbgkWerCaptureLiveKernelDump (it writes a dump), and the
 * bugcheck callback itself (it is registered and taken back).
 */

#define NKC_DEVICE L"\\Device\\NkcEtw"
#define NKC_THREADS
#define NKC_SETUP
#define NKC_LISTS 2
#include "nkc.h"
#include <wmistr.h>
#include "nkc-undoc.h"

/* {9B6F3C2A-41D7-4E58-A30C-5E7B19D264F1}: the manifest provider. */
static const GUID NkcProviderGuid = {
    0x9b6f3c2a, 0x41d7, 0x4e58, { 0xa3, 0x0c, 0x5e, 0x7b, 0x19, 0xd2, 0x64, 0xf1 }
};
/* {9B6F3C2B-41D7-4E58-A30C-5E7B19D264F1}: the classic (WPP) provider. */
static const GUID NkcClassicGuid = {
    0x9b6f3c2b, 0x41d7, 0x4e58, { 0xa3, 0x0c, 0x5e, 0x7b, 0x19, 0xd2, 0x64, 0xf1 }
};
/* {9B6F3C2C-41D7-4E58-A30C-5E7B19D264F1}: the WMI event. */
static const GUID NkcEventGuid = {
    0x9b6f3c2c, 0x41d7, 0x4e58, { 0xa3, 0x0c, 0x5e, 0x7b, 0x19, 0xd2, 0x64, 0xf1 }
};

/* How often each callback was called. */
static volatile LONG NkcEnableCalls;
static volatile LONG NkcClassicCalls;

static VOID NTAPI NkcEnable(LPCGUID SourceId, ULONG ControlCode, UCHAR Level,
                            ULONGLONG MatchAnyKeyword, ULONGLONG MatchAllKeyword,
                            PEVENT_FILTER_DESCRIPTOR FilterData, PVOID CallbackContext)
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(ControlCode);
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(MatchAnyKeyword);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);
    InterlockedIncrement(&NkcEnableCalls);
}

static NKC_ETW_CLASSIC_CALLBACK NkcClassic;

static VOID NTAPI NkcClassic(LPCGUID Guid, UCHAR ControlCode, PVOID EnableContext,
                             PVOID CallbackContext)
{
    UNREFERENCED_PARAMETER(Guid);
    UNREFERENCED_PARAMETER(ControlCode);
    UNREFERENCED_PARAMETER(EnableContext);
    UNREFERENCED_PARAMETER(CallbackContext);
    InterlockedIncrement(&NkcClassicCalls);
}

/* Never called: the system does not stop while this driver is loaded. */
static KBUGCHECK_REASON_CALLBACK_ROUTINE NkcBugCheck;

static VOID NkcBugCheck(KBUGCHECK_CALLBACK_REASON Reason,
                        struct _KBUGCHECK_REASON_CALLBACK_RECORD *Record,
                        PVOID ReasonSpecificData, ULONG ReasonSpecificDataLength)
{
    UNREFERENCED_PARAMETER(Reason);
    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(ReasonSpecificData);
    UNREFERENCED_PARAMETER(ReasonSpecificDataLength);
}

/* The callback records live in the image, which is not paged. */
static KBUGCHECK_REASON_CALLBACK_RECORD NkcBugCheckRecord;
static KBUGCHECK_REASON_CALLBACK_RECORD NkcBugCheckOther;

/*
 * WMI requests, as they arrive.
 */

#define NKC_SEEN_MAX 8

typedef struct _NKC_SEEN {
    ULONG Minor;      /* IRP_MN_... */
    ULONG Irql;       /* the IRQL it arrived at */
    ULONG System;     /* 1 if it arrived in the System process */
    ULONG Other;      /* 1 if on another thread than the one that registered */
    ULONG Provider;   /* 1 if Parameters.WMI.ProviderId is this device */
    ULONG DataPath;   /* Parameters.WMI.DataPath */
    ULONG BufferSize; /* Parameters.WMI.BufferSize */
} NKC_SEEN;

static NKC_SEEN NkcSeen[NKC_SEEN_MAX];
static volatile LONG NkcSeenCount;
static PVOID NkcRegistrar; /* the thread that registers */
/* How a registration query is answered: 0 with a WMIREGINFO that lists
 * no GUIDs, 1 with STATUS_INVALID_DEVICE_REQUEST. */
static volatile LONG NkcRefuse;
static volatile LONG NkcRegistered;

#define NKC_REGINFO_SIZE ((ULONG)FIELD_OFFSET(WMIREGINFOW, WmiRegGuid))

static NTSTATUS NkcSystemControl(PDEVICE_OBJECT Device, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    LONG Index = InterlockedIncrement(&NkcSeenCount) - 1;
    PWMIREGINFOW Info;

    if (Index < NKC_SEEN_MAX) {
        NKC_SEEN *Seen = &NkcSeen[Index];

        Seen->Minor = Stack->MinorFunction;
        Seen->Irql = KeGetCurrentIrql();
        Seen->System = IoGetCurrentProcess() == PsInitialSystemProcess ? 1 : 0;
        Seen->Other = PsGetCurrentThread() != NkcRegistrar ? 1 : 0;
        Seen->Provider = Stack->Parameters.WMI.ProviderId == (ULONG_PTR)Device ? 1 : 0;
        Seen->DataPath = (ULONG)(ULONG_PTR)Stack->Parameters.WMI.DataPath;
        Seen->BufferSize = Stack->Parameters.WMI.BufferSize;
    }
    if ((Stack->MinorFunction != IRP_MN_REGINFO && Stack->MinorFunction != IRP_MN_REGINFO_EX) ||
        Stack->Parameters.WMI.ProviderId != (ULONG_PTR)Device || NkcRefuse != 0) {
        return NkcComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    /* A registration with no GUIDs, no registry path and no MOF: the
     * smallest answer that is a valid one. */
    if (Stack->Parameters.WMI.BufferSize < NKC_REGINFO_SIZE) {
        if (Stack->Parameters.WMI.BufferSize >= sizeof(ULONG)) {
            *(ULONG *)Stack->Parameters.WMI.Buffer = NKC_REGINFO_SIZE;
            return NkcComplete(Irp, STATUS_BUFFER_TOO_SMALL, sizeof(ULONG));
        }
        return NkcComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    Info = (PWMIREGINFOW)Stack->Parameters.WMI.Buffer;
    RtlZeroMemory(Info, NKC_REGINFO_SIZE);
    Info->BufferSize = NKC_REGINFO_SIZE;
    return NkcComplete(Irp, STATUS_SUCCESS, NKC_REGINFO_SIZE);
}

static NTSTATUS NkcSetup(PDRIVER_OBJECT Driver, PDEVICE_OBJECT Device)
{
    UNREFERENCED_PARAMETER(Device);
    Driver->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = NkcSystemControl;
    return STATUS_SUCCESS;
}

static VOID NkcTeardown(PDRIVER_OBJECT Driver, PDEVICE_OBJECT Device)
{
    UNREFERENCED_PARAMETER(Driver);
    /* Only if a list was cut short between its two calls. */
    if (InterlockedExchange(&NkcRegistered, 0) != 0) {
        IoWMIRegistrationControl(Device, WMIREG_ACTION_DEREGISTER);
    }
}

/* Fire one WMI event nobody has asked for; the status. The block is the
 * kernel's once it has said yes. */
static NTSTATUS NkcFireEvent(VOID)
{
    static const WCHAR Name[] = L"Nkc";
    ULONG NameAt = FIELD_OFFSET(WNODE_SINGLE_INSTANCE, VariableData);
    ULONG Size = NameAt + 8 + 8;
    PWNODE_SINGLE_INSTANCE Wnode;
    PUSHORT Counted;
    NTSTATUS Status;

    Wnode = (PWNODE_SINGLE_INSTANCE)ExAllocatePoolWithTag(NonPagedPool, Size, NKC_TAG);
    if (Wnode == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Wnode, Size);
    Wnode->WnodeHeader.BufferSize = Size;
    Wnode->WnodeHeader.ProviderId = IoWMIDeviceObjectToProviderId(NkcDeviceObject);
    Wnode->WnodeHeader.Guid = NkcEventGuid;
    Wnode->WnodeHeader.Flags = WNODE_FLAG_SINGLE_INSTANCE | WNODE_FLAG_EVENT_ITEM;
    KeQuerySystemTime(&Wnode->WnodeHeader.TimeStamp);
    /* The instance name, counted, then eight bytes of data. */
    Wnode->OffsetInstanceName = NameAt;
    Counted = (PUSHORT)((PUCHAR)Wnode + NameAt);
    Counted[0] = 3 * sizeof(WCHAR);
    Counted[1] = Name[0];
    Counted[2] = Name[1];
    Counted[3] = Name[2];
    Wnode->DataBlockOffset = NameAt + 8;
    Wnode->SizeDataBlock = 8;
    Status = IoWMIWriteEvent(Wnode);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Wnode, NKC_TAG);
    }
    return Status;
}

/* Register the device with WMI, see what arrives, deregister. */
static VOID NkcWmiRound(NKC_LOG *Log, LONG Refuse, BOOLEAN Fire)
{
    PDEVICE_OBJECT Device = NkcDeviceObject;
    NTSTATUS Status;
    LONG Count, i;
    ULONG Id;

    NkcSeenCount = 0;
    NkcRefuse = Refuse;

    /* 0: registered. */
    Status = IoWMIRegistrationControl(Device, WMIREG_ACTION_REGISTER);
    NkcPut(Log, (ULONG)Status);
    if (!NT_SUCCESS(Status)) {
        return;
    }
    NkcRegistered = 1;

    /* How many requests arrive, with nobody but the kernel to send
     * them, and each one: minor function, IRQL, in the System process,
     * on another thread, for this device, DataPath, BufferSize.
     *
     * Answered with a registration (Refuse 0), a guess: one request,
     * 0x0B (IRP_MN_REGINFO_EX), 0, 1, 1, 1, 0 (WMIREGISTER), and the
     * size of the kernel's first buffer.
     * Refused (Refuse 1), a guess: two, the same and then 0x08
     * (IRP_MN_REGINFO): the kernel asks the older way when the newer
     * is refused. */
    NkcSettle(&NkcSeenCount, 1);
    NkcSleep(300);
    Count = NkcSeenCount;
    NkcPut(Log, (ULONG)Count);
    for (i = 0; i < Count && i < NKC_SEEN_MAX; i++) {
        NkcPut(Log, NkcSeen[i].Minor);
        NkcPut(Log, NkcSeen[i].Irql);
        NkcPut(Log, NkcSeen[i].System);
        NkcPut(Log, NkcSeen[i].Other);
        NkcPut(Log, NkcSeen[i].Provider);
        NkcPut(Log, NkcSeen[i].DataPath);
        NkcPut(Log, NkcSeen[i].BufferSize);
    }

    /* 1, 1: registered, the device has a provider id, and it is the
     * same one each time it is asked. */
    Id = IoWMIDeviceObjectToProviderId(Device);
    NkcPut(Log, Id != 0 ? 1 : 0);
    NkcPut(Log, IoWMIDeviceObjectToProviderId(Device) == Id ? 1 : 0);

    if (Fire) {
        /* 0: an event nobody enabled is taken and dropped. */
        NkcPut(Log, (ULONG)NkcFireEvent());
    }

    /* 0: deregistered; 0: nothing arrived because of it; 0: no provider
     * id any more. */
    NkcPut(Log, (ULONG)IoWMIRegistrationControl(Device, WMIREG_ACTION_DEREGISTER));
    NkcRegistered = 0;
    NkcSleep(100);
    NkcPut(Log, (ULONG)(NkcSeenCount - Count));
    NkcPut(Log, IoWMIDeviceObjectToProviderId(Device));
}

/*
 * What ZwQuerySystemInformation gives for the classes used here. The
 * kit's kernel headers define none of this; the layouts are the public
 * ones of winternl.h and of the auxiliary library.
 */

#define NKC_SYSTEM_BASIC 0            /* SystemBasicInformation */
#define NKC_SYSTEM_MODULE 11          /* SystemModuleInformation: wpprecorder.sys */
#define NKC_SYSTEM_KERNEL_DEBUGGER 35 /* SystemKernelDebuggerInformation */
#define NKC_SYSTEM_ISOLATED_USER 165  /* SystemIsolatedUserModeInformation: msrpc.sys */

typedef struct _NKC_BASIC {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} NKC_BASIC;

typedef struct _NKC_MODULE {
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} NKC_MODULE;

typedef struct _NKC_MODULES {
    ULONG NumberOfModules;
    NKC_MODULE Modules[1];
} NKC_MODULES;

/* What RtlQueryModuleInformation gives per module, asked for 0x110
 * bytes each (AUX_MODULE_EXTENDED_INFO). */
typedef struct _NKC_AUX_MODULE {
    PVOID ImageBase;
    ULONG ImageSize;
    USHORT FileNameOffset;
    UCHAR FullPathName[256];
} NKC_AUX_MODULE;

/* 1 if the file name in `Path`, from `At`, is `Name`, whatever the
 * case of its letters. */
static ULONG NkcIsFile(const UCHAR *Path, ULONG At, const CHAR *Name)
{
    ULONG i;

    for (i = 0; At + i < 256; i++) {
        UCHAR a = Path[At + i];
        UCHAR b = (UCHAR)Name[i];

        if (a >= 'A' && a <= 'Z') {
            a = (UCHAR)(a + ('a' - 'A'));
        }
        if (a != b) {
            return 0;
        }
        if (a == 0) {
            return 1;
        }
    }
    return 0;
}

static VOID NkcSystemInformation(NKC_LOG *Log)
{
    NKC_BASIC Basic;
    ULONG Words[4];
    UCHAR Debugger[2];
    NKC_MODULES *Modules = NULL;
    PVOID Base = NkcDeviceObject->DriverObject->DriverStart;
    ULONG Length, Tries, i, Mine;
    NTSTATUS Status;

    /* 0, 0x40: the basic information and its length. 0x1000, 0x10000:
     * the page size and the allocation granularity. 0x10000: the lowest
     * user address. 0xFFFEFFFF, 0x7FFF: the highest, in two halves.
     * 1: there is at least one processor. */
    RtlZeroMemory(&Basic, sizeof(Basic));
    Length = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)ZwQuerySystemInformation(NKC_SYSTEM_BASIC, &Basic, sizeof(Basic), &Length));
    NkcPut(Log, Length);
    NkcPut(Log, Basic.PageSize);
    NkcPut(Log, Basic.AllocationGranularity);
    NkcPut(Log, (ULONG)Basic.MinimumUserModeAddress);
    NkcPut(Log, (ULONG)Basic.MaximumUserModeAddress);
    NkcPut(Log, (ULONG)((ULONGLONG)Basic.MaximumUserModeAddress >> 32));
    NkcPut(Log, Basic.NumberOfProcessors > 0 ? 1 : 0);

    /* 0xC0000004 (STATUS_INFO_LENGTH_MISMATCH): a buffer too short for
     * it. The length reported then: a guess, 0x40. */
    Length = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)ZwQuerySystemInformation(NKC_SYSTEM_BASIC, &Basic, 8, &Length));
    NkcPut(Log, Length);

    /* 0xC0000003 (STATUS_INVALID_INFO_CLASS): a class there is not. */
    NkcPut(Log, (ULONG)ZwQuerySystemInformation(0xFFFF, Words, sizeof(Words), NULL));

    /* 0, 2: is a kernel debugger there, and the length; then the two
     * answers: enabled, and not present. 0, 1 on a system started
     * without debugging. */
    Debugger[0] = Debugger[1] = 0xAA;
    Length = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)ZwQuerySystemInformation(NKC_SYSTEM_KERNEL_DEBUGGER, Debugger,
                                                sizeof(Debugger), &Length));
    NkcPut(Log, Length);
    NkcPut(Log, Debugger[0]);
    NkcPut(Log, Debugger[1]);
    /* 0xC0000004: one byte is too short for it. */
    NkcPut(Log, (ULONG)ZwQuerySystemInformation(NKC_SYSTEM_KERNEL_DEBUGGER, Debugger, 1, NULL));

    /* 0, then four zeroes: sixteen bytes about isolated user mode, of
     * which there is none. 0xC0000004: eight bytes are too short. */
    Words[0] = Words[1] = Words[2] = Words[3] = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)ZwQuerySystemInformation(NKC_SYSTEM_ISOLATED_USER, Words, sizeof(Words),
                                                NULL));
    for (i = 0; i < 4; i++) {
        NkcPut(Log, Words[i]);
    }
    NkcPut(Log, (ULONG)ZwQuerySystemInformation(NKC_SYSTEM_ISOLATED_USER, Words, 8, NULL));

    /* 0xC0000004, 1: the list of loaded modules does not fit in no
     * buffer, and the length it needs is reported. */
    Length = 0;
    NkcPut(Log, (ULONG)ZwQuerySystemInformation(NKC_SYSTEM_MODULE, NULL, 0, &Length));
    NkcPut(Log, Length != 0 ? 1 : 0);

    /* 0: in a buffer of that length it does. (A driver loaded in
     * between makes the list longer: asked again.) */
    Status = STATUS_INFO_LENGTH_MISMATCH;
    for (Tries = 0; Tries < 4 && Status == STATUS_INFO_LENGTH_MISMATCH && Length != 0; Tries++) {
        ULONG Room = Length;

        Modules = (NKC_MODULES *)ExAllocatePoolWithTag(PagedPool, Room, NKC_TAG);
        if (Modules == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Status = ZwQuerySystemInformation(NKC_SYSTEM_MODULE, Modules, Room, &Length);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(Modules, NKC_TAG);
            Modules = NULL;
        }
    }
    NkcPut(Log, (ULONG)Status);
    if (Modules == NULL) {
        return;
    }

    /* 1: the length is that of the count and so many entries.
     * 1, 1: the first module is ntoskrnl.exe and the second hal.dll.
     * 1: this driver is in the list once, under its file's name. */
    NkcPut(Log, Length == FIELD_OFFSET(NKC_MODULES, Modules) +
                              Modules->NumberOfModules * sizeof(NKC_MODULE)
                    ? 1
                    : 0);
    NkcPut(Log, Modules->NumberOfModules >= 1
                    ? NkcIsFile(Modules->Modules[0].FullPathName,
                                Modules->Modules[0].OffsetToFileName, "ntoskrnl.exe")
                    : 0);
    NkcPut(Log, Modules->NumberOfModules >= 2
                    ? NkcIsFile(Modules->Modules[1].FullPathName,
                                Modules->Modules[1].OffsetToFileName, "hal.dll")
                    : 0);
    Mine = 0;
    for (i = 0; i < Modules->NumberOfModules; i++) {
        if (Modules->Modules[i].ImageBase == Base &&
            NkcIsFile(Modules->Modules[i].FullPathName, Modules->Modules[i].OffsetToFileName,
                      "nkc-etw.sys")) {
            Mine++;
        }
    }
    NkcPut(Log, Mine);
    ExFreePoolWithTag(Modules, NKC_TAG);
}

/* A routine of the kernel by its name, or NULL. */
static PVOID NkcLookup(PCWSTR Name)
{
    UNICODE_STRING String;

    RtlInitUnicodeString(&String, Name);
    return MmGetSystemRoutineAddress(&String);
}

/* PsGetVersion, as wdm.h declares it; looked up, as wpprecorder.sys
 * does, so that the list says something when it is not there. */
typedef BOOLEAN NTAPI NKC_PS_GET_VERSION(PULONG MajorVersion, PULONG MinorVersion,
                                         PULONG BuildNumber, PUNICODE_STRING CSDVersion);

static VOID NkcRun(NKC_LOG *Log)
{
    static const EVENT_DESCRIPTOR Event = { 1, 0, 0, 4, 0, 0, 0 };
    /* Provider traits: their length, then the provider's name. */
    static const UCHAR Traits[] = { 9, 0, 'N', 'k', 'c', 'E', 't', 'w', 0 };
    EVENT_DATA_DESCRIPTOR Data;
    REGHANDLE Handle = 0;
    ULONG Value = 0x4E4B;
    NKC_PS_GET_VERSION *GetVersion;
    RTL_OSVERSIONINFOW Version;
    UNICODE_STRING Csd;
    ULONG Major, Minor, Build;
    NTSTATUS Status;

    /*
     * A manifest provider.
     */

    /* 0, 1, 0: registered; the handle is not zero; and the enable
     * callback has not been called, since no session wants this
     * provider. */
    Status = EtwRegister(&NkcProviderGuid, NkcEnable, NULL, &Handle);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Handle != 0 ? 1 : 0);
    NkcPut(Log, (ULONG)NkcEnableCalls);
    if (NT_SUCCESS(Status)) {
        /* 0xC0000010 (STATUS_INVALID_DEVICE_REQUEST): a class of
         * information there is not.
         * 0xC000000D: traits too short to be traits.
         * 0: the provider's traits are set.
         * 0xC0000001 (STATUS_UNSUCCESSFUL): they are set once only. */
        NkcPut(Log, (ULONG)EtwSetInformation(Handle, (EVENT_INFO_CLASS)0x7F, (PVOID)Traits,
                                             sizeof(Traits)));
        NkcPut(Log, (ULONG)EtwSetInformation(Handle, EventProviderSetTraits, (PVOID)Traits, 2));
        NkcPut(Log, (ULONG)EtwSetInformation(Handle, EventProviderSetTraits, (PVOID)Traits,
                                             sizeof(Traits)));
        NkcPut(Log, (ULONG)EtwSetInformation(Handle, EventProviderSetTraits, (PVOID)Traits,
                                             sizeof(Traits)));

        /* 0, 0: an event with no data, and one with four bytes, are
         * written to nobody. */
        NkcPut(Log, (ULONG)EtwWriteTransfer(Handle, &Event, NULL, NULL, 0, NULL));
        EventDataDescCreate(&Data, &Value, sizeof(Value));
        NkcPut(Log, (ULONG)EtwWriteTransfer(Handle, &Event, NULL, NULL, 1, &Data));

        /* 0, 0: unregistered; the callback was never called. */
        NkcPut(Log, (ULONG)EtwUnregister(Handle));
        NkcPut(Log, (ULONG)NkcEnableCalls);
    }

    /*
     * WMI registration.
     */

    /* 0: a device that has not registered has no provider id.
     * 0xC000000D, a guess: it cannot be deregistered either. */
    NkcRegistrar = PsGetCurrentThread();
    NkcPut(Log, IoWMIDeviceObjectToProviderId(NkcDeviceObject));
    NkcPut(Log, (ULONG)IoWMIRegistrationControl(NkcDeviceObject, WMIREG_ACTION_DEREGISTER));

    /* Registered twice: its query answered, then refused. */
    NkcWmiRound(Log, 0, TRUE);
    NkcWmiRound(Log, 1, FALSE);

    /*
     * Callbacks for a bugcheck.
     */

    /* 1, 0: a record is registered, and not a second time.
     * 1, 0: it is taken back, and not a second time.
     * 0: one never registered cannot be taken back. */
    KeInitializeCallbackRecord(&NkcBugCheckRecord);
    KeInitializeCallbackRecord(&NkcBugCheckOther);
    NkcPut(Log, KeRegisterBugCheckReasonCallback(&NkcBugCheckRecord, NkcBugCheck,
                                                 KbCallbackSecondaryDumpData, (PUCHAR) "NkcEtw"));
    NkcPut(Log, KeRegisterBugCheckReasonCallback(&NkcBugCheckRecord, NkcBugCheck,
                                                 KbCallbackSecondaryDumpData, (PUCHAR) "NkcEtw"));
    NkcPut(Log, KeDeregisterBugCheckReasonCallback(&NkcBugCheckRecord));
    NkcPut(Log, KeDeregisterBugCheckReasonCallback(&NkcBugCheckRecord));
    NkcPut(Log, KeDeregisterBugCheckReasonCallback(&NkcBugCheckOther));

    /*
     * Questions about the system.
     */

    NkcSystemInformation(Log);

    /* 0: the driver verifier is not watching this driver. */
    NkcPut(Log, (ULONG)MmIsDriverVerifying(NkcDeviceObject->DriverObject));

    /* 1: PsGetVersion is there. Then 0, 10, 0: this is not a checked
     * build, and it is version 10.0. 1: its build number is the one
     * RtlGetVersion gives. 0: no service pack, so the string it hands
     * out is empty. */
    GetVersion = (NKC_PS_GET_VERSION *)NkcLookup(L"PsGetVersion");
    NkcPut(Log, GetVersion != NULL ? 1 : 0);
    if (GetVersion != NULL) {
        Major = Minor = Build = 0xAAAAAAAA;
        RtlZeroMemory(&Csd, sizeof(Csd));
        RtlZeroMemory(&Version, sizeof(Version));
        Version.dwOSVersionInfoSize = sizeof(Version);
        RtlGetVersion(&Version);
        NkcPut(Log, GetVersion(&Major, &Minor, &Build, &Csd));
        NkcPut(Log, Major);
        NkcPut(Log, Minor);
        NkcPut(Log, Build == Version.dwBuildNumber ? 1 : 0);
        NkcPut(Log, Csd.Length);
    }

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}

/*
 * List 1: the routines a tracing driver looks up.
 */

/* WmiTraceMessage, WmiQueryTraceInformation and RtlQueryRegistryValuesEx,
 * as wdm.h declares the first two and RtlQueryRegistryValues, whose
 * arguments the third takes. (wdm.h declares WmiTraceMessage only for a
 * driver run through the WPP preprocessor; the logger's handle is a
 * TRACEHANDLE there, 64 bits.) */
typedef NTSTATUS __cdecl NKC_WMI_TRACE_MESSAGE(ULONG64 LoggerHandle, ULONG MessageFlags,
                                               LPCGUID MessageGuid, USHORT MessageNumber, ...);
/* TRACE_MESSAGE_GUID of evntrace.h: the message carries its GUID. */
#define NKC_TRACE_MESSAGE_GUID 2
typedef NTSTATUS NTAPI NKC_WMI_QUERY_TRACE(TRACE_INFORMATION_CLASS TraceInformationClass,
                                           PVOID TraceInformation, ULONG TraceInformationLength,
                                           PULONG RequiredLength, PVOID Buffer);
typedef NTSTATUS NTAPI NKC_QUERY_REGISTRY_VALUES(ULONG RelativeTo, PCWSTR Path,
                                                 PRTL_QUERY_REGISTRY_TABLE QueryTable,
                                                 PVOID Context, PVOID Environment);

/* RTL_QUERY_REGISTRY_TYPECHECK and the place of the type it checks. */
#define NKC_TYPECHECK 0x00000100
#define NKC_TYPECHECK_SHIFT 24

static VOID NkcClassicProvider(NKC_LOG *Log, NKC_ETW_REGISTER_CLASSIC_PROVIDER *Register)
{
    REGHANDLE Handle = 0;
    NTSTATUS Status = STATUS_PROCEDURE_NOT_FOUND;

    /* 0xC000000D: a classic provider needs a callback.
     * 0, 1, 0: with one it is registered, has a handle, and the
     * callback is not called.
     * 0, 0: EtwUnregister ends it; the callback was never called. */
    NkcPut(Log, Register != NULL
                    ? (ULONG)Register(&NkcClassicGuid, 0, NULL, NULL, &Handle)
                    : 0);
    Handle = 0;
    if (Register != NULL) {
        Status = Register(&NkcClassicGuid, 0, NkcClassic, NULL, &Handle);
    }
    NkcPut(Log, Register != NULL ? (ULONG)Status : 0);
    NkcPut(Log, Handle != 0 ? 1 : 0);
    NkcPut(Log, (ULONG)NkcClassicCalls);
    NkcPut(Log, NT_SUCCESS(Status) && Handle != 0 ? (ULONG)EtwUnregister(Handle) : 0);
    NkcPut(Log, (ULONG)NkcClassicCalls);
}

static VOID NkcTraceInformation(NKC_LOG *Log, NKC_WMI_QUERY_TRACE *Query)
{
    WNODE_HEADER Header;
    ULONG Value, Needed;

    if (Query == NULL) {
        ULONG i;

        for (i = 0; i < 13; i++) {
            NkcPut(Log, 0);
        }
        return;
    }
    RtlZeroMemory(&Header, sizeof(Header));

    /* A logger is named by the handle in the header of the request that
     * enabled the provider. 0xC0000008: a header with none.
     * 0xC0000030 (STATUS_INVALID_PARAMETER_MIX): no header at all.
     * 0xC0000004: room for less than four bytes. */
    Value = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)Query(TraceEnableLevelClass, &Value, sizeof(Value), NULL, &Header));
    NkcPut(Log, (ULONG)Query(TraceEnableLevelClass, &Value, sizeof(Value), NULL, NULL));
    NkcPut(Log, (ULONG)Query(TraceEnableLevelClass, &Value, 2, NULL, &Header));

    /* The handle carries the answers: flags in its upper half, the
     * level in the third byte, the logger's number in the low word.
     * 0, 3, 4: the level of handle 0x0000000500030002, and the length.
     * 0, 5: its flags. 0, 2: its logger's number. */
    Header.HistoricalContext = 0x0000000500030002ull;
    Value = 0xAAAAAAAA;
    Needed = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)Query(TraceEnableLevelClass, &Value, sizeof(Value), &Needed, &Header));
    NkcPut(Log, Value);
    NkcPut(Log, Needed);
    Value = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)Query(TraceEnableFlagsClass, &Value, sizeof(Value), NULL, &Header));
    NkcPut(Log, Value);
    Value = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)Query(TraceIdClass, &Value, sizeof(Value), NULL, &Header));
    NkcPut(Log, Value);

    /* 0xC0000003 twice: EventLoggerHandleClass is not answered, and
     * class 0x7F is none. */
    NkcPut(Log, (ULONG)Query(EventLoggerHandleClass, &Value, sizeof(Value), NULL, &Header));
    NkcPut(Log, (ULONG)Query((TRACE_INFORMATION_CLASS)0x7F, &Value, sizeof(Value), NULL, &Header));
    NkcPut(Log, KeGetCurrentIrql());
}

static VOID NkcModuleInformation(NKC_LOG *Log, NKC_RTL_QUERY_MODULE_INFORMATION *Query)
{
    PVOID Base = NkcDeviceObject->DriverObject->DriverStart;
    NKC_AUX_MODULE *Modules = NULL;
    ULONG Length, Tries, Count, i, Mine;
    NTSTATUS Status;

    if (Query == NULL) {
        for (i = 0; i < 9; i++) {
            NkcPut(Log, 0);
        }
        return;
    }

    /* 0xC000000D, a guess: a size per module that is neither of the
     * two there are (8 and 0x110). */
    Length = 0;
    NkcPut(Log, (ULONG)Query(&Length, 12, NULL));

    /* 0, 1, 1: with no buffer the length needed is reported, and that
     * is a success; it is not zero and is so many times 0x110. */
    Length = 0;
    NkcPut(Log, (ULONG)Query(&Length, sizeof(NKC_AUX_MODULE), NULL));
    NkcPut(Log, Length != 0 ? 1 : 0);
    NkcPut(Log, Length % sizeof(NKC_AUX_MODULE) == 0 ? 1 : 0);

    /* 0xC0000023 (STATUS_BUFFER_TOO_SMALL), a guess: room for one
     * module only. 0: room for all. */
    Status = STATUS_BUFFER_TOO_SMALL;
    for (Tries = 0; Tries < 4 && Status == STATUS_BUFFER_TOO_SMALL && Length != 0; Tries++) {
        ULONG Room = Length;

        Modules = (NKC_AUX_MODULE *)ExAllocatePoolWithTag(PagedPool, Room, NKC_TAG);
        if (Modules == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        if (Tries == 0) {
            ULONG One = sizeof(NKC_AUX_MODULE);

            NkcPut(Log, (ULONG)Query(&One, sizeof(NKC_AUX_MODULE), Modules));
        }
        Length = Room;
        Status = Query(&Length, sizeof(NKC_AUX_MODULE), Modules);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(Modules, NKC_TAG);
            Modules = NULL;
            /* How much it needs now. */
            Length = 0;
            if (!NT_SUCCESS(Query(&Length, sizeof(NKC_AUX_MODULE), NULL))) {
                Length = 0;
            }
        }
    }
    if (Tries == 0) {
        NkcPut(Log, 0);
    }
    NkcPut(Log, (ULONG)Status);

    /* 1, 1, 1: the first module is ntoskrnl.exe, the second hal.dll,
     * and this driver is in the list once. */
    Count = Modules != NULL ? Length / sizeof(NKC_AUX_MODULE) : 0;
    NkcPut(Log, Count >= 1 ? NkcIsFile(Modules[0].FullPathName, Modules[0].FileNameOffset,
                                       "ntoskrnl.exe")
                           : 0);
    NkcPut(Log, Count >= 2 ? NkcIsFile(Modules[1].FullPathName, Modules[1].FileNameOffset,
                                       "hal.dll")
                           : 0);
    Mine = 0;
    for (i = 0; i < Count; i++) {
        if (Modules[i].ImageBase == Base &&
            NkcIsFile(Modules[i].FullPathName, Modules[i].FileNameOffset, "nkc-etw.sys")) {
            Mine++;
        }
    }
    NkcPut(Log, Mine);
    if (Modules != NULL) {
        ExFreePoolWithTag(Modules, NKC_TAG);
    }
}

static VOID NkcRegistryValues(NKC_LOG *Log, NKC_QUERY_REGISTRY_VALUES *Query)
{
    RTL_QUERY_REGISTRY_TABLE Table[2];
    ULONG Value;

    if (Query == NULL) {
        NkcPut(Log, 0);
        NkcPut(Log, 0);
        NkcPut(Log, 0);
        return;
    }

    /* 0, 1: HKLM\SYSTEM\Select says which control set is the current
     * one, a number, read straight into a variable with its type
     * checked. */
    RtlZeroMemory(Table, sizeof(Table));
    Value = 0xAAAAAAAA;
    Table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED | NKC_TYPECHECK;
    Table[0].Name = L"Current";
    Table[0].EntryContext = &Value;
    Table[0].DefaultType = (REG_DWORD << NKC_TYPECHECK_SHIFT) | REG_NONE;
    NkcPut(Log, (ULONG)Query(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\System\\Select", Table,
                             NULL, NULL));
    NkcPut(Log, Value);

    /* 0xC0000034 (STATUS_OBJECT_NAME_NOT_FOUND): a key there is not. */
    Value = 0xAAAAAAAA;
    NkcPut(Log, (ULONG)Query(RTL_REGISTRY_ABSOLUTE,
                             L"\\Registry\\Machine\\System\\Select\\NkcNoSuchKey", Table, NULL,
                             NULL));
}

static VOID NkcRunList(ULONG List, NKC_LOG *Log)
{
    static const EVENT_DESCRIPTOR Event = { 1, 0, 0, 4, 0, 0, 0 };
    PVOID Register, Message, Trace, Module, Version, Registry;
    ULONG Value = 0;

    UNREFERENCED_PARAMETER(List);

    /* 1 six times: every routine the tracing start-up looks up is
     * there. 0: one that does not exist is not. */
    Register = NkcLookup(L"EtwRegisterClassicProvider");
    Message = NkcLookup(L"WmiTraceMessage");
    Trace = NkcLookup(L"WmiQueryTraceInformation");
    Module = NkcLookup(L"RtlQueryModuleInformation");
    Version = NkcLookup(L"PsGetVersion");
    Registry = NkcLookup(L"RtlQueryRegistryValuesEx");
    NkcPut(Log, Register != NULL ? 1 : 0);
    NkcPut(Log, Message != NULL ? 1 : 0);
    NkcPut(Log, Trace != NULL ? 1 : 0);
    NkcPut(Log, Module != NULL ? 1 : 0);
    NkcPut(Log, Version != NULL ? 1 : 0);
    NkcPut(Log, Registry != NULL ? 1 : 0);
    NkcPut(Log, NkcLookup(L"NkcNoSuchRoutine") != NULL ? 1 : 0);

    /* 1: the address a name is looked up to is the one a driver that
     * imports the name is given. */
    NkcPut(Log, NkcLookup(L"EtwRegister") == (PVOID)(ULONG_PTR)EtwRegister ? 1 : 0);

    /* 0xC0000008 (STATUS_INVALID_HANDLE) twice: a trace message for a
     * logger there is not. A logger's handle has the logger's number in
     * its low word: number 0xFFFF is more than there can be, and number
     * 0 is none that runs (a guess). The arguments end with a null
     * pointer. */
    NkcPut(Log, Message != NULL
                    ? (ULONG)((NKC_WMI_TRACE_MESSAGE *)Message)(0xFFFF, NKC_TRACE_MESSAGE_GUID,
                                                                &NkcClassicGuid, 1, (PVOID)NULL,
                                                                (SIZE_T)0)
                    : 0);
    NkcPut(Log, Message != NULL
                    ? (ULONG)((NKC_WMI_TRACE_MESSAGE *)Message)(0, NKC_TRACE_MESSAGE_GUID,
                                                                &NkcClassicGuid, 1, (PVOID)NULL,
                                                                (SIZE_T)0)
                    : 0);

    NkcClassicProvider(Log, (NKC_ETW_REGISTER_CLASSIC_PROVIDER *)Register);
    NkcTraceInformation(Log, (NKC_WMI_QUERY_TRACE *)Trace);
    NkcModuleInformation(Log, (NKC_RTL_QUERY_MODULE_INFORMATION *)Module);
    NkcRegistryValues(Log, (NKC_QUERY_REGISTRY_VALUES *)Registry);

    /* A registration handle of zero. 0xC0000008 three times: nothing
     * is set for it, nothing unregistered, nothing written. */
    NkcPut(Log, (ULONG)EtwSetInformation(0, EventProviderSetTraits, &Value, sizeof(Value)));
    NkcPut(Log, (ULONG)EtwUnregister(0));
    NkcPut(Log, (ULONG)EtwWriteTransfer(0, &Event, NULL, NULL, 0, NULL));

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
