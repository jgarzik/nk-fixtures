/*
 * ABI probe: records what Microsoft's own compiler and WDK headers say
 * about the size and layout of driver-visible kernel structures.
 *
 * This file is NK's, not Microsoft's, but it includes only <ntddk.h> and
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
 * "sizeof <type>" and "offsetof <type> <member>".
 */

#include <ntddk.h>

#define NKABI_NAME_LEN 88

typedef struct _NKABI_ENTRY {
    char Name[NKABI_NAME_LEN];
    unsigned __int64 Value;
} NKABI_ENTRY;

#define SZ(type) { "sizeof " #type, sizeof(type) },
#define OFF(type, member) { "offsetof " #type " " #member, FIELD_OFFSET(type, member) },

/* Kept in the image even though nothing reads it at run time. */
#pragma comment(linker, "/include:NkAbiTable")

const NKABI_ENTRY NkAbiTable[] = {
    /* Marker, with the pointer size as a sanity check. */
    { "NKABI-BEGIN v1", sizeof(void *) },

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

    { "NKABI-END", 0 },
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
