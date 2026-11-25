/*
 * Conformance: the registry, as a driver uses it.
 *
 * Creating a key under the driver's own service key, setting and
 * reading values, what a missing key or value and a short buffer give,
 * and deleting the key again.
 */

#define NKC_DEVICE L"\\Device\\NkcReg"
#include "nkc.h"

#define NKC_KEY L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\nkc-reg\\NkcTest"

static NTSTATUS NkcOpen(PCWSTR Path, BOOLEAN Create, PHANDLE Key, PULONG Disposition)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                               NULL);
    *Key = NULL;
    if (Create) {
        return ZwCreateKey(Key, KEY_ALL_ACCESS, &Attributes, 0, NULL, REG_OPTION_NON_VOLATILE,
                           Disposition);
    }
    return ZwOpenKey(Key, KEY_ALL_ACCESS, &Attributes);
}

/* Query `Value` into a buffer of `Room` bytes: log the status, the
 * length the query reports, and, on success, the type, the data's
 * length and its first four bytes. */
static VOID NkcQuery(NKC_LOG *Log, HANDLE Key, PCWSTR Value, ULONG Room)
{
    UCHAR Buffer[64];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    UNICODE_STRING Name;
    ULONG Length = 0xEEEEEEEE;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Value);
    RtlFillMemory(Buffer, sizeof(Buffer), 0xEE);
    Status = ZwQueryValueKey(Key, &Name, KeyValuePartialInformation, Buffer, Room, &Length);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Length);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, Info->Type);
        NkcPut(Log, Info->DataLength);
        NkcPut(Log, *(ULONG UNALIGNED *)Info->Data);
    }
}

static VOID NkcRun(NKC_LOG *Log)
{
    HANDLE Key, Again;
    ULONG Disposition = 0;
    ULONG Number = 0x12345678;
    WCHAR Text[] = L"nk";
    UNICODE_STRING Name;

    /* 0xC0000034: the key is not there yet. */
    NkcPut(Log, (ULONG)NkcOpen(NKC_KEY, FALSE, &Key, NULL));

    /* 0, 1: created, and said to be new. */
    NkcPut(Log, (ULONG)NkcOpen(NKC_KEY, TRUE, &Key, &Disposition));
    NkcPut(Log, Disposition);
    if (Key == NULL) {
        return;
    }

    /* 0, 2: created again, it is opened, and said to exist.
     * 0: and it can simply be opened, by a name in other letter case. */
    NkcPut(Log, (ULONG)NkcOpen(NKC_KEY, TRUE, &Again, &Disposition));
    NkcPut(Log, Disposition);
    if (Again != NULL) {
        ZwClose(Again);
    }
    NkcPut(Log, (ULONG)NkcOpen(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\"
                               L"NKC-REG\\nkctest",
                               FALSE, &Again, NULL));
    if (Again != NULL) {
        ZwClose(Again);
    }

    /* 0xC0000034 and the length left as it was: no such value. */
    NkcQuery(Log, Key, L"Number", sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 16);

    /* 0, 0: a number and a string are set. */
    RtlInitUnicodeString(&Name, L"Number");
    NkcPut(Log, (ULONG)ZwSetValueKey(Key, &Name, 0, REG_DWORD, &Number, sizeof(Number)));
    RtlInitUnicodeString(&Name, L"Text");
    NkcPut(Log, (ULONG)ZwSetValueKey(Key, &Name, 0, REG_SZ, Text, sizeof(Text)));

    /* 0, 16, 4, 4, 0x12345678: the number comes back, by a name in
     * other letter case, with the length of what was returned. */
    NkcQuery(Log, Key, L"NUMBER", sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 16);

    /* 0, 18, 1, 6, 0x006B006E: and the string, terminator included. */
    NkcQuery(Log, Key, L"Text", sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 16);

    /* Room for the header but not the data: the status, and the length
     * that would have been needed. Then no room at all. */
    NkcQuery(Log, Key, L"Text", FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data));
    NkcQuery(Log, Key, L"Text", 0);

    /* 0, then 0x12345679 read back: a value is replaced by setting it. */
    Number++;
    RtlInitUnicodeString(&Name, L"Number");
    NkcPut(Log, (ULONG)ZwSetValueKey(Key, &Name, 0, REG_DWORD, &Number, sizeof(Number)));
    NkcQuery(Log, Key, L"Number", sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 16);

    /* 0, 0, 0xC0000034: deleted and closed, the key is gone. */
    NkcPut(Log, (ULONG)ZwDeleteKey(Key));
    NkcPut(Log, (ULONG)ZwClose(Key));
    NkcPut(Log, (ULONG)NkcOpen(NKC_KEY, FALSE, &Key, NULL));

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
