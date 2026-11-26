/*
 * Conformance: the registry, as a driver uses it.
 *
 * Creating a key under the driver's own service key, setting and
 * reading values, what a missing key or value and a short buffer give,
 * and deleting the key again. Then, on a key with a class, values and
 * subkeys: every information class of ZwQueryKey, ZwEnumerateKey,
 * ZwEnumerateValueKey and ZwQueryValueKey, with room and without;
 * ZwDeleteValueKey; and the query tables of RtlQueryRegistryValues and
 * RtlQueryRegistryValuesEx.
 *
 * The driver touches two keys, both of which it creates and deletes:
 * NkcTest under its own service key, and NkcRegTest under Control. Its
 * service must be named nkc-reg.
 *
 * Structures are logged as their bytes, four to a value, times left
 * out. The buffer a query writes to is filled with 0xEE first, so a
 * byte the kernel did not write shows as 0xEE.
 *
 * No routine from nkc-undoc.h is used.
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

/* The same in the full form, which carries the name: log the status and
 * the length reported, and, when the header fitted, the type, where the
 * data is, its length and the name's. */
static VOID NkcQueryFull(NKC_LOG *Log, HANDLE Key, PCWSTR Value, ULONG Room)
{
    UCHAR Buffer[64];
    PKEY_VALUE_FULL_INFORMATION Info = (PKEY_VALUE_FULL_INFORMATION)Buffer;
    UNICODE_STRING Name;
    ULONG Length = 0xEEEEEEEE;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, Value);
    RtlFillMemory(Buffer, sizeof(Buffer), 0xEE);
    Status = ZwQueryValueKey(Key, &Name, KeyValueFullInformation, Buffer, Room, &Length);
    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Length);
    if (Status == STATUS_SUCCESS || Status == STATUS_BUFFER_OVERFLOW) {
        NkcPut(Log, Info->Type);
        NkcPut(Log, Info->DataOffset);
        NkcPut(Log, Info->DataLength);
        NkcPut(Log, Info->NameLength);
    }
}

static VOID NkcMore(NKC_LOG *Log);

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

    /* The full form of the string: with room for all of it, with room
     * for its header alone, and with none. Then of a value whose name
     * has an odd number of letters, and of one with no data. */
    NkcQueryFull(Log, Key, L"TEXT", 64);
    NkcQueryFull(Log, Key, L"Text", FIELD_OFFSET(KEY_VALUE_FULL_INFORMATION, Name));
    NkcQueryFull(Log, Key, L"Text", 0);
    RtlInitUnicodeString(&Name, L"Odd");
    NkcPut(Log, (ULONG)ZwSetValueKey(Key, &Name, 0, REG_BINARY, &Number, 3));
    NkcQueryFull(Log, Key, L"Odd", 64);
    RtlInitUnicodeString(&Name, L"Empty");
    NkcPut(Log, (ULONG)ZwSetValueKey(Key, &Name, 0, REG_BINARY, NULL, 0));
    NkcQueryFull(Log, Key, L"Empty", 64);
    NkcQuery(Log, Key, L"Empty", sizeof(KEY_VALUE_PARTIAL_INFORMATION));

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

    NkcMore(Log);
}

/* ---- Everything below was added after the list above was first recorded;
 * the values above keep their places. ------------------------------------- */

#define NKC_MARK 0x4E000000u
#define MARK(n) NkcPut(Log, NKC_MARK | (n))

#define NKC_CONTROL_KEY L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\NkcRegTest"

/* Where answers are written: 256 bytes, aligned to eight. */
static ULONGLONG NkcRoom[32];
#define NKC_ROOM ((PUCHAR)NkcRoom)

/* Bytes, four to a value, an odd end filled with 0xFF. */
static VOID NkcPutBytes(NKC_LOG *Log, const UCHAR *Bytes, ULONG Count)
{
    ULONG i, j, Value;

    for (i = 0; i < Count; i += 4) {
        Value = 0;
        for (j = 0; j < 4; j++) {
            Value |= (ULONG)(i + j < Count ? Bytes[i + j] : 0xFF) << (8 * j);
        }
        NkcPut(Log, Value);
    }
}

/* Log what a query answered into NkcRoom, which was filled with 0xEE
 * before: the status and the length it reported; then, on success, the
 * bytes from `Skip` up to that length; when only the fixed part fitted
 * (0x80000005), the bytes from `Skip` up to `Fixed`. `Skip` leaves out a
 * time at the start. */
static VOID NkcAnswer(NKC_LOG *Log, NTSTATUS Status, ULONG Length, ULONG Skip, ULONG Fixed)
{
    ULONG End = 0;

    NkcPut(Log, (ULONG)Status);
    NkcPut(Log, Length);
    if (Status == STATUS_SUCCESS) {
        End = Length > sizeof(NkcRoom) ? sizeof(NkcRoom) : Length;
    } else if (Status == STATUS_BUFFER_OVERFLOW) {
        End = Fixed;
    }
    if (End > Skip) {
        NkcPutBytes(Log, NKC_ROOM + Skip, End - Skip);
    }
}

/* ZwQueryKey (Index below zero) or ZwEnumerateKey of subkey `Index`,
 * into `Room` bytes. */
static VOID NkcKeyInfo(NKC_LOG *Log, HANDLE Key, LONG Index, ULONG Class, ULONG Room, ULONG Skip,
                       ULONG Fixed)
{
    ULONG Length = 0xEEEEEEEE;
    NTSTATUS Status;

    RtlFillMemory(NkcRoom, sizeof(NkcRoom), 0xEE);
    if (Index < 0) {
        Status = ZwQueryKey(Key, (KEY_INFORMATION_CLASS)Class, NkcRoom, Room, &Length);
    } else {
        Status = ZwEnumerateKey(Key, (ULONG)Index, (KEY_INFORMATION_CLASS)Class, NkcRoom, Room,
                                &Length);
    }
    NkcAnswer(Log, Status, Length, Skip, Fixed);
}

/* The same with too little room, four times: none, one byte less than
 * the fixed part, the fixed part alone, one byte less than all of it.
 * Status and length each time; nothing of the answer. */
static VOID NkcKeyShort(NKC_LOG *Log, HANDLE Key, LONG Index, ULONG Class, ULONG Fixed, ULONG All)
{
    NkcKeyInfo(Log, Key, Index, Class, 0, Fixed, Fixed);
    NkcKeyInfo(Log, Key, Index, Class, Fixed - 1, Fixed, Fixed);
    NkcKeyInfo(Log, Key, Index, Class, Fixed, Fixed, Fixed);
    NkcKeyInfo(Log, Key, Index, Class, All - 1, Fixed, Fixed);
}

/* ZwQueryValueKey of `Name`, or, if that is NULL, ZwEnumerateValueKey
 * of value `Index`, into `Room` bytes. */
static VOID NkcValueInfo(NKC_LOG *Log, HANDLE Key, PCWSTR Name, ULONG Index, ULONG Class,
                         ULONG Room, ULONG Fixed)
{
    UNICODE_STRING String;
    ULONG Length = 0xEEEEEEEE;
    NTSTATUS Status;

    RtlFillMemory(NkcRoom, sizeof(NkcRoom), 0xEE);
    if (Name != NULL) {
        RtlInitUnicodeString(&String, Name);
        Status = ZwQueryValueKey(Key, &String, (KEY_VALUE_INFORMATION_CLASS)Class, NkcRoom, Room,
                                 &Length);
    } else {
        Status = ZwEnumerateValueKey(Key, Index, (KEY_VALUE_INFORMATION_CLASS)Class, NkcRoom,
                                     Room, &Length);
    }
    NkcAnswer(Log, Status, Length, 0, Fixed);
}

static NTSTATUS NkcSet(HANDLE Key, PCWSTR Name, ULONG Type, PVOID Data, ULONG Length)
{
    UNICODE_STRING String;

    RtlInitUnicodeString(&String, Name);
    return ZwSetValueKey(Key, &String, 0, Type, Data, Length);
}

/* Create or open the key `Name` under `Parent`, with a class if one is
 * given. */
static NTSTATUS NkcChild(HANDLE Parent, PCWSTR Name, PCWSTR Class, PHANDLE Key)
{
    UNICODE_STRING String, ClassString;
    OBJECT_ATTRIBUTES Attributes;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&Attributes, &String, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               Parent, NULL);
    *Key = NULL;
    if (Class != NULL) {
        RtlInitUnicodeString(&ClassString, Class);
    }
    return ZwCreateKey(Key, KEY_ALL_ACCESS, &Attributes, 0, Class != NULL ? &ClassString : NULL,
                       REG_OPTION_NON_VOLATILE, NULL);
}

/* Sizes of the fixed parts. */
#define NKC_KEY_BASIC 16  /* LastWriteTime, TitleIndex, NameLength */
#define NKC_KEY_NODE 24   /* ..., ClassOffset, ClassLength, NameLength */
#define NKC_KEY_FULL 44   /* ..., ClassOffset, ClassLength, SubKeys, MaxNameLen, MaxClassLen,
                             Values, MaxValueNameLen, MaxValueDataLen */
#define NKC_KEY_NAME 4    /* NameLength */
#define NKC_KEY_CACHED 36 /* LastWriteTime, TitleIndex, SubKeys, MaxNameLen, Values,
                             MaxValueNameLen, MaxValueDataLen, NameLength */
#define NKC_VALUE_BASIC 12   /* TitleIndex, Type, NameLength */
#define NKC_VALUE_FULL 20    /* TitleIndex, Type, DataOffset, DataLength, NameLength */
#define NKC_VALUE_PARTIAL 12 /* TitleIndex, Type, DataLength */
#define NKC_VALUE_PARTIAL64 8 /* Type, DataLength */

/* The key the rest works on:
 *
 *   NkcTest, class "Cls"
 *     values, in the order set: Number (REG_DWORD 0x12345678), Text
 *       (REG_SZ "nk"), Odd (REG_BINARY, 3 bytes), the unnamed value
 *       (REG_SZ "d"), Multi (REG_MULTI_SZ "a", "bc")
 *     subkeys, in the order created: Beta (class "BC"; one value, Val,
 *       REG_BINARY of 5 bytes; one subkey, Sub), alpha, Gamma9
 */
static NTSTATUS NkcBuild(PHANDLE Key)
{
    static ULONG Number = 0x12345678;
    static WCHAR Text[] = L"nk";
    static WCHAR Unnamed[] = L"d";
    static WCHAR Multi[] = L"a\0bc\0";
    static UCHAR Five[5] = {1, 2, 3, 4, 5};
    HANDLE Sub, Deeper;
    NTSTATUS Status;

    Status = NkcChild(NULL, NKC_KEY, L"Cls", Key);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    NkcSet(*Key, L"Number", REG_DWORD, &Number, sizeof(Number));
    NkcSet(*Key, L"Text", REG_SZ, Text, sizeof(Text));
    NkcSet(*Key, L"Odd", REG_BINARY, &Number, 3);
    NkcSet(*Key, L"", REG_SZ, Unnamed, sizeof(Unnamed));
    NkcSet(*Key, L"Multi", REG_MULTI_SZ, Multi, sizeof(Multi));
    if (NT_SUCCESS(NkcChild(*Key, L"Beta", L"BC", &Sub))) {
        NkcSet(Sub, L"Val", REG_BINARY, Five, sizeof(Five));
        if (NT_SUCCESS(NkcChild(Sub, L"Sub", NULL, &Deeper))) {
            ZwClose(Deeper);
        }
        ZwClose(Sub);
    }
    if (NT_SUCCESS(NkcChild(*Key, L"alpha", NULL, &Sub))) {
        ZwClose(Sub);
    }
    if (NT_SUCCESS(NkcChild(*Key, L"Gamma9", NULL, &Sub))) {
        ZwClose(Sub);
    }
    return STATUS_SUCCESS;
}

/* Delete the key `Name` under `Parent`, which must have no subkeys. */
static NTSTATUS NkcRemove(HANDLE Parent, PCWSTR Name)
{
    HANDLE Key;
    NTSTATUS Status;

    Status = NkcChild(Parent, Name, NULL, &Key);
    if (NT_SUCCESS(Status)) {
        Status = ZwDeleteKey(Key);
        ZwClose(Key);
    }
    return Status;
}

static VOID NkcKeys(NKC_LOG *Log, HANDLE Key)
{
    ULONG Class;

    /* ZwQueryKey, each class with room for everything. Times are left
     * out. The sizes are bytes; names are UTF-16.
     *
     * Basic: 0, 30; TitleIndex 0, NameLength 14, "NkcTest".
     * Node: 0, 46; TitleIndex 0, ClassOffset 40, ClassLength 6,
     *   NameLength 14, "NkcTest", two bytes untouched (0xEE), "Cls".
     *   (That the class starts at a multiple of four is a guess; if it
     *   follows the name directly: 44, and ClassOffset 38.)
     * Full: 0, 50; TitleIndex 0, ClassOffset 44, ClassLength 6,
     *   SubKeys 3, MaxNameLen 12, MaxClassLen 4, Values 5,
     *   MaxValueNameLen 12, MaxValueDataLen 12, "Cls".
     * Name: 0, 130; NameLength 126,
     *   "\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\nkc-reg\NkcTest":
     *   the name with the link CurrentControlSet followed. (The control
     *   set's number is the machine's, and the letter case of each
     *   component is as it was created.)
     * Cached: 0, 36; TitleIndex 0, SubKeys 3, MaxNameLen 12, Values 5,
     *   MaxValueNameLen 12, MaxValueDataLen 12, NameLength 14. */
    MARK(0x10);
    NkcKeyInfo(Log, Key, -1, KeyBasicInformation, sizeof(NkcRoom), 8, NKC_KEY_BASIC);
    NkcKeyInfo(Log, Key, -1, KeyNodeInformation, sizeof(NkcRoom), 8, NKC_KEY_NODE);
    NkcKeyInfo(Log, Key, -1, KeyFullInformation, sizeof(NkcRoom), 8, NKC_KEY_FULL);
    NkcKeyInfo(Log, Key, -1, KeyNameInformation, sizeof(NkcRoom), 0, NKC_KEY_NAME);
    NkcKeyInfo(Log, Key, -1, KeyCachedInformation, sizeof(NkcRoom), 8, NKC_KEY_CACHED);

    /* Too little room. Each line is a status and the length reported,
     * for no room, a byte less than the fixed part, the fixed part, and
     * a byte less than everything:
     * Basic:  0xC0000023 30, 0xC0000023 30, 0x80000005 30, 0x80000005 30.
     * Node:   0xC0000023 46, 0xC0000023 46, 0x80000005 46, 0x80000005 46.
     * Full:   0xC0000023 50, 0xC0000023 50, 0x80000005 50, 0x80000005 50.
     * Name:   0xC0000023 130, 0xC0000023 130, 0x80000005 130, 0x80000005 130.
     * Cached (all of it is fixed): 0xC0000023 36, 0xC0000023 36. */
    MARK(0x11);
    NkcKeyShort(Log, Key, -1, KeyBasicInformation, NKC_KEY_BASIC, 30);
    NkcKeyShort(Log, Key, -1, KeyNodeInformation, NKC_KEY_NODE, 46);
    NkcKeyShort(Log, Key, -1, KeyFullInformation, NKC_KEY_FULL, 50);
    NkcKeyShort(Log, Key, -1, KeyNameInformation, NKC_KEY_NAME, 130);
    NkcKeyInfo(Log, Key, -1, KeyCachedInformation, 0, NKC_KEY_CACHED, NKC_KEY_CACHED);
    NkcKeyInfo(Log, Key, -1, KeyCachedInformation, NKC_KEY_CACHED - 1, NKC_KEY_CACHED,
               NKC_KEY_CACHED);

    /* The header that fitted when the name did not: 0x80000005, 30;
     * TitleIndex 0, NameLength 14. */
    NkcKeyInfo(Log, Key, -1, KeyBasicInformation, NKC_KEY_BASIC, 8, NKC_KEY_BASIC);

    /* The classes after Cached, 5 to 10, each with room for 256 bytes:
     * status, length and whatever was returned. Guesses:
     * 5 (flags): 0, 12; three zero words.
     * 6 (virtualization): 0, 4; a word of flags.
     * 7 (handle tags): 0, 4; 0.
     * 8 (trust): 0, 4; a word of flags.
     * 9 (layer): 0, 4; a word of flags.
     * 10: 0xC000000D, the length untouched: there is no such class. */
    MARK(0x12);
    for (Class = 5; Class <= 10; Class++) {
        NkcKeyInfo(Log, Key, -1, Class, sizeof(NkcRoom), 0, 0);
    }

    /* ZwEnumerateKey: subkeys come in order of their names, letter case
     * disregarded, not in the order created.
     * Basic of 0, 1, 2: 0, 26, TitleIndex 0, NameLength 10, "alpha";
     *   0, 24, 0, 8, "Beta"; 0, 28, 0, 12, "Gamma9".
     * Basic of 3: 0x8000001A, the length untouched.
     * Node of 1: 0, 36; 0, ClassOffset 32, ClassLength 4, NameLength 8,
     *   "Beta", "BC".
     * Node of 0: 0, 34; 0, ClassOffset 0xFFFFFFFF, ClassLength 0,
     *   NameLength 10, "alpha": a key without a class.
     * Full of 1: 0, 48; 0, ClassOffset 44, ClassLength 4, SubKeys 1,
     *   MaxNameLen 6, MaxClassLen 0, Values 1, MaxValueNameLen 6,
     *   MaxValueDataLen 5, "BC".
     * Full of 2: 0, 44; 0, 0xFFFFFFFF, 0, then six zeros.
     * Name (3) and Cached (4) of 0: 0xC000000D twice: a subkey is
     *   enumerated in the first three classes only. */
    MARK(0x13);
    NkcKeyInfo(Log, Key, 0, KeyBasicInformation, sizeof(NkcRoom), 8, NKC_KEY_BASIC);
    NkcKeyInfo(Log, Key, 1, KeyBasicInformation, sizeof(NkcRoom), 8, NKC_KEY_BASIC);
    NkcKeyInfo(Log, Key, 2, KeyBasicInformation, sizeof(NkcRoom), 8, NKC_KEY_BASIC);
    NkcKeyInfo(Log, Key, 3, KeyBasicInformation, sizeof(NkcRoom), 8, NKC_KEY_BASIC);
    NkcKeyInfo(Log, Key, 1, KeyNodeInformation, sizeof(NkcRoom), 8, NKC_KEY_NODE);
    NkcKeyInfo(Log, Key, 0, KeyNodeInformation, sizeof(NkcRoom), 8, NKC_KEY_NODE);
    NkcKeyInfo(Log, Key, 1, KeyFullInformation, sizeof(NkcRoom), 8, NKC_KEY_FULL);
    NkcKeyInfo(Log, Key, 2, KeyFullInformation, sizeof(NkcRoom), 8, NKC_KEY_FULL);
    NkcKeyInfo(Log, Key, 0, KeyNameInformation, sizeof(NkcRoom), 0, NKC_KEY_NAME);
    NkcKeyInfo(Log, Key, 0, KeyCachedInformation, sizeof(NkcRoom), 8, NKC_KEY_CACHED);

    /* Too little room for subkey 0 in the basic class:
     * 0xC0000023 26, 0xC0000023 26, 0x80000005 26, 0x80000005 26.
     * And for subkey 1 in the node class: the same statuses, 36.
     * 0x8000001A: past the end, no room is not looked at. */
    NkcKeyShort(Log, Key, 0, KeyBasicInformation, NKC_KEY_BASIC, 26);
    NkcKeyShort(Log, Key, 1, KeyNodeInformation, NKC_KEY_NODE, 36);
    NkcKeyInfo(Log, Key, 3, KeyBasicInformation, 0, NKC_KEY_BASIC, NKC_KEY_BASIC);
}

static VOID NkcValues(NKC_LOG *Log, HANDLE Key)
{
    static ULONG Number = 0x12345678;
    UNICODE_STRING Name;
    ULONG Index;

    /* ZwEnumerateValueKey: values come in the order they were first set.
     * Basic of 0 to 4, each status, length, then TitleIndex 0, the
     * type, NameLength and the name:
     *   0, 24; 0, 4, 12, "Number".   0, 20; 0, 1, 8, "Text".
     *   0, 18; 0, 3, 6, "Odd".       0, 12; 0, 1, 0: the unnamed value.
     *   0, 22; 0, 7, 10, "Multi".
     * Basic of 5: 0x8000001A, the length untouched. */
    MARK(0x20);
    for (Index = 0; Index <= 5; Index++) {
        NkcValueInfo(Log, Key, NULL, Index, KeyValueBasicInformation, sizeof(NkcRoom),
                     NKC_VALUE_BASIC);
    }

    /* The other classes. The data of the full classes start at a
     * multiple of eight; bytes between name and data are untouched.
     * Full of 1 (Text): 0, 38; 0, 1, DataOffset 32, DataLength 6,
     *   NameLength 8, "Text", 4 bytes untouched, "nk" and terminator.
     * Full of 3 (unnamed): 0, 28; 0, 1, DataOffset 24, DataLength 4,
     *   NameLength 0, 4 bytes untouched, "d" and terminator.
     * Partial of 2 (Odd): 0, 15; 0, 3, DataLength 3, 0x78 0x56 0x34.
     * Partial of 4 (Multi): 0, 24; 0, 7, 12, "a", 0, "bc", 0, 0.
     * Full, aligned to 64 bits, of 2 (Odd): 0, 35; 0, 3, DataOffset
     *   32, DataLength 3, NameLength 6, "Odd", 6 bytes untouched, data.
     * Partial, aligned to 64 bits, of 1 (Text): 0, 14; type 1,
     *   DataLength 6, data: this class has no TitleIndex.
     * Class 5 (layer) of 0: a guess: 0xC000000D.
     * Class 6 of 0: 0xC000000D: there is no such class.
     * Full of 5: 0x8000001A. */
    MARK(0x21);
    NkcValueInfo(Log, Key, NULL, 1, KeyValueFullInformation, sizeof(NkcRoom), NKC_VALUE_FULL);
    NkcValueInfo(Log, Key, NULL, 3, KeyValueFullInformation, sizeof(NkcRoom), NKC_VALUE_FULL);
    NkcValueInfo(Log, Key, NULL, 2, KeyValuePartialInformation, sizeof(NkcRoom),
                 NKC_VALUE_PARTIAL);
    NkcValueInfo(Log, Key, NULL, 4, KeyValuePartialInformation, sizeof(NkcRoom),
                 NKC_VALUE_PARTIAL);
    NkcValueInfo(Log, Key, NULL, 2, KeyValueFullInformationAlign64, sizeof(NkcRoom),
                 NKC_VALUE_FULL);
    NkcValueInfo(Log, Key, NULL, 1, KeyValuePartialInformationAlign64, sizeof(NkcRoom),
                 NKC_VALUE_PARTIAL64);
    NkcValueInfo(Log, Key, NULL, 0, 5, sizeof(NkcRoom), 0);
    NkcValueInfo(Log, Key, NULL, 0, 6, sizeof(NkcRoom), 0);
    NkcValueInfo(Log, Key, NULL, 5, KeyValueFullInformation, sizeof(NkcRoom), NKC_VALUE_FULL);

    /* Too little room, enumerating value 0 (Number). Status and length;
     * where the fixed part fitted (0x80000005), the fixed part too.
     * Basic, room 0, 11, 12, 23: 0xC0000023 24; 0xC0000023 24;
     *   0x80000005 24 and 0, 4, 12; the same.
     * Full, room 0, 19, 20, 35: 0xC0000023 36; 0xC0000023 36;
     *   0x80000005 36 and 0, 4, DataOffset 32, DataLength 4,
     *   NameLength 12; the same: the offset is given even when the
     *   data did not fit.
     * Partial, room 0, 11, 12, 15: 0xC0000023 16; 0xC0000023 16;
     *   0x80000005 16 and 0, 4, 4; the same.
     * Partial aligned, room 0, 7, 8, 11: 0xC0000023 12; 0xC0000023 12;
     *   0x80000005 12 and 4, 4; the same. */
    MARK(0x22);
    NkcValueInfo(Log, Key, NULL, 0, KeyValueBasicInformation, 0, NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, NULL, 0, KeyValueBasicInformation, 11, NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, NULL, 0, KeyValueBasicInformation, 12, NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, NULL, 0, KeyValueBasicInformation, 23, NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, NULL, 0, KeyValueFullInformation, 0, NKC_VALUE_FULL);
    NkcValueInfo(Log, Key, NULL, 0, KeyValueFullInformation, 19, NKC_VALUE_FULL);
    NkcValueInfo(Log, Key, NULL, 0, KeyValueFullInformation, 20, NKC_VALUE_FULL);
    NkcValueInfo(Log, Key, NULL, 0, KeyValueFullInformation, 35, NKC_VALUE_FULL);
    NkcValueInfo(Log, Key, NULL, 0, KeyValuePartialInformation, 0, NKC_VALUE_PARTIAL);
    NkcValueInfo(Log, Key, NULL, 0, KeyValuePartialInformation, 11, NKC_VALUE_PARTIAL);
    NkcValueInfo(Log, Key, NULL, 0, KeyValuePartialInformation, 12, NKC_VALUE_PARTIAL);
    NkcValueInfo(Log, Key, NULL, 0, KeyValuePartialInformation, 15, NKC_VALUE_PARTIAL);
    NkcValueInfo(Log, Key, NULL, 0, KeyValuePartialInformationAlign64, 0, NKC_VALUE_PARTIAL64);
    NkcValueInfo(Log, Key, NULL, 0, KeyValuePartialInformationAlign64, 7, NKC_VALUE_PARTIAL64);
    NkcValueInfo(Log, Key, NULL, 0, KeyValuePartialInformationAlign64, 8, NKC_VALUE_PARTIAL64);
    NkcValueInfo(Log, Key, NULL, 0, KeyValuePartialInformationAlign64, 11, NKC_VALUE_PARTIAL64);

    /* ZwQueryValueKey in the classes the list above does not use, by a
     * name in other letter case: the name comes back as it was set.
     * Basic of TEXT: 0, 20; 0, 1, 8, "Text".
     * Basic with room 0, 11, 12, 19: 0xC0000023 20; 0xC0000023 20;
     *   0x80000005 20 and 0, 1, 8; the same.
     * Full aligned of ODD: 0, 35; as enumerated.
     * Partial aligned of TEXT: 0, 14; as enumerated.
     * Partial aligned with room 0, 7, 8: 0xC0000023 14; 0xC0000023 14;
     *   0x80000005 14 and 1, 6.
     * Basic of the unnamed value: 0, 12; 0, 1, 0.
     * Class 5 and class 6 of Text: as enumerated.
     * Basic of a value that is not there: 0xC0000034, length untouched. */
    MARK(0x23);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValueBasicInformation, sizeof(NkcRoom),
                 NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValueBasicInformation, 0, NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValueBasicInformation, 11, NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValueBasicInformation, 12, NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValueBasicInformation, 19, NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, L"ODD", 0, KeyValueFullInformationAlign64, sizeof(NkcRoom),
                 NKC_VALUE_FULL);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValuePartialInformationAlign64, sizeof(NkcRoom),
                 NKC_VALUE_PARTIAL64);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValuePartialInformationAlign64, 0,
                 NKC_VALUE_PARTIAL64);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValuePartialInformationAlign64, 7,
                 NKC_VALUE_PARTIAL64);
    NkcValueInfo(Log, Key, L"TEXT", 0, KeyValuePartialInformationAlign64, 8,
                 NKC_VALUE_PARTIAL64);
    NkcValueInfo(Log, Key, L"", 0, KeyValueBasicInformation, sizeof(NkcRoom), NKC_VALUE_BASIC);
    NkcValueInfo(Log, Key, L"Text", 0, 5, sizeof(NkcRoom), 0);
    NkcValueInfo(Log, Key, L"Text", 0, 6, sizeof(NkcRoom), 0);
    NkcValueInfo(Log, Key, L"Absent", 0, KeyValueBasicInformation, sizeof(NkcRoom),
                 NKC_VALUE_BASIC);

    /* ZwDeleteValueKey.
     * 0: a value is deleted, by a name in other letter case.
     * 0xC0000034: it cannot be deleted twice.
     * 0xC0000034: nor can a value that never was.
     * 0, 20; 0, 1, 8, "Text": the value after it has moved up to its
     * place in the order.
     * 0, 36; ..., Values 4, MaxValueNameLen 12, MaxValueDataLen 12, ...:
     * the key has four values.
     * 0, 0, then 0, 18; 0, 3, 6, "Odd": deleted and set again, Odd is
     * the last value. */
    MARK(0x24);
    RtlInitUnicodeString(&Name, L"NUMBER");
    NkcPut(Log, (ULONG)ZwDeleteValueKey(Key, &Name));
    NkcPut(Log, (ULONG)ZwDeleteValueKey(Key, &Name));
    RtlInitUnicodeString(&Name, L"Absent");
    NkcPut(Log, (ULONG)ZwDeleteValueKey(Key, &Name));
    NkcValueInfo(Log, Key, NULL, 0, KeyValueBasicInformation, sizeof(NkcRoom), NKC_VALUE_BASIC);
    NkcKeyInfo(Log, Key, -1, KeyCachedInformation, sizeof(NkcRoom), 8, NKC_KEY_CACHED);
    RtlInitUnicodeString(&Name, L"Odd");
    NkcPut(Log, (ULONG)ZwDeleteValueKey(Key, &Name));
    NkcPut(Log, (ULONG)NkcSet(Key, L"Odd", REG_BINARY, &Number, 3));
    NkcValueInfo(Log, Key, NULL, 3, KeyValueBasicInformation, sizeof(NkcRoom), NKC_VALUE_BASIC);
}

/* ---- RtlQueryRegistryValues and RtlQueryRegistryValuesEx ---------------- */

/* Windows has both exports and the kit a declaration of each; this
 * driver calls each by its own name. */
#ifdef RtlQueryRegistryValues
#undef RtlQueryRegistryValues
#endif

#define NKC_PLAIN 0 /* RtlQueryRegistryValues */
#define NKC_EX 1    /* RtlQueryRegistryValuesEx */

static NTSTATUS NkcQueryTable(ULONG Which, ULONG RelativeTo, PCWSTR Path,
                              PRTL_QUERY_REGISTRY_TABLE Table, PVOID Context, PVOID Environment)
{
    if (Which == NKC_PLAIN) {
        return RtlQueryRegistryValues(RelativeTo, Path, Table, Context, Environment);
    }
    return RtlQueryRegistryValuesEx(RelativeTo, Path, Table, Context, Environment);
}

/* The environment REG_EXPAND_SZ values are expanded from: one variable. */
static WCHAR NkcEnvironment[] = L"NKVAR=value\0";

/* A table of up to four entries and its terminator. */
typedef struct _NKC_TABLE {
    RTL_QUERY_REGISTRY_TABLE Entry[5];
} NKC_TABLE;

/* Entry `Index`: store value `Name` where `Target` points. `Expect` is
 * the type the value must have (RTL_QUERY_REGISTRY_TYPECHECK); the
 * entry has no default. */
static VOID NkcDirect(NKC_TABLE *Table, ULONG Index, ULONG Flags, PWSTR Name, PVOID Target,
                      ULONG Expect)
{
    PRTL_QUERY_REGISTRY_TABLE Entry = &Table->Entry[Index];

    Entry->QueryRoutine = NULL;
    Entry->Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK | Flags;
    Entry->Name = Name;
    Entry->EntryContext = Target;
    Entry->DefaultType = (Expect << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    Entry->DefaultData = NULL;
    Entry->DefaultLength = 0;
}

/* Run a one-entry table on the test key, by its full name. */
static NTSTATUS NkcOne(ULONG Which, NKC_TABLE *Table)
{
    return NkcQueryTable(Which, RTL_REGISTRY_ABSOLUTE, NKC_KEY, Table->Entry, NULL,
                         NkcEnvironment);
}

/* Log a string a query stored: its length and room in bytes, then its
 * text; all ones if it has no buffer. Free the buffer if the query
 * allocated it. */
static VOID NkcStored(NKC_LOG *Log, PUNICODE_STRING String, BOOLEAN Allocated)
{
    if (String->Buffer == NULL) {
        NkcPut(Log, 0xFFFFFFFF);
        return;
    }
    NkcPut(Log, String->Length);
    NkcPut(Log, String->MaximumLength);
    NkcPutBytes(Log, (PUCHAR)String->Buffer, String->Length);
    if (Allocated) {
        ExFreePool(String->Buffer);
    }
    String->Buffer = NULL;
    String->Length = String->MaximumLength = 0;
}

static VOID NkcQueryDirect(NKC_LOG *Log, HANDLE Key, ULONG Which)
{
    static ULONGLONG Qword = 0x1122334455667788;
    static WCHAR Expand[] = L"%NKVAR%\\x%NOPE%";
    static WCHAR DefaultText[] = L"dflt";
    static ULONG DefaultNumber = 0xDEFA0017;
    NKC_TABLE Table;
    UNICODE_STRING String, Strings[3];
    WCHAR Small[3];
    ULONG Number, Buffer[6], i;
    UNICODE_STRING Name;

    NkcSet(Key, L"Number", REG_DWORD, &Qword, sizeof(ULONG));
    NkcSet(Key, L"Qword", REG_QWORD, &Qword, sizeof(Qword));
    NkcSet(Key, L"Expand", REG_EXPAND_SZ, Expand, sizeof(Expand));
    RtlZeroMemory(&Table, sizeof(Table));

    /* 0, 0x55667788: a REG_DWORD is stored in the ULONG pointed at. */
    Number = 0xEEEEEEEE;
    NkcDirect(&Table, 0, 0, L"Number", &Number, REG_DWORD);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcPut(Log, Number);

    /* 0, 0xEE345678: three bytes of REG_BINARY are stored the same way,
     * and the fourth byte left alone. */
    Number = 0xEEEEEEEE;
    NkcDirect(&Table, 0, 0, L"Odd", &Number, REG_BINARY);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcPut(Log, Number);

    /* Data of more than four bytes go to a buffer whose first word is
     * its size.
     * 0; 8, 11, 0x55667788, 0x11223344, 0xEEEEEEEE: a positive size:
     * the data's length, its type, the data.
     * 0; 0x55667788, 0x11223344, 0xEEEEEEEE: a negative size: the data
     * alone.
     * 0xC0000023: a size too small for length, type and data. */
    RtlFillMemory(Buffer, sizeof(Buffer), 0xEE);
    Buffer[0] = sizeof(Buffer);
    NkcDirect(&Table, 0, 0, L"Qword", Buffer, REG_QWORD);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    for (i = 0; i < 5; i++) {
        NkcPut(Log, Buffer[i]);
    }
    RtlFillMemory(Buffer, sizeof(Buffer), 0xEE);
    Buffer[0] = (ULONG)(-(LONG)sizeof(Buffer));
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    for (i = 0; i < 3; i++) {
        NkcPut(Log, Buffer[i]);
    }
    RtlFillMemory(Buffer, sizeof(Buffer), 0xEE);
    Buffer[0] = 12;
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));

    /* 0; 4, 6, "nk": a REG_SZ is stored in a UNICODE_STRING; one
     * without a buffer is given one, with room for the terminator.
     * 0; 4, 6, "nk": a buffer of the caller's with just that room is
     * used.
     * 0xC0000023: one without room for the terminator is too small. */
    RtlZeroMemory(&String, sizeof(String));
    NkcDirect(&Table, 0, 0, L"Text", &String, REG_SZ);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcStored(Log, &String, TRUE);
    String.Buffer = Small;
    String.Length = 0;
    String.MaximumLength = sizeof(Small);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcStored(Log, &String, FALSE);
    String.Buffer = Small;
    String.Length = 0;
    String.MaximumLength = sizeof(Small) - sizeof(WCHAR);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));

    /* 0; 26, 28, "value\x%NOPE%": a REG_EXPAND_SZ is expanded from the
     * environment given; a variable it has not stays as written.
     * 0; 30, 32, "%NKVAR%\x%NOPE%": with RTL_QUERY_REGISTRY_NOEXPAND it
     * is stored as it is. (That the type expected is that of the
     * value as stored, in both cases, is a guess.) */
    RtlZeroMemory(&String, sizeof(String));
    NkcDirect(&Table, 0, 0, L"Expand", &String, REG_EXPAND_SZ);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcStored(Log, &String, TRUE);
    NkcDirect(&Table, 0, RTL_QUERY_REGISTRY_NOEXPAND, L"Expand", &String, REG_EXPAND_SZ);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcStored(Log, &String, TRUE);

    /* 0; 10, 12, "a", 0, "bc", 0: a REG_MULTI_SZ with NOEXPAND is one
     * string, its last terminator not counted.
     * 0; 2, 4, "a"; 4, 6, "bc"; all ones: without NOEXPAND each of its
     * strings is stored in the next UNICODE_STRING of an array (a
     * guess). */
    RtlZeroMemory(&String, sizeof(String));
    NkcDirect(&Table, 0, RTL_QUERY_REGISTRY_NOEXPAND, L"Multi", &String, REG_MULTI_SZ);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcStored(Log, &String, TRUE);
    RtlZeroMemory(Strings, sizeof(Strings));
    NkcDirect(&Table, 0, 0, L"Multi", Strings, REG_MULTI_SZ);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    for (i = 0; i < 3; i++) {
        NkcStored(Log, &Strings[i], TRUE);
    }

    /* 0xC0000024, 0xEEEEEEEE: a value of another type than the entry
     * expects: STATUS_OBJECT_TYPE_MISMATCH, and nothing stored. */
    Number = 0xEEEEEEEE;
    NkcDirect(&Table, 0, 0, L"Text", &Number, REG_DWORD);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcPut(Log, Number);

    /* A value that is not there.
     * 0xC0000034: with RTL_QUERY_REGISTRY_REQUIRED.
     * 0, 0xEEEEEEEE: without, and without a default: nothing stored.
     * 0, 0xDEFA0017: with a REG_DWORD default, that is stored.
     * 0; 8, 10, "dflt": a REG_SZ default of length 0 is measured. */
    Number = 0xEEEEEEEE;
    NkcDirect(&Table, 0, RTL_QUERY_REGISTRY_REQUIRED, L"Absent", &Number, REG_DWORD);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcDirect(&Table, 0, 0, L"Absent", &Number, REG_DWORD);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcPut(Log, Number);
    Table.Entry[0].DefaultType |= REG_DWORD;
    Table.Entry[0].DefaultData = &DefaultNumber;
    Table.Entry[0].DefaultLength = sizeof(DefaultNumber);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcPut(Log, Number);
    RtlZeroMemory(&String, sizeof(String));
    NkcDirect(&Table, 0, 0, L"Absent", &String, REG_SZ);
    Table.Entry[0].DefaultType |= REG_SZ;
    Table.Entry[0].DefaultData = DefaultText;
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcStored(Log, &String, TRUE);

    /* Subkeys. 0; 5, 3, 0x04030201, 0xEEEEEE05; 0x55667788: an entry
     * with RTL_QUERY_REGISTRY_SUBKEY names a subkey, the next entry
     * reads Val there, and one with RTL_QUERY_REGISTRY_TOPKEY reads
     * Number of the key the call named.
     * 0xC0000034: a subkey that is not there. */
    RtlFillMemory(Buffer, sizeof(Buffer), 0xEE);
    Buffer[0] = sizeof(Buffer);
    Number = 0xEEEEEEEE;
    RtlZeroMemory(&Table, sizeof(Table));
    Table.Entry[0].Flags = RTL_QUERY_REGISTRY_SUBKEY;
    Table.Entry[0].Name = L"Beta";
    NkcDirect(&Table, 1, 0, L"Val", Buffer, REG_BINARY);
    NkcDirect(&Table, 2, RTL_QUERY_REGISTRY_TOPKEY, L"Number", &Number, REG_DWORD);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    for (i = 0; i < 4; i++) {
        NkcPut(Log, Buffer[i]);
    }
    NkcPut(Log, Number);
    Table.Entry[0].Name = L"NoSuchKey";
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));

    /* 0, 0x55667788, 0xC0000034: with RTL_QUERY_REGISTRY_DELETE the
     * value is stored and then deleted. */
    NkcSet(Key, L"Temp", REG_DWORD, &Qword, sizeof(ULONG));
    Number = 0xEEEEEEEE;
    RtlZeroMemory(&Table, sizeof(Table));
    NkcDirect(&Table, 0, RTL_QUERY_REGISTRY_DELETE, L"Temp", &Number, REG_DWORD);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcPut(Log, Number);
    RtlInitUnicodeString(&Name, L"Temp");
    NkcPut(Log, (ULONG)ZwDeleteValueKey(Key, &Name));

    /* 0xC000000D: an entry that stores directly cannot also name a
     * subkey. */
    NkcDirect(&Table, 0, RTL_QUERY_REGISTRY_SUBKEY, L"Beta", &Number, REG_DWORD);
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));

    /* Without RTL_QUERY_REGISTRY_TYPECHECK, as drivers written before
     * it do, in a hive the system trusts:
     * 0, 0x55667788: the number. 0; 4, 6, "nk": the string. */
    Number = 0xEEEEEEEE;
    RtlZeroMemory(&Table, sizeof(Table));
    Table.Entry[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    Table.Entry[0].Name = L"Number";
    Table.Entry[0].EntryContext = &Number;
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcPut(Log, Number);
    RtlZeroMemory(&String, sizeof(String));
    Table.Entry[0].Name = L"Text";
    Table.Entry[0].EntryContext = &String;
    NkcPut(Log, (ULONG)NkcOne(Which, &Table));
    NkcStored(Log, &String, TRUE);
}

/* What the routine is told to answer, by the entry's context. */
#define NKC_ANSWER_OK 0x100
#define NKC_ANSWER_FAIL 0x200  /* STATUS_UNSUCCESSFUL */
#define NKC_ANSWER_SMALL 0x300 /* STATUS_BUFFER_TOO_SMALL */

/* A query routine. Logs six values: a mark; the type; the length; the
 * value name's first character (0xFFFF: no name); the data's first four
 * bytes (fewer: filled with 0xFF; all ones and a zero length: no data);
 * the entry's context. */
static NTSTATUS NTAPI NkcRoutine(PWSTR ValueName, ULONG ValueType, PVOID ValueData,
                                 ULONG ValueLength, PVOID Context, PVOID EntryContext)
{
    NKC_LOG *Log = (NKC_LOG *)Context;
    ULONG Answer = (ULONG)(ULONG_PTR)EntryContext;

    MARK(0xC0);
    NkcPut(Log, ValueType);
    NkcPut(Log, ValueLength);
    NkcPut(Log, ValueName == NULL ? 0xFFFF : ValueName[0]);
    if (ValueData == NULL || ValueLength == 0) {
        NkcPut(Log, 0xFFFFFFFF);
    } else {
        NkcPutBytes(Log, (PUCHAR)ValueData, ValueLength < 4 ? ValueLength : 4);
    }
    NkcPut(Log, Answer);
    switch (Answer & 0xF00) {
    case NKC_ANSWER_FAIL:
        return STATUS_UNSUCCESSFUL;
    case NKC_ANSWER_SMALL:
        return STATUS_BUFFER_TOO_SMALL;
    default:
        return STATUS_SUCCESS;
    }
}

/* Entry `Index`: call the routine for value `Name`, with `Tag` as the
 * entry's context. */
static VOID NkcCall(NKC_TABLE *Table, ULONG Index, ULONG Flags, PWSTR Name, ULONG Tag)
{
    PRTL_QUERY_REGISTRY_TABLE Entry = &Table->Entry[Index];

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->QueryRoutine = NkcRoutine;
    Entry->Flags = Flags;
    Entry->Name = Name;
    Entry->EntryContext = (PVOID)(ULONG_PTR)Tag;
}

static VOID NkcQueryRoutine(NKC_LOG *Log, ULONG Which)
{
    static WCHAR DefaultText[] = L"dflt";
    NKC_TABLE Table;
    ULONG Number;

#define NKC_RUN() \
    NkcPut(Log, (ULONG)NkcQueryTable(Which, RTL_REGISTRY_ABSOLUTE, NKC_KEY, Table.Entry, Log, \
                                     NkcEnvironment))

    RtlZeroMemory(&Table, sizeof(Table));

    /* Each call of the routine logs: mark, type, length, the name's
     * first letter, the data's first bytes, the entry's context.
     * One call: 4, 4, 'N', 0x55667788, 0x101. Then the status, 0. */
    NkcCall(&Table, 0, 0, L"Number", NKC_ANSWER_OK | 1);
    NKC_RUN();

    /* One call: 1, 6, 'T', "nk", 0x102: a string's length counts its
     * terminator. 0. */
    NkcCall(&Table, 0, 0, L"Text", NKC_ANSWER_OK | 2);
    NKC_RUN();

    /* Two calls, one for each string of the REG_MULTI_SZ, each as a
     * REG_SZ: 1, 4, 'M', "a" and terminator, 0x103; 1, 6, 'M', "bc",
     * 0x103. 0. */
    NkcCall(&Table, 0, 0, L"Multi", NKC_ANSWER_OK | 3);
    NKC_RUN();

    /* One call with NOEXPAND: 7, 12, 'M', "a", 0, 0x104. 0. */
    NkcCall(&Table, 0, RTL_QUERY_REGISTRY_NOEXPAND, L"Multi", NKC_ANSWER_OK | 4);
    NKC_RUN();

    /* One call: the REG_EXPAND_SZ expanded, as a REG_SZ (a guess; or
     * still type 2): 1, 28, 'E', "va", 0x105. 0.
     * One call with NOEXPAND: 2, 32, 'E', "%N", 0x106. 0. */
    NkcCall(&Table, 0, 0, L"Expand", NKC_ANSWER_OK | 5);
    NKC_RUN();
    NkcCall(&Table, 0, RTL_QUERY_REGISTRY_NOEXPAND, L"Expand", NKC_ANSWER_OK | 6);
    NKC_RUN();

    /* A value that is not there.
     * No call, 0: no default.
     * No call, 0xC0000034: required.
     * One call with the entry's default: 1, 10, 'A', "df", 0x109; 0
     * (the length measured, terminator counted). */
    NkcCall(&Table, 0, 0, L"Absent", NKC_ANSWER_OK | 7);
    NKC_RUN();
    NkcCall(&Table, 0, RTL_QUERY_REGISTRY_REQUIRED, L"Absent", NKC_ANSWER_OK | 8);
    NKC_RUN();
    NkcCall(&Table, 0, 0, L"Absent", NKC_ANSWER_OK | 9);
    Table.Entry[0].DefaultType = REG_SZ;
    Table.Entry[0].DefaultData = DefaultText;
    NKC_RUN();

    /* The routine's status.
     * One call, then 0xC0000001: a failure ends the query with it, and
     * the entry after it is not reached.
     * Two calls, then 0: STATUS_BUFFER_TOO_SMALL from the routine is
     * not taken for a failure (a guess: the second entry is reached). */
    NkcCall(&Table, 0, 0, L"Number", NKC_ANSWER_FAIL | 1);
    NkcCall(&Table, 1, 0, L"Text", NKC_ANSWER_OK | 0x11);
    NKC_RUN();
    NkcCall(&Table, 0, 0, L"Number", NKC_ANSWER_SMALL | 1);
    NKC_RUN();
    RtlZeroMemory(&Table, sizeof(Table));

    /* An entry without a name: the routine is called for every value
     * of the key, in the key's order, each by its own name. Eight
     * calls (Text, the unnamed value, Multi's two strings, Odd, Number,
     * Qword, Expand): types, lengths and names 1 6 'T'; 1 4 and a name
     * whose first character is its terminator, 0; 1 4 'M'; 1 6 'M';
     * 3 3 'O'; 4 4 'N'; 11 8 'Q'; 1 28 'E'. 0.
     * With RTL_QUERY_REGISTRY_NOVALUE: one call: 0, 0, no name, no
     * data, 0x122. 0. */
    NkcCall(&Table, 0, 0, NULL, NKC_ANSWER_OK | 0x21);
    NKC_RUN();
    NkcCall(&Table, 0, RTL_QUERY_REGISTRY_NOVALUE, NULL, NKC_ANSWER_OK | 0x22);
    NKC_RUN();

    /* A subkey entry with a routine and no value named after it: the
     * routine is called for every value of the subkey: 3, 5, 'V',
     * 0x04030201, 0x123. 0. */
    NkcCall(&Table, 0, RTL_QUERY_REGISTRY_SUBKEY, L"Beta", NKC_ANSWER_OK | 0x23);
    NKC_RUN();

    /* 0xC000000D, and no call: an entry with both a routine and
     * RTL_QUERY_REGISTRY_DIRECT. */
    Number = 0xEEEEEEEE;
    NkcCall(&Table, 0, RTL_QUERY_REGISTRY_DIRECT, L"Number", NKC_ANSWER_OK | 0x24);
    Table.Entry[0].EntryContext = &Number;
    NKC_RUN();
#undef NKC_RUN
}

static VOID NkcQueryRoots(NKC_LOG *Log, HANDLE Key, ULONG Which)
{
    NKC_TABLE Table;
    ULONG Number;
    HANDLE Control;
    ULONG Seven = 7;

    RtlZeroMemory(&Table, sizeof(Table));
    NkcDirect(&Table, 0, RTL_QUERY_REGISTRY_REQUIRED, L"Number", &Number, REG_DWORD);

    /* What the path is relative to.
     * 0, 0x55667788: RTL_REGISTRY_SERVICES and "nkc-reg\NkcTest".
     * 0, 0x55667788: RTL_REGISTRY_HANDLE and the key's handle.
     * 0xC0000034: RTL_REGISTRY_ABSOLUTE and a key that is not there.
     * The same with RTL_REGISTRY_OPTIONAL: a guess: 0xC0000034 too, as
     * the value is required.
     * 0xC0000034: RTL_REGISTRY_SERVICES and a service that is not there.
     * 0xC000000D: a root there is none of (99). */
    Number = 0xEEEEEEEE;
    NkcPut(Log, (ULONG)NkcQueryTable(Which, RTL_REGISTRY_SERVICES, L"nkc-reg\\NkcTest",
                                     Table.Entry, NULL, NULL));
    NkcPut(Log, Number);
    Number = 0xEEEEEEEE;
    NkcPut(Log, (ULONG)NkcQueryTable(Which, RTL_REGISTRY_HANDLE, (PCWSTR)Key, Table.Entry, NULL,
                                     NULL));
    NkcPut(Log, Number);
    NkcPut(Log, (ULONG)NkcQueryTable(Which, RTL_REGISTRY_ABSOLUTE, NKC_KEY L"\\NoSuchKey",
                                     Table.Entry, NULL, NULL));
    NkcPut(Log, (ULONG)NkcQueryTable(Which, RTL_REGISTRY_ABSOLUTE | RTL_REGISTRY_OPTIONAL,
                                     NKC_KEY L"\\NoSuchKey", Table.Entry, NULL, NULL));
    NkcPut(Log, (ULONG)NkcQueryTable(Which, RTL_REGISTRY_SERVICES, L"nkc-no-such-service",
                                     Table.Entry, NULL, NULL));
    NkcPut(Log, (ULONG)NkcQueryTable(Which, 99, L"nkc-reg", Table.Entry, NULL, NULL));

    /* 0; then 0, 7: RTL_REGISTRY_CONTROL and the name of a key this
     * driver makes under Control for the purpose, and deletes: 0. */
    NkcPut(Log, (ULONG)NkcChild(NULL, NKC_CONTROL_KEY, NULL, &Control));
    if (Control != NULL) {
        NkcSet(Control, L"Number", REG_DWORD, &Seven, sizeof(Seven));
        Number = 0xEEEEEEEE;
        NkcPut(Log, (ULONG)NkcQueryTable(Which, RTL_REGISTRY_CONTROL, L"NkcRegTest", Table.Entry,
                                         NULL, NULL));
        NkcPut(Log, Number);
        NkcPut(Log, (ULONG)ZwDeleteKey(Control));
        ZwClose(Control);
    }
}

static VOID NkcMore(NKC_LOG *Log)
{
    HANDLE Key, Beta;
    ULONG Which;

    /* 0: the key and what is under it are made. */
    MARK(0x01);
    NkcPut(Log, (ULONG)NkcBuild(&Key));
    if (Key == NULL) {
        return;
    }
    NkcKeys(Log, Key);
    NkcValues(Log, Key);

    /* The query tables, first through RtlQueryRegistryValues, then
     * through RtlQueryRegistryValuesEx: the two lists are the same. */
    for (Which = NKC_PLAIN; Which <= NKC_EX; Which++) {
        MARK(0x30 + Which);
        NkcQueryDirect(Log, Key, Which);
        MARK(0x40 + Which);
        NkcQueryRoutine(Log, Which);
        MARK(0x50 + Which);
        NkcQueryRoots(Log, Key, Which);
    }

    /* 0xC0000121 (STATUS_CANNOT_DELETE): a key that has subkeys.
     * 0, 0, 0, 0: the subkeys are deleted, innermost first.
     * 0, 0, 0xC0000034: then the key; it is gone.
     * 0xC0000034: so is the key under Control. */
    MARK(0x02);
    NkcPut(Log, (ULONG)ZwDeleteKey(Key));
    if (NT_SUCCESS(NkcChild(Key, L"Beta", NULL, &Beta))) {
        NkcPut(Log, (ULONG)NkcRemove(Beta, L"Sub"));
        ZwClose(Beta);
    }
    NkcPut(Log, (ULONG)NkcRemove(Key, L"Beta"));
    NkcPut(Log, (ULONG)NkcRemove(Key, L"alpha"));
    NkcPut(Log, (ULONG)NkcRemove(Key, L"Gamma9"));
    NkcPut(Log, (ULONG)ZwDeleteKey(Key));
    NkcPut(Log, (ULONG)ZwClose(Key));
    NkcPut(Log, (ULONG)NkcOpen(NKC_KEY, FALSE, &Key, NULL));
    NkcPut(Log, (ULONG)NkcOpen(NKC_CONTROL_KEY, FALSE, &Key, NULL));

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
