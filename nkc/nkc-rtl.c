/*
 * Conformance: the run-time library, as Microsoft's file systems use it.
 *
 * The C run-time string routines the kernel exports, formatted output,
 * counted strings and code-page conversion, SIDs, access lists and
 * descriptors, the Unicode prefix table, wildcard matching of file
 * names, and the table of characters legal in a file name.
 *
 * The list is in that order, one routine of this file per group, each
 * starting with a mark, NKC_MARK | n. A comment before each group of
 * NkcPut calls says what Windows is predicted to answer; where the
 * prediction is a guess it says so. Text is logged two characters to a
 * value, the first in the low half, an odd end filled with 0xFFFF;
 * bytes four to a value, filled with 0xFF.
 *
 * Tables too large for the list have device-control codes of their own.
 * Each returns raw data, not a list, and needs an output buffer of
 * exactly the size given or more (STATUS_BUFFER_TOO_SMALL otherwise):
 *
 *   0x222800 + 4 * n, n = 0..15   8192 bytes: RtlUpcaseUnicodeChar of
 *                                 the 4096 characters from n * 4096, as
 *                                 16-bit values
 *   0x222840                      512 bytes: what RtlMultiByteToUnicodeN
 *                                 makes of each byte 0x00..0xFF alone,
 *                                 as 16-bit values (0xFFFF: the status
 *                                 was not success, or no character
 *                                 came out)
 *   0x222880 + 4 * n, n = 0..15   4096 bytes: the first byte that
 *                                 RtlUnicodeToMultiByteN makes of each
 *                                 of the 4096 characters from n * 4096
 *                                 alone (0: nothing came out)
 *
 * The code-page tables are those of the system's ANSI code page, which
 * is the machine's setting: 1252 on a United States installation.
 *
 * So that the compiler cannot answer for the kernel, the C run-time
 * routines are called through pointers it must read from memory.
 *
 * No routine from nkc-undoc.h is used: all of these are declared by the
 * kit's headers.
 */

/* The routines for file systems are declared by <ntifs.h>, which must
 * come before <ntddk.h>. The kernel's C run-time routines are those of
 * old: no warning about them is wanted. */
#define _CRT_SECURE_NO_WARNINGS
#include <ntifs.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#pragma warning(disable : 4996)

#define NKC_DEVICE L"\\Device\\NkcRtl"
#define NKC_IRP_CONTROL
#include "nkc.h"

#define NKC_MARK 0x57000000u
#define MARK(n) NkcPut(Log, NKC_MARK | (n))

#define NKC_FN(n) CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA00 + (n), METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NKC_IOCTL_UPCASE NKC_FN(0x00)  /* to NKC_FN(0x0F) */
#define NKC_IOCTL_TO_WIDE NKC_FN(0x10)
#define NKC_IOCTL_TO_ANSI NKC_FN(0x20) /* to NKC_FN(0x2F) */
#define NKC_CHUNK 4096

#define NKC_POOL_TAG 'trNN'

static ULONG NkcBool(BOOLEAN Value)
{
    return (ULONG)(UCHAR)Value;
}

/* Text, two characters to a value. */
static VOID NkcPutWide(NKC_LOG *Log, const WCHAR *Text, ULONG Count)
{
    ULONG i;

    for (i = 0; i < Count; i += 2) {
        NkcPut(Log, (ULONG)Text[i] | ((i + 1 < Count ? (ULONG)Text[i + 1] : 0xFFFFu) << 16));
    }
}

/* Bytes, four to a value. */
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

/* ---- The tables with control codes of their own ------------------------- */

/* What RtlMultiByteToUnicodeN makes of one byte. */
static USHORT NkcToWide(UCHAR Byte)
{
    WCHAR Wide[2] = {0xFFFF, 0xFFFF};
    ULONG Bytes = 0;
    CHAR Narrow = (CHAR)Byte;

    if (RtlMultiByteToUnicodeN(Wide, sizeof(WCHAR), &Bytes, &Narrow, 1) != STATUS_SUCCESS ||
        Bytes != sizeof(WCHAR)) {
        return 0xFFFF;
    }
    return Wide[0];
}

/* The first byte RtlUnicodeToMultiByteN makes of one character. */
static UCHAR NkcToAnsi(WCHAR Wide)
{
    CHAR Narrow[4] = {0, 0, 0, 0};
    ULONG Bytes = 0;

    if (!NT_SUCCESS(RtlUnicodeToMultiByteN(Narrow, sizeof(Narrow), &Bytes, &Wide,
                                           sizeof(WCHAR))) ||
        Bytes == 0) {
        return 0;
    }
    return (UCHAR)Narrow[0];
}

static NTSTATUS NkcIrpControl(PIRP Irp, ULONG Code)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Room = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PUCHAR Out = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG Chunk, i;

    if (Code >= NKC_IOCTL_UPCASE && Code < NKC_IOCTL_UPCASE + 4 * 16 && (Code & 3) == 0) {
        Chunk = (Code - NKC_IOCTL_UPCASE) / 4;
        if (Room < NKC_CHUNK * sizeof(USHORT)) {
            return NkcComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        for (i = 0; i < NKC_CHUNK; i++) {
            ((USHORT UNALIGNED *)Out)[i] = RtlUpcaseUnicodeChar((WCHAR)(Chunk * NKC_CHUNK + i));
        }
        return NkcComplete(Irp, STATUS_SUCCESS, NKC_CHUNK * sizeof(USHORT));
    }
    if (Code == NKC_IOCTL_TO_WIDE) {
        if (Room < 256 * sizeof(USHORT)) {
            return NkcComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        for (i = 0; i < 256; i++) {
            ((USHORT UNALIGNED *)Out)[i] = NkcToWide((UCHAR)i);
        }
        return NkcComplete(Irp, STATUS_SUCCESS, 256 * sizeof(USHORT));
    }
    if (Code >= NKC_IOCTL_TO_ANSI && Code < NKC_IOCTL_TO_ANSI + 4 * 16 && (Code & 3) == 0) {
        Chunk = (Code - NKC_IOCTL_TO_ANSI) / 4;
        if (Room < NKC_CHUNK) {
            return NkcComplete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        for (i = 0; i < NKC_CHUNK; i++) {
            Out[i] = NkcToAnsi((WCHAR)(Chunk * NKC_CHUNK + i));
        }
        return NkcComplete(Irp, STATUS_SUCCESS, NKC_CHUNK);
    }
    return NkcComplete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

/* ---- The C run-time string routines ------------------------------------- */

/* Where in `Base` a pointer the routine returned is; all ones for NULL. */
#define NKC_AT(p, base) ((p) == NULL ? 0xFFFFFFFFu : (ULONG)((p) - (base)))

static VOID NkcCrt(NKC_LOG *Log)
{
    int (__cdecl *volatile Stricmp)(const char *, const char *) = _stricmp;
    int (__cdecl *volatile Wcsicmp)(const wchar_t *, const wchar_t *) = _wcsicmp;
    int (__cdecl *volatile Strncmp)(const char *, const char *, size_t) = strncmp;
    char *(__cdecl *volatile Strrchr)(const char *, int) = (char *(__cdecl *)(const char *, int))strrchr;
    wchar_t *(__cdecl *volatile Wcsstr)(const wchar_t *, const wchar_t *) =
        (wchar_t *(__cdecl *)(const wchar_t *, const wchar_t *))wcsstr;
    static const char Path[] = "a/b/c";
    static const WCHAR Hello[] = L"hello world";
    static const WCHAR Aaab[] = L"aaab";
    static const WCHAR EAcute[] = {0x00E9, 0};      /* small e with acute */
    static const WCHAR EAcuteBig[] = {0x00C9, 0};   /* capital E with acute */
    static const WCHAR Cyrillic[] = {0x0430, 0};    /* small a */
    static const WCHAR CyrillicBig[] = {0x0410, 0}; /* capital A */

    MARK(0x10);

    /* _stricmp. The values are the difference of the first two
     * characters that differ, as unsigned, letters A to Z made small:
     * 0: "abc" and "ABC".
     * -1: "abc", "abd". 1: "B", "a". -1: "a", "B".
     * -6: "[" against "a": '[' lies between the capitals and the small
     * letters, so the sign tells that letters are made small, not big.
     * 99: "abc", "ab". -99: "ab", "abc". 0: "", "".
     * 32: bytes 0xE9 and 0xC9: no letters to this routine.
     * 136: byte 0xE9 against "a": characters compare as unsigned. */
    NkcPut(Log, (ULONG)Stricmp("abc", "ABC"));
    NkcPut(Log, (ULONG)Stricmp("abc", "abd"));
    NkcPut(Log, (ULONG)Stricmp("B", "a"));
    NkcPut(Log, (ULONG)Stricmp("a", "B"));
    NkcPut(Log, (ULONG)Stricmp("[", "a"));
    NkcPut(Log, (ULONG)Stricmp("abc", "ab"));
    NkcPut(Log, (ULONG)Stricmp("ab", "abc"));
    NkcPut(Log, (ULONG)Stricmp("", ""));
    NkcPut(Log, (ULONG)Stricmp("\xE9", "\xC9"));
    NkcPut(Log, (ULONG)Stricmp("\xE9", "a"));

    /* _wcsicmp, the same way: 0, -1, -6, 99, -99.
     * 32, 32: U+00E9 against U+00C9, and U+0430 against U+0410: only A
     * to Z are letters to this routine (a guess).
     * 65438: U+FFFF against "a": characters compare as unsigned. */
    NkcPut(Log, (ULONG)Wcsicmp(L"abc", L"ABC"));
    NkcPut(Log, (ULONG)Wcsicmp(L"abc", L"abd"));
    NkcPut(Log, (ULONG)Wcsicmp(L"[", L"a"));
    NkcPut(Log, (ULONG)Wcsicmp(L"abc", L"ab"));
    NkcPut(Log, (ULONG)Wcsicmp(L"ab", L"abc"));
    NkcPut(Log, (ULONG)Wcsicmp(EAcute, EAcuteBig));
    NkcPut(Log, (ULONG)Wcsicmp(Cyrillic, CyrillicBig));
    NkcPut(Log, (ULONG)Wcsicmp(L"\xFFFF", L"a"));

    /* strncmp. 0: "abc", "abd" over 2. A negative number over 3: -1 (a
     * guess: the difference, as the C source of the routine gives it;
     * some builds give -1 for any "less").
     * 0: over no characters. Negative: "ab" against "abc" over 5.
     * 0: "ab", "abc" over 2. 0: equal strings, over more than they have.
     * Positive: byte 0x80 against "a": unsigned. Positive: "b", "a". */
    NkcPut(Log, (ULONG)Strncmp("abc", "abd", 2));
    NkcPut(Log, (ULONG)Strncmp("abc", "abd", 3));
    NkcPut(Log, (ULONG)Strncmp("abc", "abd", 0));
    NkcPut(Log, (ULONG)Strncmp("ab", "abc", 5));
    NkcPut(Log, (ULONG)Strncmp("ab", "abc", 2));
    NkcPut(Log, (ULONG)Strncmp("abc", "abc", 100));
    NkcPut(Log, (ULONG)Strncmp("\x80", "a", 1));
    NkcPut(Log, (ULONG)Strncmp("b", "a", 1));

    /* strrchr in "a/b/c". 3: the last '/'. All ones: no 'x'.
     * 5: the terminator is found where the string ends. 0: 'a'.
     * All ones: nothing in an empty string. 3: only the character's low
     * byte counts ('/' + 0x100). */
    NkcPut(Log, NKC_AT(Strrchr(Path, '/'), Path));
    NkcPut(Log, NKC_AT(Strrchr(Path, 'x'), Path));
    NkcPut(Log, NKC_AT(Strrchr(Path, 0), Path));
    NkcPut(Log, NKC_AT(Strrchr(Path, 'a'), Path));
    NkcPut(Log, NKC_AT(Strrchr(Path + 5, 'a'), Path));
    NkcPut(Log, NKC_AT(Strrchr(Path, '/' + 0x100), Path));

    /* wcsstr. 4: "o w" in "hello world". 0: the empty string is found
     * at the start. All ones: "xyz" is not there; nor "HELLO"; nor a
     * string longer than the one searched.
     * 1: "aab" in "aaab". 6: "world", at the end. */
    NkcPut(Log, NKC_AT(Wcsstr(Hello, L"o w"), Hello));
    NkcPut(Log, NKC_AT(Wcsstr(Hello, L""), Hello));
    NkcPut(Log, NKC_AT(Wcsstr(Hello, L"xyz"), Hello));
    NkcPut(Log, NKC_AT(Wcsstr(Hello, L"HELLO"), Hello));
    NkcPut(Log, NKC_AT(Wcsstr(Aaab, L"aaabb"), Aaab));
    NkcPut(Log, NKC_AT(Wcsstr(Aaab, L"aab"), Aaab));
    NkcPut(Log, NKC_AT(Wcsstr(Hello, L"world"), Hello));
}

/* ---- _vsnwprintf -------------------------------------------------------- */

#define NKC_TEXT 64

static WCHAR NkcText[NKC_TEXT + 1];

/* _vsnwprintf into NkcText, which is first filled with 0xEEEE, with
 * room for `Count` characters. */
static int __cdecl NkcPrint(size_t Count, const WCHAR *Format, ...)
{
    int (__cdecl *volatile Print)(wchar_t *, size_t, const wchar_t *, va_list) = _vsnwprintf;
    va_list Arguments;
    int Result;
    ULONG i;

    for (i = 0; i <= NKC_TEXT; i++) {
        NkcText[i] = 0xEEEE;
    }
    va_start(Arguments, Format);
    Result = Print(NkcText, Count, Format, Arguments);
    va_end(Arguments);
    return Result;
}

/* Log what _vsnwprintf returned, then the text: through its terminator
 * if the routine says it wrote fewer than `Count` characters, else all
 * `Count` characters of the buffer. */
static VOID NkcPrinted(NKC_LOG *Log, int Result, ULONG Count)
{
    NkcPut(Log, (ULONG)Result);
    NkcPutWide(Log, NkcText, Result < 0 || (ULONG)Result >= Count ? Count : (ULONG)Result + 1);
}

static VOID NkcFormat(NKC_LOG *Log)
{
    static WCHAR Wide[] = L"unicode";
    static CHAR Narrow[] = "ansi";
    UNICODE_STRING Unicode, Empty;
    ANSI_STRING Ansi;

    MARK(0x20);

    /* 17, "wide|narrow|ws|hs" and its terminator: in a wide format %s
     * and %ws take a wide string, %S and %hs a narrow one. */
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L"%s|%S|%ws|%hs", L"wide", "narrow", L"ws", "hs"),
               NKC_TEXT);

    /* 8, "uni|ansi": %wZ takes a UNICODE_STRING, %Z an ANSI_STRING;
     * each gives as many characters as its Length says, here three of
     * "unicode", and needs no terminator. */
    Unicode.Buffer = Wide;
    Unicode.Length = 3 * sizeof(WCHAR);
    Unicode.MaximumLength = sizeof(Wide);
    Ansi.Buffer = Narrow;
    Ansi.Length = 4;
    Ansi.MaximumLength = sizeof(Narrow);
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L"%wZ|%Z", &Unicode, &Ansi), NKC_TEXT);

    /* 37, "-5|7|4000000000|beef|BEEF|10|ffffffff". */
    NkcPrinted(Log,
               NkcPrint(NKC_TEXT, L"%d|%i|%u|%x|%X|%o|%x", -5, 7, 4000000000u, 0xBEEF, 0xBEEF, 8,
                        -1),
               NKC_TEXT);

    /* 25, "   42|42   |00042|+42| 42": width, left, zeros, sign, space. */
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L"%5d|%-5d|%05d|%+d|% d", 42, 42, 42, 42, 42), NKC_TEXT);

    /* 27, "      ab|000000AB|0xab|0XAB". */
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L"%8x|%08X|%#x|%#X", 0xAB, 0xAB, 0xAB, 0xAB), NKC_TEXT);

    /* 15, "00042|     042|": a precision is a least number of digits;
     * zero with precision zero is no digit at all. */
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L"%.5d|%8.3d|%.0d", 42, 42, 0), NKC_TEXT);

    /* 16, "000000001234ABCD": a pointer is sixteen capital hex digits. */
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L"%p", (PVOID)(ULONG_PTR)0x1234ABCD), NKC_TEXT);

    /* 39, "-1|18446744073709551615|123456789abcdef". */
    NkcPrinted(Log,
               NkcPrint(NKC_TEXT, L"%I64d|%I64u|%I64x", (LONGLONG)-1, (ULONGLONG)-1,
                        (ULONGLONG)0x123456789ABCDEF),
               NKC_TEXT);

    /* 29, "123456789abcdef|abcdef0123|77": ll and I (pointer-sized) are
     * 64 bits, I32 is 32. (ll is a guess.) */
    NkcPrinted(Log,
               NkcPrint(NKC_TEXT, L"%llx|%Ix|%I32d", (ULONGLONG)0x123456789ABCDEF,
                        (SIZE_T)0xABCDEF0123, 77),
               NKC_TEXT);

    /* 36, "-100000|3000000000|deadbeef|-2|65535": l is 32 bits; h takes
     * the low 16 of what was passed (0xFFFFFFFE, 0x1FFFF). */
    NkcPrinted(Log,
               NkcPrint(NKC_TEXT, L"%ld|%lu|%lx|%hd|%hu", -100000L, 3000000000UL, 0xDEADBEEFUL,
                        -2, 0x1FFFF),
               NKC_TEXT);

    /* 33, "abc|     right|left      |xy|   7": a string's precision is
     * a most; width and precision can come from the arguments. */
    NkcPrinted(Log,
               NkcPrint(NKC_TEXT, L"%.3s|%10s|%-10s|%.*s|%*d", L"abcdef", L"right", L"left", 2,
                        L"xyz", 4, 7),
               NKC_TEXT);

    /* 9, "w|n|W|h|%": in a wide format %c and %wc take a wide
     * character, %C and %hc a narrow one. */
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L"%c|%C|%wc|%hc|%%", L'w', 'n', L'W', 'h'), NKC_TEXT);

    /* 20, "(null)|(null)|(null)": a null string pointer, a null
     * UNICODE_STRING pointer, and a UNICODE_STRING without a buffer. */
    Empty.Buffer = NULL;
    Empty.Length = 0;
    Empty.MaximumLength = 0;
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L"%s|%wZ|%wZ", (PWSTR)NULL, (PUNICODE_STRING)NULL, &Empty),
               NKC_TEXT);

    /* "abcdef" into room for 7, 6, 4 and 0 characters.
     * 6, the text and its terminator.
     * 6, the text; no terminator: all six characters are the text's.
     * -1, "abcd": as much as fits, no terminator.
     * -1, and nothing shown. */
    NkcPrinted(Log, NkcPrint(7, L"%s", L"abcdef"), 7);
    NkcPrinted(Log, NkcPrint(6, L"%s", L"abcdef"), 6);
    NkcPrinted(Log, NkcPrint(4, L"%s", L"abcdef"), 4);
    NkcPrinted(Log, NkcPrint(0, L"%s", L"abcdef"), 0);

    /* 0xEEEE, 0xEEEE: the character after a full buffer is never
     * written: after room for 4, and after room for 0. */
    NkcPrint(4, L"%s", L"abcdef");
    NkcPut(Log, NkcText[4]);
    NkcPrint(0, L"%s", L"abcdef");
    NkcPut(Log, NkcText[0]);

    /* 0 and a terminator alone: an empty format. -1, "12": a number cut
     * off. */
    NkcPrinted(Log, NkcPrint(NKC_TEXT, L""), NKC_TEXT);
    NkcPrinted(Log, NkcPrint(2, L"%d", 12345), 2);
}

/* ---- Counted strings and code pages ------------------------------------- */

static VOID NkcStrings(NKC_LOG *Log)
{
    static UCHAR One[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    static UCHAR Two[8] = {1, 2, 3, 9, 5, 6, 7, 8};
    static const WCHAR Mixed[] = {'a', 'b', 'c', ' ', 0x00E9, 0x00FF, 0x0131, 0};
    static const WCHAR SmallE[] = {0x00E9, 'x', 0};
    static const WCHAR BigE[] = {0x00C9, 0};
    static const WCHAR Han[] = {'a', 0x4E00, 'b', 0};
    static const GUID Guid = {0x12345678, 0x9ABC, 0xDEF0, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                                            0xAA, 0xFF}};
    static const WCHAR Samples[] = {'a',    'z',    '{',    0x00B5, 0x00DF, 0x00E9, 0x00F7,
                                    0x00FF, 0x0131, 0x017F, 0x01C5, 0x03C2, 0x0450, 0x10D0,
                                    0x1E9E, 0x2170, 0x24D0, 0xFF41, 0xFFFF};
    UNICODE_STRING A, B, Source, Dest;
    ANSI_STRING Ansi;
    WCHAR Room[16];
    CHAR NarrowRoom[8];
    ULONG Bytes, i, Changed, Hash;
    NTSTATUS Status;

    MARK(0x30);

    /* RtlCompareMemory. 8: all eight bytes equal. 3: the first three.
     * 0: over no bytes. 0: the very first differs. */
    NkcPut(Log, (ULONG)RtlCompareMemory(One, One, 8));
    NkcPut(Log, (ULONG)RtlCompareMemory(One, Two, 8));
    NkcPut(Log, (ULONG)RtlCompareMemory(One, Two, 0));
    NkcPut(Log, (ULONG)RtlCompareMemory(One, Two + 3, 5));

    /* RtlPrefixUnicodeString(prefix, string, ignore case).
     * 1: "ab" starts "abc". 0: "AB" does not. 1: without regard to case
     * it does. 0: "abc" does not start "ab". 1: the empty string starts
     * anything. 1: a string starts itself. 0: "ac" does not start "abc".
     * 1, 0: capital E with acute starts small e with acute, "x" without
     * regard to case, and not with. */
    RtlInitUnicodeString(&A, L"ab");
    RtlInitUnicodeString(&B, L"abc");
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&A, &B, FALSE)));
    RtlInitUnicodeString(&A, L"AB");
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&A, &B, FALSE)));
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&A, &B, TRUE)));
    RtlInitUnicodeString(&A, L"ab");
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&B, &A, TRUE)));
    RtlInitUnicodeString(&A, L"");
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&A, &B, FALSE)));
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&B, &B, FALSE)));
    RtlInitUnicodeString(&A, L"ac");
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&A, &B, TRUE)));
    RtlInitUnicodeString(&A, BigE);
    RtlInitUnicodeString(&B, SmallE);
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&A, &B, TRUE)));
    NkcPut(Log, NkcBool(RtlPrefixUnicodeString(&A, &B, FALSE)));

    /* RtlUpcaseUnicodeChar of nineteen characters, two to a value. All
     * but the first three are guesses; the table itself is behind the
     * control codes. 'A', 'Z'; '{', U+039C (micro sign: capital mu);
     * U+00DF (sharp s: itself), U+00C9; U+00F7 (division sign: itself),
     * U+0178; 'I' (dotless i), 'S' (long s); U+01C4, U+03A3 (final
     * sigma); U+0400, U+10D0 (Georgian: itself); U+1E9E (itself),
     * U+2160; U+24B6, U+FF21; U+FFFF. */
    for (i = 0; i < RTL_NUMBER_OF(Samples); i++) {
        Room[i % 2] = RtlUpcaseUnicodeChar(Samples[i]);
        if (i % 2 == 1 || i + 1 == RTL_NUMBER_OF(Samples)) {
            NkcPutWide(Log, Room, i % 2 + 1);
        }
    }

    /* The whole table in two numbers: how many of the 65536 characters
     * have a capital other than themselves, and a hash of all 65536
     * capitals. Not predicted. */
    Changed = 0;
    Hash = 2166136261u;
    for (i = 0; i < 0x10000; i++) {
        WCHAR Up = RtlUpcaseUnicodeChar((WCHAR)i);
        if (Up != (WCHAR)i) {
            Changed++;
        }
        Hash = (Hash ^ Up) * 16777619u;
    }
    NkcPut(Log, Changed);
    NkcPut(Log, Hash);

    /* RtlUpcaseUnicodeString into a string it allocates.
     * 0; 14, 14: the length, and no room for a terminator.
     * "ABC ", U+00C9, U+0178, 'I'. */
    RtlInitUnicodeString(&Source, Mixed);
    Dest.Buffer = NULL;
    Dest.Length = Dest.MaximumLength = 0xEEEE;
    Status = RtlUpcaseUnicodeString(&Dest, &Source, TRUE);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, Dest.Length);
        NkcPut(Log, Dest.MaximumLength);
        NkcPutWide(Log, Dest.Buffer, Dest.Length / sizeof(WCHAR));
        RtlFreeUnicodeString(&Dest);
    }

    /* Into the caller's buffer. 0x80000005 with room for 6 characters
     * of 7; the length then (a guess: left as it was, 0).
     * 0; 14, 32 with room for 16: the length, the room unchanged.
     * 0, "AB": a string made capital in place. */
    Dest.Buffer = Room;
    Dest.Length = 0;
    Dest.MaximumLength = 6 * sizeof(WCHAR);
    NkcPut(Log, (ULONG)RtlUpcaseUnicodeString(&Dest, &Source, FALSE));
    NkcPut(Log, Dest.Length);
    Dest.Length = 0;
    Dest.MaximumLength = sizeof(Room);
    NkcPut(Log, (ULONG)RtlUpcaseUnicodeString(&Dest, &Source, FALSE));
    NkcPut(Log, Dest.Length);
    NkcPut(Log, Dest.MaximumLength);
    Room[0] = 'a';
    Room[1] = 'b';
    Dest.Length = 2 * sizeof(WCHAR);
    NkcPut(Log, (ULONG)RtlUpcaseUnicodeString(&Dest, &Dest, FALSE));
    NkcPutWide(Log, Room, 2);

    /* RtlMultiByteToUnicodeN.
     * 0, 6, "abc": three bytes into room for more.
     * 0x80000005, 4, "ab": into room for two characters.
     * 0x80000005, 4: into five bytes of room, the odd byte is no room.
     * 0, 0: no bytes. 0: and the count may be left out. */
    MARK(0x31);
    RtlFillMemory(Room, sizeof(Room), 0xEE);
    Bytes = 0xEEEEEEEE;
    NkcPut(Log, (ULONG)RtlMultiByteToUnicodeN(Room, sizeof(Room), &Bytes, "abc", 3));
    NkcPut(Log, Bytes);
    NkcPutWide(Log, Room, 3);
    Bytes = 0xEEEEEEEE;
    NkcPut(Log, (ULONG)RtlMultiByteToUnicodeN(Room, 4, &Bytes, "abc", 3));
    NkcPut(Log, Bytes);
    NkcPutWide(Log, Room, 2);
    Bytes = 0xEEEEEEEE;
    NkcPut(Log, (ULONG)RtlMultiByteToUnicodeN(Room, 5, &Bytes, "abc", 3));
    NkcPut(Log, Bytes);
    Bytes = 0xEEEEEEEE;
    NkcPut(Log, (ULONG)RtlMultiByteToUnicodeN(Room, sizeof(Room), &Bytes, "abc", 0));
    NkcPut(Log, Bytes);
    NkcPut(Log, (ULONG)RtlMultiByteToUnicodeN(Room, sizeof(Room), NULL, "abc", 3));

    /* The code page in two numbers: how many of the bytes 0x00..0x7F
     * come out as themselves (128), and a hash of what all 256 come out
     * as (not predicted: the machine's code page). */
    Changed = 0;
    Hash = 2166136261u;
    for (i = 0; i < 256; i++) {
        USHORT Wide = NkcToWide((UCHAR)i);
        if (i < 128 && Wide == i) {
            Changed++;
        }
        Hash = (Hash ^ Wide) * 16777619u;
    }
    NkcPut(Log, Changed);
    NkcPut(Log, Hash);

    /* RtlUnicodeStringToAnsiString into a string it allocates.
     * 0; 3, 4; "abc" and its terminator.
     * Freed, the string is cleared: 1 (no buffer), 0, 0. */
    RtlInitUnicodeString(&Source, L"abc");
    Ansi.Buffer = NULL;
    Ansi.Length = Ansi.MaximumLength = 0xEEEE;
    Status = RtlUnicodeStringToAnsiString(&Ansi, &Source, TRUE);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, Ansi.Length);
        NkcPut(Log, Ansi.MaximumLength);
        NkcPutBytes(Log, (PUCHAR)Ansi.Buffer, 4);
        RtlFreeAnsiString(&Ansi);
        NkcPut(Log, Ansi.Buffer == NULL ? 1 : 0);
        NkcPut(Log, Ansi.Length);
        NkcPut(Log, Ansi.MaximumLength);
    }

    /* 0; 0, 1: the empty string takes one byte, its terminator. */
    RtlInitUnicodeString(&Source, L"");
    Status = RtlUnicodeStringToAnsiString(&Ansi, &Source, TRUE);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, Ansi.Length);
        NkcPut(Log, Ansi.MaximumLength);
        RtlFreeAnsiString(&Ansi);
    }

    /* Into the caller's buffer.
     * 0x80000005; 2, 3; "ab", 0, 0xEE: "abc" into three bytes: what
     * fits, terminated.
     * 0; 3, 8; "abc", 0: into eight.
     * 0; 3; 'a', '?', 'b', 0: a character the code page has not becomes
     * its default character (a guess, for code page 1252). */
    RtlInitUnicodeString(&Source, L"abc");
    RtlFillMemory(NarrowRoom, sizeof(NarrowRoom), 0xEE);
    Ansi.Buffer = NarrowRoom;
    Ansi.Length = 0;
    Ansi.MaximumLength = 3;
    NkcPut(Log, (ULONG)RtlUnicodeStringToAnsiString(&Ansi, &Source, FALSE));
    NkcPut(Log, Ansi.Length);
    NkcPut(Log, Ansi.MaximumLength);
    NkcPutBytes(Log, (PUCHAR)NarrowRoom, 4);
    Ansi.Length = 0;
    Ansi.MaximumLength = sizeof(NarrowRoom);
    NkcPut(Log, (ULONG)RtlUnicodeStringToAnsiString(&Ansi, &Source, FALSE));
    NkcPut(Log, Ansi.Length);
    NkcPut(Log, Ansi.MaximumLength);
    NkcPutBytes(Log, (PUCHAR)NarrowRoom, 4);
    RtlInitUnicodeString(&Source, Han);
    Ansi.Length = 0;
    NkcPut(Log, (ULONG)RtlUnicodeStringToAnsiString(&Ansi, &Source, FALSE));
    NkcPut(Log, Ansi.Length);
    NkcPutBytes(Log, (PUCHAR)NarrowRoom, 4);

    /* RtlStringFromGUID. 0; 76, 78: 38 characters and room for a
     * terminator; "{12345678-9abc-def0-1122-33445566aaff}": small hex
     * digits. */
    MARK(0x32);
    Dest.Buffer = NULL;
    Status = RtlStringFromGUID(&Guid, &Dest);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, Dest.Length);
        NkcPut(Log, Dest.MaximumLength);
        NkcPutWide(Log, Dest.Buffer, Dest.Length / sizeof(WCHAR));
        RtlFreeUnicodeString(&Dest);
    }
}

/* ---- SIDs, access lists, descriptors ------------------------------------ */

typedef struct _NKC_SID {
    ULONG Room[17]; /* SECURITY_MAX_SID_SIZE, 68 bytes, aligned */
} NKC_SID;

/* A SID of authority {0,0,0,0,0,Authority} and `Count` subauthorities. */
static PSID NkcSid(NKC_SID *Sid, UCHAR Authority, UCHAR Count, const ULONG *Subs)
{
    SID_IDENTIFIER_AUTHORITY Value = {{0, 0, 0, 0, 0, 0}};
    UCHAR i;

    Value.Value[5] = Authority;
    RtlZeroMemory(Sid, sizeof(*Sid));
    RtlInitializeSid(Sid, &Value, Count);
    for (i = 0; i < Count; i++) {
        *RtlSubAuthoritySid(Sid, i) = Subs[i];
    }
    return Sid;
}

/* RtlConvertSidToUnicodeString into a string it allocates: the status,
 * then the length, the room and the text. */
static VOID NkcSidText(NKC_LOG *Log, PSID Sid)
{
    UNICODE_STRING Text;
    NTSTATUS Status;

    Text.Buffer = NULL;
    Text.Length = Text.MaximumLength = 0;
    Status = RtlConvertSidToUnicodeString(&Text, Sid, TRUE);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status)) {
        NkcPut(Log, Text.Length);
        NkcPut(Log, Text.MaximumLength);
        NkcPutWide(Log, Text.Buffer, Text.Length / sizeof(WCHAR));
        RtlFreeUnicodeString(&Text);
    }
}

/* RtlGetAppContainerSidType and RtlGetAppContainerParent of one SID:
 * the first's status and the type it stored (0xEEEEEEEE: none); the
 * second's status and, if it gave a SID, its number of subauthorities
 * and whether it is the first eight subauthorities of `Sid`. */
static VOID NkcAppContainer(NKC_LOG *Log, PSID Sid)
{
    ULONG Type = 0xEEEEEEEE;
    PSID Parent = NULL;
    NKC_SID Expected;
    NTSTATUS Status;

    NkcPut(Log, (ULONG)RtlGetAppContainerSidType(Sid, (PVOID)&Type));
    NkcPut(Log, Type);
    Status = RtlGetAppContainerParent(Sid, &Parent);
    NkcPut(Log, (ULONG)Status);
    if (NT_SUCCESS(Status) && Parent != NULL) {
        NkcPut(Log, *RtlSubAuthorityCountSid(Parent));
        NkcSid(&Expected, 15, 8, RtlSubAuthoritySid(Sid, 0));
        NkcPut(Log, NkcBool(RtlEqualSid(Parent, &Expected)));
        ExFreePool(Parent);
    }
}

static VOID NkcSecurity(NKC_LOG *Log)
{
    static const ULONG Admins[2] = {32, 544};
    static const ULONG Users[2] = {32, 545};
    static const ULONG System[1] = {18};
    static const ULONG Big[2] = {0xFFFFFFFF, 0x80000000};
    static const ULONG Package[12] = {2, 11, 22, 33, 44, 55, 66, 77, 1001, 1002, 1003, 1004};
    static const ULONG Capability[2] = {3, 1};
    static const ULONG Fifteen[15] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    NKC_SID One, Two;
    PSID Sid, Other;
    SECURITY_DESCRIPTOR Sd;
    UCHAR Relative[128];
    ULONG AclRoom[32];
    PACL Acl = (PACL)AclRoom;
    PSID Got;
    BOOLEAN Defaulted;
    ULONG Length;
    UNICODE_STRING Text;
    WCHAR TextRoom[8];

    MARK(0x40);

    /* 16: the room a SID of two subauthorities needs. 0: initialised.
     * 2: its count. 8, 12: where its subauthorities are. 16: its length.
     * 1: valid. 1: equal to the kernel's SID for administrators.
     * 0: not equal to the one for the system. */
    NkcPut(Log, RtlLengthRequiredSid(2));
    {
        SID_IDENTIFIER_AUTHORITY Nt = SECURITY_NT_AUTHORITY;
        RtlFillMemory(&One, sizeof(One), 0xEE);
        NkcPut(Log, (ULONG)RtlInitializeSid(&One, &Nt, 2));
    }
    Sid = &One;
    NkcPut(Log, *RtlSubAuthorityCountSid(Sid));
    NkcPut(Log, (ULONG)((PUCHAR)RtlSubAuthoritySid(Sid, 0) - (PUCHAR)Sid));
    NkcPut(Log, (ULONG)((PUCHAR)RtlSubAuthoritySid(Sid, 1) - (PUCHAR)Sid));
    *RtlSubAuthoritySid(Sid, 0) = 32;
    *RtlSubAuthoritySid(Sid, 1) = 544;
    NkcPut(Log, RtlLengthSid(Sid));
    NkcPut(Log, NkcBool(RtlValidSid(Sid)));
    NkcPut(Log, NkcBool(RtlEqualSid(Sid, SeExports->SeAliasAdminsSid)));
    NkcPut(Log, NkcBool(RtlEqualSid(Sid, SeExports->SeLocalSystemSid)));

    /* RtlEqualSid. 0: another last subauthority. 0: fewer
     * subauthorities. 0: another authority. 1: itself. */
    NkcPut(Log, NkcBool(RtlEqualSid(Sid, NkcSid(&Two, 5, 2, Users))));
    NkcPut(Log, NkcBool(RtlEqualSid(Sid, NkcSid(&Two, 5, 1, Admins))));
    NkcPut(Log, NkcBool(RtlEqualSid(Sid, NkcSid(&Two, 1, 2, Admins))));
    NkcPut(Log, NkcBool(RtlEqualSid(Sid, Sid)));

    /* RtlValidSid. 1: fifteen subauthorities. 0: sixteen. 0: revision 2.
     * 1: no subauthorities. */
    Other = NkcSid(&Two, 5, 15, Fifteen);
    NkcPut(Log, NkcBool(RtlValidSid(Other)));
    ((PISID)Other)->SubAuthorityCount = 16;
    NkcPut(Log, NkcBool(RtlValidSid(Other)));
    Other = NkcSid(&Two, 5, 2, Admins);
    ((PISID)Other)->Revision = 2;
    NkcPut(Log, NkcBool(RtlValidSid(Other)));
    NkcPut(Log, NkcBool(RtlValidSid(NkcSid(&Two, 5, 0, Admins))));

    /* RtlCopySid. 0, 1: into room for it, and the copy is equal.
     * 0xC0000023: into less room. */
    RtlFillMemory(&Two, sizeof(Two), 0xEE);
    NkcPut(Log, (ULONG)RtlCopySid(16, &Two, Sid));
    NkcPut(Log, NkcBool(RtlEqualSid(&Two, Sid)));
    NkcPut(Log, (ULONG)RtlCopySid(15, &Two, Sid));

    /* RtlConvertSidToUnicodeString.
     * 0; 24, 26 (the room: a guess), "S-1-5-32-544".
     * 0; "S-1-5-18".
     * 0; "S-1-5-4294967295-2147483648": subauthorities are unsigned.
     * 0; "S-1-0x010000000005-18": an authority beyond 32 bits is in
     * hex (the digits: a guess).
     * 0xC0000078: a SID of revision 2. */
    MARK(0x41);
    NkcSidText(Log, Sid);
    NkcSidText(Log, NkcSid(&Two, 5, 1, System));
    NkcSidText(Log, NkcSid(&Two, 5, 2, Big));
    Other = NkcSid(&Two, 5, 1, System);
    ((PISID)Other)->IdentifierAuthority.Value[0] = 1;
    NkcSidText(Log, Other);
    Other = NkcSid(&Two, 5, 1, System);
    ((PISID)Other)->Revision = 2;
    NkcSidText(Log, Other);

    /* 0x80000005: into the caller's buffer, with room for 8 characters
     * of the 12. */
    Text.Buffer = TextRoom;
    Text.Length = 0;
    Text.MaximumLength = sizeof(TextRoom);
    NkcPut(Log, (ULONG)RtlConvertSidToUnicodeString(&Text, Sid, FALSE));

    /* App containers. For each SID: the status of
     * RtlGetAppContainerSidType and the type; the status of
     * RtlGetAppContainerParent and, on success, the parent's number of
     * subauthorities and whether it is the SID's first eight. All
     * guesses:
     *   S-1-5-18                        0xC000000D?, 0 or untouched; failure
     *   S-1-15-2-(7 numbers)            0, 2 (parent); failure: it has no parent
     *   S-1-15-2-(7 numbers)-(4 more)   0, 1 (child); 0, 8, 1
     *   S-1-15-2-11                     0, 3 (invalid), or failure; failure
     *   S-1-15-2-(8 numbers)            the same
     *   S-1-15-3-1 (a capability)       not an app container; failure */
    MARK(0x42);
    NkcAppContainer(Log, NkcSid(&Two, 5, 1, System));
    NkcAppContainer(Log, NkcSid(&Two, 15, 8, Package));
    NkcAppContainer(Log, NkcSid(&Two, 15, 12, Package));
    NkcAppContainer(Log, NkcSid(&Two, 15, 2, Package));
    NkcAppContainer(Log, NkcSid(&Two, 15, 9, Package));
    NkcAppContainer(Log, NkcSid(&Two, 15, 2, Capability));

    /* RtlCreateAcl in 64 bytes at revision 2.
     * 0; 2, 0, 64, 0, 0: the revision, a zero byte, the size, no
     * entries, a zero word.
     * 0, 4: revision 4 is taken too.
     * 0xC000000D, 0xC000000D: revisions 1 and 5 are not.
     * 0xC0000023: fewer bytes than a header.
     * 0, 64: a size of 67 is brought down to a multiple of four (a
     * guess).
     * 0xC000000D: a size that does not fit in 16 bits. */
    MARK(0x43);
    RtlFillMemory(AclRoom, sizeof(AclRoom), 0xEE);
    NkcPut(Log, (ULONG)RtlCreateAcl(Acl, 64, ACL_REVISION));
    NkcPut(Log, Acl->AclRevision);
    NkcPut(Log, Acl->Sbz1);
    NkcPut(Log, Acl->AclSize);
    NkcPut(Log, Acl->AceCount);
    NkcPut(Log, Acl->Sbz2);
    NkcPut(Log, (ULONG)RtlCreateAcl(Acl, 64, 4));
    NkcPut(Log, Acl->AclRevision);
    NkcPut(Log, (ULONG)RtlCreateAcl(Acl, 64, 1));
    NkcPut(Log, (ULONG)RtlCreateAcl(Acl, 64, 5));
    NkcPut(Log, (ULONG)RtlCreateAcl(Acl, 4, ACL_REVISION));
    NkcPut(Log, (ULONG)RtlCreateAcl(Acl, 67, ACL_REVISION));
    NkcPut(Log, Acl->AclSize);
    NkcPut(Log, (ULONG)RtlCreateAcl(Acl, 0x10000, ACL_REVISION));
    RtlCreateAcl(Acl, 64, ACL_REVISION);

    /* Owner and group of an absolute descriptor.
     * 0, 1, 0: the owner is set: the descriptor points at the caller's
     * SID; SE_OWNER_DEFAULTED is clear.
     * 0, 1: set as defaulted, the bit (1) is set.
     * 0; 0, 1, 1: and it reads back: the same SID, defaulted.
     * 0, 1, 2: the group likewise: its bit is 2.
     * 0, 1, 0: no owner: the pointer is null and the bit clear. */
    MARK(0x44);
    RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    NkcPut(Log, (ULONG)RtlSetOwnerSecurityDescriptor(&Sd, Sid, FALSE));
    NkcPut(Log, Sd.Owner == Sid ? 1 : 0);
    NkcPut(Log, Sd.Control & SE_OWNER_DEFAULTED);
    NkcPut(Log, (ULONG)RtlSetOwnerSecurityDescriptor(&Sd, Sid, TRUE));
    NkcPut(Log, Sd.Control & SE_OWNER_DEFAULTED);
    Got = NULL;
    Defaulted = 0xEE;
    NkcPut(Log, (ULONG)RtlGetOwnerSecurityDescriptor(&Sd, &Got, &Defaulted));
    NkcPut(Log, Got == Sid ? 1 : 0);
    NkcPut(Log, NkcBool(Defaulted));
    NkcPut(Log, (ULONG)RtlSetGroupSecurityDescriptor(&Sd, Sid, TRUE));
    NkcPut(Log, Sd.Group == Sid ? 1 : 0);
    NkcPut(Log, Sd.Control & SE_GROUP_DEFAULTED);
    NkcPut(Log, (ULONG)RtlSetOwnerSecurityDescriptor(&Sd, NULL, FALSE));
    NkcPut(Log, Sd.Owner == NULL ? 1 : 0);
    NkcPut(Log, Sd.Control & SE_OWNER_DEFAULTED);

    /* RtlValidSecurityDescriptor.
     * 1: the descriptor, with a group and no owner.
     * 1: with an owner and an access list.
     * 0: when the owner is a SID of revision 2.
     * 0: at revision 2.
     * 0, 1: made self-relative, it is valid in that form. */
    NkcPut(Log, NkcBool(RtlValidSecurityDescriptor(&Sd)));
    RtlSetOwnerSecurityDescriptor(&Sd, Sid, FALSE);
    RtlSetDaclSecurityDescriptor(&Sd, TRUE, Acl, FALSE);
    NkcPut(Log, NkcBool(RtlValidSecurityDescriptor(&Sd)));
    Other = NkcSid(&Two, 5, 2, Admins);
    ((PISID)Other)->Revision = 2;
    RtlSetOwnerSecurityDescriptor(&Sd, Other, FALSE);
    NkcPut(Log, NkcBool(RtlValidSecurityDescriptor(&Sd)));
    RtlSetOwnerSecurityDescriptor(&Sd, Sid, FALSE);
    Sd.Revision = 2;
    NkcPut(Log, NkcBool(RtlValidSecurityDescriptor(&Sd)));
    Sd.Revision = SECURITY_DESCRIPTOR_REVISION;
    Length = sizeof(Relative);
    NkcPut(Log, (ULONG)RtlAbsoluteToSelfRelativeSD(&Sd, Relative, &Length));
    NkcPut(Log, NkcBool(RtlValidSecurityDescriptor(Relative)));

    /* 0xC0000079, 0xC0000079: owner and group cannot be set in a
     * self-relative descriptor.
     * 0xC0000058, 0xC0000058: nor in one of revision 2. */
    NkcPut(Log, (ULONG)RtlSetOwnerSecurityDescriptor(Relative, Sid, FALSE));
    NkcPut(Log, (ULONG)RtlSetGroupSecurityDescriptor(Relative, Sid, FALSE));
    Sd.Revision = 2;
    NkcPut(Log, (ULONG)RtlSetOwnerSecurityDescriptor(&Sd, Sid, FALSE));
    NkcPut(Log, (ULONG)RtlSetGroupSecurityDescriptor(&Sd, Sid, FALSE));
}

/* ---- The Unicode prefix table ------------------------------------------- */

#define NKC_PREFIXES 5

static UNICODE_PREFIX_TABLE NkcTable;
static UNICODE_PREFIX_TABLE_ENTRY NkcEntries[NKC_PREFIXES];
static UNICODE_STRING NkcNames[NKC_PREFIXES];

/* Put `Name` in the table as entry `Number` (1 to 5): what the routine
 * said. */
static ULONG NkcInsert(ULONG Number, PCWSTR Name)
{
    RtlInitUnicodeString(&NkcNames[Number - 1], Name);
    return NkcBool(RtlInsertUnicodePrefix(&NkcTable, &NkcNames[Number - 1],
                                          &NkcEntries[Number - 1]));
}

/* The number of the entry found for `Name`; 0 for none. */
static ULONG NkcFind(PCWSTR Name, ULONG CaseInsensitiveIndex)
{
    UNICODE_STRING Full;
    PUNICODE_PREFIX_TABLE_ENTRY Entry;

    RtlInitUnicodeString(&Full, Name);
    Entry = RtlFindUnicodePrefix(&NkcTable, &Full, CaseInsensitiveIndex);
    return Entry == NULL ? 0 : (ULONG)(Entry - NkcEntries) + 1;
}

static VOID NkcPrefixes(NKC_LOG *Log)
{
    MARK(0x50);

    /* 0x800: the table's type code once initialised. 0: nothing is
     * found in an empty table. */
    RtlFillMemory(&NkcTable, sizeof(NkcTable), 0xEE);
    RtlInitializeUnicodePrefix(&NkcTable);
    NkcPut(Log, (ULONG)NkcTable.NodeTypeCode);
    NkcPut(Log, NkcFind(L"\\a", 0));

    /* 1, 1, 1, 1: four names go in: \a, \a\b, \a\b\c, \x.
     * 0: \a a second time, as another entry, does not. */
    NkcPut(Log, NkcInsert(1, L"\\a"));
    NkcPut(Log, NkcInsert(2, L"\\a\\b"));
    NkcPut(Log, NkcInsert(3, L"\\a\\b\\c"));
    NkcPut(Log, NkcInsert(4, L"\\x"));
    NkcPut(Log, NkcInsert(5, L"\\a"));

    /* The longest name in the table that starts the name looked for and
     * ends where one of its components ends:
     * 3: \a\b\c\d. 3: \a\b\c. 2: \a\b. 1: \a\bc. 1: \a.
     * 0: \ab. 0: \y. 4: \x\a\b. 0: a\b (no backslash first).
     * 2: \a\b\ (a guess). */
    NkcPut(Log, NkcFind(L"\\a\\b\\c\\d", 0));
    NkcPut(Log, NkcFind(L"\\a\\b\\c", 0));
    NkcPut(Log, NkcFind(L"\\a\\b", 0));
    NkcPut(Log, NkcFind(L"\\a\\bc", 0));
    NkcPut(Log, NkcFind(L"\\a", 0));
    NkcPut(Log, NkcFind(L"\\ab", 0));
    NkcPut(Log, NkcFind(L"\\y", 0));
    NkcPut(Log, NkcFind(L"\\x\\a\\b", 0));
    NkcPut(Log, NkcFind(L"a\\b", 0));
    NkcPut(Log, NkcFind(L"\\a\\b\\", 0));

    /* Letter case. The third argument says from where on case is
     * disregarded.
     * 2: \A\B\X from 0: all of it.
     * 0: \A\B\X from 100: none of it.
     * 1: \a\B\X from 100: \a matches as written, \B does not match \b.
     * \a\B from 3 and from 6: 2, 1 if the argument counts characters
     * ('B' is the fourth); 2, 2 if it counts bytes (a guess: characters). */
    NkcPut(Log, NkcFind(L"\\A\\B\\X", 0));
    NkcPut(Log, NkcFind(L"\\A\\B\\X", 100));
    NkcPut(Log, NkcFind(L"\\a\\B\\X", 100));
    NkcPut(Log, NkcFind(L"\\a\\B", 3));
    NkcPut(Log, NkcFind(L"\\a\\B", 6));

    /* 3, 1: \a\b removed, \a\b\c\d still finds \a\b\c, and \a\b finds \a.
     * 1: \a\b\c removed too, \a\b\c\d finds \a. */
    RtlRemoveUnicodePrefix(&NkcTable, &NkcEntries[1]);
    NkcPut(Log, NkcFind(L"\\a\\b\\c\\d", 0));
    NkcPut(Log, NkcFind(L"\\a\\b", 0));
    RtlRemoveUnicodePrefix(&NkcTable, &NkcEntries[2]);
    NkcPut(Log, NkcFind(L"\\a\\b\\c\\d", 0));

    /* 1: the name \ alone goes in, as entry 3.
     * 3: it starts every name that has nothing longer: \zzz.
     * 4, 1: \x\y and \a\q still find their own.
     * 0: a name without a backslash first is not started by it (a guess). */
    NkcPut(Log, NkcInsert(3, L"\\"));
    NkcPut(Log, NkcFind(L"\\zzz", 0));
    NkcPut(Log, NkcFind(L"\\x\\y", 0));
    NkcPut(Log, NkcFind(L"\\a\\q", 0));
    NkcPut(Log, NkcFind(L"zzz", 0));

    /* 1: \X goes in beside \x, as entry 2: names that differ in case
     * are different names (a guess).
     * 2, 4: with case regarded, each is found by its own spelling.
     * Which of the two is found with case disregarded, by \x and by \X:
     * not predicted. */
    NkcPut(Log, NkcInsert(2, L"\\X"));
    NkcPut(Log, NkcFind(L"\\X", 100));
    NkcPut(Log, NkcFind(L"\\x", 100));
    NkcPut(Log, NkcFind(L"\\x", 0));
    NkcPut(Log, NkcFind(L"\\X", 0));

    /* 3, 2: \x removed, \x\y with case regarded finds only the name \,
     * and with case disregarded finds \X. 0, 0: all removed, nothing
     * is found. */
    RtlRemoveUnicodePrefix(&NkcTable, &NkcEntries[3]);
    NkcPut(Log, NkcFind(L"\\x\\y", 100));
    NkcPut(Log, NkcFind(L"\\x\\y", 0));
    RtlRemoveUnicodePrefix(&NkcTable, &NkcEntries[0]);
    RtlRemoveUnicodePrefix(&NkcTable, &NkcEntries[1]);
    RtlRemoveUnicodePrefix(&NkcTable, &NkcEntries[2]);
    NkcPut(Log, NkcFind(L"\\a", 0));
    NkcPut(Log, NkcFind(L"\\", 0));
}

/* ---- Wildcards ---------------------------------------------------------- */

typedef struct _NKC_MATCH {
    PCWSTR Expression;
    PCWSTR Name;
    BOOLEAN IgnoreCase;
} NKC_MATCH;

/* Each line: the expression, the name, whether case is disregarded; in
 * the comment, the predicted answer. `<` is DOS_STAR, `>` DOS_QM and
 * `"` DOS_DOT. With case disregarded the expression must be in capitals
 * already. Lines marked (g) are guesses. */
static const NKC_MATCH NkcMatches[] = {
    /* Empty strings, and the lone star. */
    {L"*", L"anything", FALSE},   /* 1 */
    {L"*", L"", FALSE},           /* 0: an empty name matches only an empty expression */
    {L"", L"", FALSE},            /* 1 */
    {L"", L"a", FALSE},           /* 0 */
    /* No wildcard. */
    {L"abc", L"abc", FALSE},      /* 1 */
    {L"abc", L"ABC", FALSE},      /* 0 */
    {L"ABC", L"abc", TRUE},       /* 1 */
    {L"abc", L"ABC", TRUE},       /* 0 (g): the expression is not made capital */
    {L"abc", L"abcd", FALSE},     /* 0 */
    {L"abcd", L"abc", FALSE},     /* 0 */
    /* A star first and nothing else: the name's end is compared. */
    {L"*abc", L"xxabc", FALSE},   /* 1 */
    {L"*abc", L"xxabd", FALSE},   /* 0 */
    {L"*abc", L"abc", FALSE},     /* 1 */
    {L"*abcd", L"bcd", FALSE},    /* 0 */
    {L"*ABC", L"xxabc", TRUE},    /* 1 */
    {L"*.txt", L"file.txt", FALSE},     /* 1 */
    {L"*.txt", L"file.txt.bak", FALSE}, /* 0 */
    {L"*.TXT", L"file.txt", TRUE},      /* 1 */
    {L"*.TXT", L"file.txt", FALSE},     /* 0 */
    /* Stars elsewhere. */
    {L"a*", L"a", FALSE},         /* 1 */
    {L"a*", L"abc", FALSE},       /* 1 */
    {L"a*", L"ba", FALSE},        /* 0 */
    {L"a*c", L"ac", FALSE},       /* 1 */
    {L"a*c", L"abcbc", FALSE},    /* 1 */
    {L"a*c", L"abcb", FALSE},     /* 0 */
    {L"*a*", L"xax", FALSE},      /* 1 */
    {L"*a*", L"xxx", FALSE},      /* 0 */
    {L"**", L"x", FALSE},         /* 1 */
    {L"a*b*c", L"aXbYc", FALSE},  /* 1 */
    {L"a*b*c", L"acb", FALSE},    /* 0 */
    {L"*a*a*a", L"aaa", FALSE},   /* 1 */
    {L"*a*a*a*a", L"aaa", FALSE}, /* 0 */
    {L"*.", L"file.", FALSE},     /* 1 */
    {L"*.", L"file", FALSE},      /* 0 */
    {L"*.*", L"file", FALSE},     /* 0 */
    {L"*.*", L"file.txt", FALSE}, /* 1 */
    {L"*.*", L".", FALSE},        /* 1 */
    /* Question marks. */
    {L"a?c", L"abc", FALSE},      /* 1 */
    {L"a?c", L"ac", FALSE},       /* 0 */
    {L"a?c", L"abbc", FALSE},     /* 0 */
    {L"a?c", L"a.c", FALSE},      /* 1 */
    {L"???", L"ab", FALSE},       /* 0 */
    {L"???", L"abc", FALSE},      /* 1 */
    {L"?", L"", FALSE},           /* 0 */
    {L"a?", L"a", FALSE},         /* 0 */
    {L"?*", L"a", FALSE},         /* 1 */
    /* DOS_STAR: any characters, but it does not take the name's last
     * period for itself... */
    {L"<", L"abc", FALSE},        /* 1 (g) */
    {L"<", L"a.b", FALSE},        /* 0 (g) */
    {L"<.txt", L"file.txt", FALSE},   /* 1 */
    {L"<.txt", L"a.b.txt", FALSE},    /* 1 */
    {L"<.txt", L"file.txt.bak", FALSE}, /* 0 */
    {L"<.b", L"a.b.c", FALSE},    /* 0 (g) */
    {L"a<", L"a.b", FALSE},       /* 0 (g) */
    {L"a<c", L"a.c", FALSE},      /* 0 (g) */
    {L"a<c", L"abc", FALSE},      /* 1 (g) */
    {L"<\"*", L"file", FALSE},    /* 1: what "*.*" stands for */
    {L"<\"*", L"file.txt", FALSE}, /* 1 */
    {L"<\"*", L"a.b.c", FALSE},   /* 1 */
    {L"<\"", L"file.", FALSE},    /* 1 (g) */
    /* DOS_QM: one character; at a period or the name's end, none. */
    {L"a>", L"a", FALSE},         /* 1 */
    {L"a>", L"ab", FALSE},        /* 1 */
    {L"a>", L"abc", FALSE},       /* 0 */
    {L"a>>", L"a", FALSE},        /* 1 */
    {L"a>c", L"ac", FALSE},       /* 0 (g) */
    {L"a>c", L"abc", FALSE},      /* 1 */
    {L"a>.c", L"a.c", FALSE},     /* 1 */
    {L">>>.txt", L"ab.txt", FALSE},   /* 1 */
    {L">>>.txt", L"abcd.txt", FALSE}, /* 0 */
    {L">", L".", FALSE},          /* 0 (g) */
    {L">>>>>>>>\">>>", L"abc.de", FALSE},       /* 1: what "????????.???" stands for */
    {L">>>>>>>>\">>>", L"abc", FALSE},          /* 1 */
    {L">>>>>>>>\">>>", L"abcdefghi.x", FALSE},  /* 0 */
    {L">>>>>>>>\">>>", L"abc.defg", FALSE},     /* 0 */
    /* DOS_DOT: a period; at the name's end, nothing. */
    {L"a\"b", L"a.b", FALSE},     /* 1 */
    {L"a\"b", L"axb", FALSE},     /* 0 */
    {L"a\"b", L"ab", FALSE},      /* 0 */
    {L"a\"", L"a", FALSE},        /* 1 */
    {L"a\"", L"a.", FALSE},       /* 1 */
    {L"a\"", L"ab", FALSE},       /* 0 */
    {L"\"", L".", FALSE},         /* 1 */
    {L"file\"*", L"file", FALSE}, /* 1 */
    {L"file\"*", L"file.c", FALSE}, /* 1 */
    {L"file\"*", L"filex", FALSE},  /* 0 */
    /* Case, with wildcards. */
    {L"A?C*", L"abcdef", TRUE},   /* 1 */
    {L"A?C*", L"abcdef", FALSE},  /* 0 */
    {L"<.TXT", L"File.Txt", TRUE}, /* 1 */
};

static BOOLEAN NkcMatch(PCWSTR Expression, PCWSTR Name, BOOLEAN IgnoreCase, PWCH Table)
{
    UNICODE_STRING E, N;

    RtlInitUnicodeString(&E, Expression);
    RtlInitUnicodeString(&N, Name);
    return FsRtlIsNameInExpression(&E, &N, IgnoreCase, Table);
}

static VOID NkcWildcards(NKC_LOG *Log)
{
    static const WCHAR BigE[] = {0x00C9, '*', 0};
    static const WCHAR SmallE[] = {0x00E9, 'x', 0};
    static const WCHAR BigAlpha[] = {0x0391, '?', 0};
    static const WCHAR SmallAlpha[] = {0x03B1, 0x03B2, 0};
    PWCH Table;
    ULONG i;

    MARK(0x60);

    /* One value for each line of the table above. */
    for (i = 0; i < RTL_NUMBER_OF(NkcMatches); i++) {
        NkcPut(Log, NkcBool(NkcMatch(NkcMatches[i].Expression, NkcMatches[i].Name,
                                     NkcMatches[i].IgnoreCase, NULL)));
    }

    /* 1, 0: capital E with acute, star, against small e with acute,
     * "x": with case disregarded the system's table is used; with case
     * regarded they differ. 1: capital alpha likewise. */
    MARK(0x61);
    NkcPut(Log, NkcBool(NkcMatch(BigE, SmallE, TRUE, NULL)));
    NkcPut(Log, NkcBool(NkcMatch(BigE, SmallE, FALSE, NULL)));
    NkcPut(Log, NkcBool(NkcMatch(BigAlpha, SmallAlpha, TRUE, NULL)));

    /* The caller's own table of capitals.
     * 0, 1: one that leaves every character as it is: "ABC" does not
     * match "abc" with case disregarded; "abc" does.
     * 1, 1: one that says what RtlUpcaseUnicodeChar says: "ABC" matches
     * "abc", and "*.TXT" matches "file.txt".
     * 0: with case regarded a table is not used.
     * 1: one that makes every character 'X': "X?X" matches "abc". */
    Table = (PWCH)ExAllocatePoolWithTag(PagedPool, 0x10000 * sizeof(WCHAR), NKC_POOL_TAG);
    if (Table == NULL) {
        MARK(0xE0);
        return;
    }
    for (i = 0; i < 0x10000; i++) {
        Table[i] = (WCHAR)i;
    }
    NkcPut(Log, NkcBool(NkcMatch(L"ABC", L"abc", TRUE, Table)));
    NkcPut(Log, NkcBool(NkcMatch(L"abc", L"abc", TRUE, Table)));
    for (i = 0; i < 0x10000; i++) {
        Table[i] = RtlUpcaseUnicodeChar((WCHAR)i);
    }
    NkcPut(Log, NkcBool(NkcMatch(L"ABC", L"abc", TRUE, Table)));
    NkcPut(Log, NkcBool(NkcMatch(L"*.TXT", L"file.txt", TRUE, Table)));
    NkcPut(Log, NkcBool(NkcMatch(L"ABC", L"abc", FALSE, Table)));
    for (i = 0; i < 0x10000; i++) {
        Table[i] = 'X';
    }
    NkcPut(Log, NkcBool(NkcMatch(L"X?X", L"abc", TRUE, Table)));
    ExFreePoolWithTag(Table, NKC_POOL_TAG);
}

/* ---- Characters legal in file names ------------------------------------- */

static VOID NkcLegal(NKC_LOG *Log)
{
    UCHAR Flags[128];
    ULONG i;

    MARK(0x70);

    /* FsRtlLegalAnsiCharacterArray, the entries for characters 0 to
     * 127, four to a value. Each is a set of bits: 1 legal in a FAT
     * name, 2 in an HPFS name, 4 in an NTFS name, 8 a wildcard, 16 legal
     * in an OLE name. Not predicted entry by entry; in outline (a guess):
     * control characters 0; letters and digits 0x17; the wildcards
     * " * < > ? 8; \ 0; / 0. */
    for (i = 0; i < 128; i++) {
        Flags[i] = LEGAL_ANSI_CHARACTER_ARRAY[i];
    }
    NkcPutBytes(Log, Flags, sizeof(Flags));
}

static VOID NkcRun(NKC_LOG *Log)
{
    NkcCrt(Log);
    NkcFormat(Log);
    NkcStrings(Log);
    NkcSecurity(Log);
    NkcPrefixes(Log);
    NkcWildcards(Log);
    NkcLegal(Log);

    /* 0: back at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
