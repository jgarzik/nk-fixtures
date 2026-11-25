"""Registry hive fixtures: a text manifest in, a hive written by Windows out.

parse()    reads the manifest format documented at the top of
           hive/system.hive.txt (any OS)
build()    has Windows' own registry create the keys and values in a hive
           that starts empty, and save it to a file (Windows, elevated)
inspect()  reads the base block of a hive file (any OS)

Standard library only.
"""

import json
import os
import struct

REG_TYPES = {
    "none": 0, "sz": 1, "expand_sz": 2, "binary": 3, "dword": 4, "dword_be": 5,
    "multi_sz": 7, "resource_list": 8, "full_resource_descriptor": 9,
    "resource_requirements_list": 10, "qword": 11,
}
STRING_TYPES = ("sz", "expand_sz")
NUMBER_TYPES = {"dword": ("<I", 32), "dword_be": (">I", 32), "qword": ("<Q", 64)}
MAX_KEY_NAME = 255      # characters in one path component
MAX_VALUE_NAME = 16383  # characters
# Data longer than this does not fit one cell: a hive of version 1.4 or
# later splits it into segments under a "big data" record.
MAX_CELL_DATA = 16344
BASE_BLOCK = 4096


class ManifestError(ValueError):
    pass


class Key:
    def __init__(self, path, class_name=None):
        self.path = path              # components joined by "\\"
        self.class_name = class_name  # str or None
        self.values = []              # [Value], in manifest order


class Value:
    def __init__(self, name, type_name, data):
        self.name = name              # "" is the key's unnamed value
        self.type_name = type_name
        self.type = REG_TYPES[type_name]
        self.data = data              # bytes, exactly as stored


def _fields(line):
    """Split a line into fields: bare words, or JSON strings in quotes."""
    out, i, n = [], 0, len(line)
    decoder = json.JSONDecoder()
    while i < n:
        if line[i] == " ":
            i += 1
        elif line[i] == '"':
            try:
                text, end = decoder.raw_decode(line, i)
            except json.JSONDecodeError as e:
                raise ManifestError(f"bad quoted string: {e.msg}") from None
            if end < n and line[end] != " ":
                raise ManifestError("a quoted string must be followed by a space")
            out.append(text)
            i = end
        else:
            end = line.find(" ", i)
            end = n if end < 0 else end
            if '"' in line[i:end]:
                raise ManifestError("a quote inside a bare word")
            out.append(line[i:end])
            i = end
    return out


def _utf16(text):
    try:
        return text.encode("utf-16-le")
    except UnicodeEncodeError:
        raise ManifestError("a string holds half of a surrogate pair") from None


def _raw(field):
    """Raw data: hex:<digits> or counter:<length>. None if `field` is neither."""
    if field.startswith("hex:"):
        try:
            return bytes.fromhex(field[4:])
        except ValueError:
            raise ManifestError(f"bad hex data {field[4:]!r}") from None
    if field.startswith("counter:"):
        try:
            length = int(field[8:], 0)
        except ValueError:
            raise ManifestError(f"bad length {field[8:]!r}") from None
        if not 0 <= length <= 1 << 20:
            raise ManifestError("counter data is at most 1 MiB")
        words = b"".join(struct.pack("<I", i) for i in range((length + 3) // 4))
        return words[:length]
    return None


def _data(type_name, fields):
    if len(fields) == 1:
        raw = _raw(fields[0])
        if raw is not None:
            return raw
    if type_name in STRING_TYPES:
        if len(fields) != 1:
            raise ManifestError(f"{type_name} takes one string")
        return _utf16(fields[0] + "\0")
    if type_name == "multi_sz":
        if "" in fields:
            raise ManifestError("an empty string would end a multi_sz early")
        return _utf16("".join(f + "\0" for f in fields) + "\0")
    if type_name in NUMBER_TYPES:
        fmt, bits = NUMBER_TYPES[type_name]
        try:
            number = int(fields[0], 0) if len(fields) == 1 else None
        except ValueError:
            number = None
        if number is None or not 0 <= number < 1 << bits:
            raise ManifestError(f"{type_name} takes one number below 2^{bits}")
        return struct.pack(fmt, number)
    raise ManifestError(f"{type_name} takes hex:<digits> or counter:<length>")


def _path(text):
    parts = text.split("\\")
    for part in parts:
        if not part:
            raise ManifestError("a key path has an empty component")
        if len(part) > MAX_KEY_NAME:
            raise ManifestError(f"a key name is longer than {MAX_KEY_NAME} characters")
        _utf16(part)
    return "\\".join(parts)


def parse(text):
    """The keys a manifest describes, as [Key], in manifest order.

    Keys and value names are compared as Windows compares them, without
    regard to case (approximated by str.upper, which is exact for the
    names a manifest should use). Raises ManifestError with a line number.
    """
    keys, seen, current = [], {}, None

    def add(path, class_name):
        folded = path.upper()
        if folded in seen:
            raise ManifestError(f"key {path!r} is already there")
        if class_name is not None and any(k.startswith(folded + "\\") for k in seen):
            raise ManifestError("a key with a class must come before the keys under it")
        key = seen[folded] = Key(path, class_name)
        keys.append(key)
        return key

    for number, line in enumerate(text.split("\n"), 1):
        try:
            if not line.isascii():
                raise ManifestError("not ASCII: write other characters as \\uXXXX in quotes")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields = _fields(line)
            what, args = fields[0], fields[1:]
            if what == "key":
                if len(args) == 1:
                    current = add(_path(args[0]), None)
                elif len(args) == 3 and args[1] == "class":
                    current = add(_path(args[0]), args[2])
                    _utf16(args[2])
                else:
                    raise ManifestError("expected: key <path> [class <string>]")
            elif what == "keys":
                try:
                    count = int(args[1], 0) if len(args) == 2 else -1
                except ValueError:
                    count = -1
                if not 1 <= count <= 10000:
                    raise ManifestError("expected: keys <path-prefix> <count, 1 to 10000>")
                for i in range(count):
                    add(_path(f"{args[0]}{i:04d}"), None)
                current = None
            elif what == "value":
                if current is None:
                    raise ManifestError("a value needs a key line before it")
                if len(args) < 2:
                    raise ManifestError("expected: value <name> <type> <data...>")
                name, type_name = args[0], args[1]
                if type_name not in REG_TYPES:
                    raise ManifestError(f"unknown type {type_name!r}")
                if len(name) > MAX_VALUE_NAME:
                    raise ManifestError("value name too long")
                _utf16(name)
                if any(v.name.upper() == name.upper() for v in current.values):
                    raise ManifestError(f"value {name!r} is already there")
                current.values.append(Value(name, type_name, _data(type_name, args[2:])))
            else:
                raise ManifestError(f"unknown line kind {what!r}")
        except ManifestError as e:
            raise ManifestError(f"line {number}: {e}") from None
    if not keys:
        raise ManifestError("the manifest names no key")
    return keys


def summary(keys):
    values = [v for k in keys for v in k.values]
    return {"keys": len(keys), "values": len(values),
            "largest_value": max((len(v.data) for v in values), default=0)}


# --- reading a hive's base block ----------------------------------------------

def inspect(data):
    """What the base block of a hive file says. Raises ValueError if `data`
    is not a hive."""
    if len(data) < BASE_BLOCK or data[:4] != b"regf":
        raise ValueError("not a registry hive (no regf signature)")
    seq1, seq2 = struct.unpack_from("<II", data, 4)
    major, minor, file_type, file_format, root_cell, length = struct.unpack_from("<6I", data, 0x14)
    checksum = 0
    for word in struct.unpack_from("<127I", data, 0):
        checksum ^= word
    checksum = {0: 1, 0xFFFFFFFF: 0xFFFFFFFE}.get(checksum, checksum)
    return {
        "version": f"{major}.{minor}", "major": major, "minor": minor,
        "type": file_type, "format": file_format, "root_cell": root_cell,
        "bins_length": length,
        "file_length_matches": len(data) == BASE_BLOCK + length,
        "checksum_ok": checksum == struct.unpack_from("<I", data, 0x1FC)[0],
        # Unequal sequence numbers mean a write was in progress: the file
        # would need its transaction logs.
        "clean": seq1 == seq2,
    }


# --- writing a hive with Windows ----------------------------------------------

KEY_ALL_ACCESS = 0xF003F
REG_LATEST_FORMAT = 2
REG_CREATED_NEW_KEY = 1
ERROR_NOT_ALL_ASSIGNED = 1300


def build(keys, out_path, work_dir, mount="NKHIVE"):
    """Have Windows write `keys` into a new hive file at `out_path`.

    1. An empty key is created under HKLM\\SOFTWARE and saved to a file:
       that file is an empty hive.
    2. The empty hive is loaded at HKLM\\<mount>.
    3. Every key is created with RegCreateKeyExW (which takes the class)
       and every value set with NtSetValueKey, the system call behind a
       driver's ZwSetValueKey: the bytes stored are exactly the
       manifest's, where RegSetValueExW would add a missing terminator
       to a string.
    4. The loaded hive is saved to `out_path` in the latest hive format
       (RegSaveKeyExW, REG_LATEST_FORMAT) and unloaded.

    Needs the backup and restore privileges, so an elevated process.
    """
    import ctypes
    from ctypes import wintypes

    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    HKEY = ctypes.c_void_p
    HKLM = HKEY(0x80000002)

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", LUID),
                    ("Attributes", wintypes.DWORD)]

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                    ("Buffer", ctypes.c_void_p)]

    def declare(fn, restype, *argtypes):
        fn.restype, fn.argtypes = restype, argtypes
        return fn

    LONG, DWORD, LPCWSTR = wintypes.LONG, wintypes.DWORD, wintypes.LPCWSTR
    GetCurrentProcess = declare(k32.GetCurrentProcess, wintypes.HANDLE)
    CloseHandle = declare(k32.CloseHandle, wintypes.BOOL, wintypes.HANDLE)
    OpenProcessToken = declare(adv.OpenProcessToken, wintypes.BOOL, wintypes.HANDLE, DWORD,
                               ctypes.POINTER(wintypes.HANDLE))
    LookupPrivilegeValue = declare(adv.LookupPrivilegeValueW, wintypes.BOOL, LPCWSTR, LPCWSTR,
                                   ctypes.POINTER(LUID))
    AdjustTokenPrivileges = declare(adv.AdjustTokenPrivileges, wintypes.BOOL, wintypes.HANDLE,
                                    wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), DWORD,
                                    ctypes.c_void_p, ctypes.c_void_p)
    RegCreateKeyEx = declare(adv.RegCreateKeyExW, LONG, HKEY, LPCWSTR, DWORD, LPCWSTR, DWORD,
                             DWORD, ctypes.c_void_p, ctypes.POINTER(HKEY),
                             ctypes.POINTER(DWORD))
    RegCloseKey = declare(adv.RegCloseKey, LONG, HKEY)
    RegDeleteKey = declare(adv.RegDeleteKeyW, LONG, HKEY, LPCWSTR)
    RegSaveKeyEx = declare(adv.RegSaveKeyExW, LONG, HKEY, LPCWSTR, ctypes.c_void_p, DWORD)
    RegLoadKey = declare(adv.RegLoadKeyW, LONG, HKEY, LPCWSTR, LPCWSTR)
    RegUnLoadKey = declare(adv.RegUnLoadKeyW, LONG, HKEY, LPCWSTR)
    NtSetValueKey = declare(ntdll.NtSetValueKey, LONG, HKEY, ctypes.POINTER(UNICODE_STRING),
                            wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG)

    def check(error, what):
        if error:
            raise OSError(f"{what}: {ctypes.FormatError(error).strip()} (error {error})")

    def enable(privilege):
        token = wintypes.HANDLE()
        if not OpenProcessToken(GetCurrentProcess(), 0x28, ctypes.byref(token)):
            check(ctypes.get_last_error(), "OpenProcessToken")
        try:
            wanted = TOKEN_PRIVILEGES(1, LUID(), 2)  # SE_PRIVILEGE_ENABLED
            if not LookupPrivilegeValue(None, privilege, ctypes.byref(wanted.Luid)):
                check(ctypes.get_last_error(), f"LookupPrivilegeValue {privilege}")
            ctypes.set_last_error(0)
            ok = AdjustTokenPrivileges(token, False, ctypes.byref(wanted), 0, None, None)
            error = ctypes.get_last_error()
            if not ok or error == ERROR_NOT_ALL_ASSIGNED:
                check(error or 1, f"enable {privilege} (is the process elevated?)")
        finally:
            CloseHandle(token)

    def create(parent, path, class_name=None):
        key, disposition = HKEY(), DWORD()
        check(RegCreateKeyEx(parent, path, 0, class_name, 0, KEY_ALL_ACCESS, None,
                             ctypes.byref(key), ctypes.byref(disposition)),
              f"create key {path!r}")
        return key, disposition.value

    def remove(path):
        for name in (path, path + ".LOG1", path + ".LOG2"):
            try:
                os.remove(name)
            except OSError:
                pass  # not there, or still held by a hive that would not unload

    def populate(root):
        for entry in keys:
            key, disposition = create(root, entry.path, entry.class_name)
            try:
                if entry.class_name is not None and disposition != REG_CREATED_NEW_KEY:
                    raise OSError(f"key {entry.path!r} existed before its class could be set")
                for value in entry.values:
                    name = ctypes.create_unicode_buffer(value.name)
                    length = len(value.name.encode("utf-16-le"))
                    string = UNICODE_STRING(length, length, ctypes.addressof(name))
                    size = len(value.data)
                    data = (ctypes.c_ubyte * max(size, 1)).from_buffer_copy(
                        value.data.ljust(1, b"\0"))
                    status = NtSetValueKey(key, ctypes.byref(string), 0, value.type, data, size)
                    if status < 0:
                        raise OSError(f"set value {value.name!r} of {entry.path!r}: "
                                      f"status {status & 0xFFFFFFFF:#010x}")
            finally:
                RegCloseKey(key)

    enable("SeBackupPrivilege")
    enable("SeRestorePrivilege")

    out_path = os.path.abspath(out_path)
    seed_file = os.path.join(os.path.abspath(work_dir), "empty.hiv")
    seed_key = f"SOFTWARE\\NkHiveSeed-{os.getpid()}"
    remove(seed_file)
    remove(out_path)

    key, _ = create(HKLM, seed_key)
    try:
        check(RegSaveKeyEx(key, seed_file, None, REG_LATEST_FORMAT), "save the empty key")
    finally:
        RegCloseKey(key)
        RegDeleteKey(HKLM, seed_key)

    check(RegLoadKey(HKLM, mount, seed_file), f"load the empty hive at HKLM\\{mount}")
    try:
        root, _ = create(HKLM, mount)
        try:
            populate(root)
            check(RegSaveKeyEx(root, out_path, None, REG_LATEST_FORMAT), "save the hive")
        finally:
            RegCloseKey(root)
    except BaseException:
        RegUnLoadKey(HKLM, mount)
        remove(seed_file)
        raise
    check(RegUnLoadKey(HKLM, mount), f"unload HKLM\\{mount}")
    remove(seed_file)
