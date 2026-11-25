"""Minimal PE32+ reader: just the metadata the fixture manifest records.

Standard library only, so it runs unchanged on the Windows build runner and
on the Linux release job.
"""

import struct

MACHINES = {0x8664: "x64", 0xAA64: "arm64", 0x14C: "x86"}
ORDINAL_FLAG64 = 1 << 63


class PeError(ValueError):
    pass


def _cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("ascii", "replace")


def parse(data):
    """Return a dict of PE metadata for a PE32+ image, or raise PeError."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PeError("not an MZ image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise PeError("missing PE signature")
    machine, nsect, timestamp, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise PeError("not PE32+")
    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    checksum = struct.unpack_from("<I", data, opt + 64)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    ndirs = struct.unpack_from("<I", data, opt + 108)[0]
    dirs = [struct.unpack_from("<II", data, opt + 112 + 8 * i) for i in range(min(ndirs, 16))]

    sections = []
    sect = opt + opt_size
    for i in range(nsect):
        name, vsize, va, rsize, raw = struct.unpack_from("<8sIIII", data, sect + 40 * i)
        sections.append((name.rstrip(b"\0").decode("ascii", "replace"), va, vsize, raw, rsize))

    def off(rva):
        for _, va, vsize, raw, rsize in sections:
            if va <= rva < va + max(vsize, rsize):
                return raw + (rva - va)
        raise PeError(f"rva {rva:#x} outside all sections")

    imports = {}
    if len(dirs) > 1 and dirs[1][0]:
        desc = off(dirs[1][0])
        while True:
            ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", data, desc)
            if not name_rva:
                break
            names = []
            thunk = off(ilt or iat)
            while True:
                val = struct.unpack_from("<Q", data, thunk)[0]
                if not val:
                    break
                if val & ORDINAL_FLAG64:
                    names.append(f"#{val & 0xFFFF}")
                else:
                    names.append(_cstr(data, off(val & 0x7FFFFFFF) + 2))
                thunk += 8
            imports.setdefault(_cstr(data, off(name_rva)), []).extend(names)
            desc += 20

    return {
        "machine": MACHINES.get(machine, f"{machine:#06x}"),
        "timestamp": timestamp,
        "image_base": f"{image_base:#x}",
        "size_of_image": size_of_image,
        "entry_rva": entry_rva,
        "checksum": checksum,
        "subsystem": subsystem,
        "sections": [s[0] for s in sections],
        "has_relocations": len(dirs) > 5 and dirs[5][1] > 0,
        "has_exception_table": len(dirs) > 3 and dirs[3][1] > 0,
        "signed": len(dirs) > 4 and dirs[4][1] > 0,
        "imports": {dll: sorted(names) for dll, names in sorted(imports.items())},
    }
