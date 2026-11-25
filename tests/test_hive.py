"""Host tests for the hive manifest: its parser, the manifest in this
repository, and how the pipeline records a hive.

Run: python3 -m unittest discover -s tests
"""

import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import fixtures  # noqa: E402
import hive  # noqa: E402

SCRIPT = str(ROOT / "scripts" / "fixtures.py")
U = chr(92) + "u"  # the two characters that start an escape in a quoted field


def one(text):
    """The single value of the single key a manifest describes."""
    (key,) = hive.parse("key K\n" + text)
    (value,) = key.values
    return value


def make_hive(minor=5, bins=4096, dirty=False, bad_checksum=False, extra=b""):
    """A file with a well-formed base block and `bins` bytes after it."""
    base = bytearray(4096)
    base[:4] = b"regf"
    struct.pack_into("<II", base, 4, 7, 8 if dirty else 7)
    struct.pack_into("<6I", base, 0x14, 1, minor, 0, 1, 0x20, bins)
    checksum = 0
    for word in struct.unpack_from("<127I", base, 0):
        checksum ^= word
    struct.pack_into("<I", base, 0x1FC, checksum ^ (1 if bad_checksum else 0))
    return bytes(base) + b"hbin" + b"\0" * (bins - 4) + extra


class ParseTests(unittest.TestCase):
    def test_keys_values_and_order(self):
        keys = hive.parse("# comment\n\nkey A\\B\nvalue One dword 1\n  value Two sz two\n"
                          "key A\\C class Cls\nkey D\n")
        self.assertEqual([k.path for k in keys], ["A\\B", "A\\C", "D"])
        self.assertEqual([k.class_name for k in keys], [None, "Cls", None])
        self.assertEqual([(v.name, v.type, v.data) for v in keys[0].values],
                         [("One", 4, b"\x01\0\0\0"), ("Two", 1, "two\0".encode("utf-16-le"))])
        self.assertEqual(hive.summary(keys), {"keys": 3, "values": 2, "largest_value": 8})

    def test_strings(self):
        self.assertEqual(one("value V sz nk").data, b"n\0k\0\0\0")
        self.assertEqual(one('value V sz ""').data, b"\0\0")
        self.assertEqual(one('value V expand_sz "a b"').data, "a b\0".encode("utf-16-le"))
        self.assertEqual(one("value V expand_sz %SystemRoot%\\x").type, 2)
        self.assertEqual(one("value V multi_sz a bc").data, "a\0bc\0\0".encode("utf-16-le"))
        self.assertEqual(one("value V multi_sz").data, b"\0\0")

    def test_numbers(self):
        self.assertEqual(one("value V dword 0x12345678").data, bytes.fromhex("78563412"))
        self.assertEqual(one("value V dword_be 0x12345678").data, bytes.fromhex("12345678"))
        self.assertEqual(one("value V dword_be 1").type, 5)
        self.assertEqual(one("value V qword 0x0123456789abcdef").data,
                         bytes.fromhex("efcdab8967452301"))
        self.assertEqual(one("value V qword 10").type, 11)

    def test_raw_data_for_any_type(self):
        self.assertEqual(one("value V binary hex:").data, b"")
        self.assertEqual((one("value V none hex:0102").type, one("value V none hex:0102").data),
                         (0, b"\x01\x02"))
        self.assertEqual(one("value V sz hex:6e006b").data, b"n\0k")
        self.assertEqual(one("value V dword hex:01").data, b"\x01")
        self.assertEqual(one("value V resource_list hex:AAbb").type, 8)
        self.assertEqual(one("value V binary counter:0").data, b"")
        self.assertEqual(one("value V binary counter:10").data,
                         bytes.fromhex("00000000010000000200"))
        big = one("value V binary counter:16345").data
        self.assertEqual(len(big), 16345)
        self.assertEqual(big[16340:], bytes.fromhex("f50f0000f6"))

    def test_quoted_fields(self):
        text = f'key "A B{U}00e9\\\\C" class "x y"\nvalue "" sz "q{U}0022"\nvalue "{U}03b1" dword 1\n'
        (key,) = hive.parse(text)
        self.assertEqual((key.path, key.class_name), ("A B\u00e9\\C", "x y"))
        self.assertEqual([v.name for v in key.values], ["", "\u03b1"])
        self.assertEqual(key.values[0].data, 'q"\0'.encode("utf-16-le"))
        # A surrogate pair in escapes is one character, two UTF-16 units.
        (key,) = hive.parse(f'key "{U}d83d{U}de00"\n')
        self.assertEqual(len(key.path.encode("utf-16-le")), 4)

    def test_keys_directive(self):
        keys = hive.parse("keys Many\\K 3\n")
        self.assertEqual([k.path for k in keys], ["Many\\K0000", "Many\\K0001", "Many\\K0002"])

    def test_errors_name_the_line(self):
        for text, why in (
                ("", "names no key"),
                ("value V dword 1", "line 1: a value needs a key"),
                ("keys P 2\nvalue V dword 1", "line 2: a value needs a key"),
                ("key A\nkey a", "line 2: key 'a' is already there"),
                ("key A\nvalue V dword 1\nvalue v dword 2", "line 3: value 'v' is already there"),
                ("key A\\B\nkey A class C", "line 2: a key with a class must come before"),
                ("key A\\\\B", "empty component"),
                ("key \\A", "empty component"),
                ("key " + "k" * 256, "longer than 255"),
                ("key A B", "expected: key"),
                ("key A klass B", "expected: key"),
                ("keys A", "expected: keys"),
                ("keys A 0", "expected: keys"),
                ("keys A many", "expected: keys"),
                ("key A\nvalue V", "expected: value"),
                ("key A\nvalue V word 1", "unknown type 'word'"),
                ("key A\nvalue V dword", "takes one number"),
                ("key A\nvalue V dword 1 2", "takes one number"),
                ("key A\nvalue V dword 0x100000000", "takes one number below 2^32"),
                ("key A\nvalue V dword -1", "takes one number"),
                ("key A\nvalue V dword one", "takes one number"),
                ("key A\nvalue V sz a b", "takes one string"),
                ("key A\nvalue V sz", "takes one string"),
                ('key A\nvalue V multi_sz a "" b', "end a multi_sz early"),
                ("key A\nvalue V binary 0102", "takes hex:"),
                ("key A\nvalue V binary hex:0", "bad hex data"),
                ("key A\nvalue V binary hex:zz", "bad hex data"),
                ("key A\nvalue V binary counter:x", "bad length"),
                ("key A\nvalue V binary counter:2000000", "at most 1 MiB"),
                ('key A\nvalue "V dword 1', "bad quoted string"),
                ('key A\nvalue "V"x dword 1', "must be followed by a space"),
                ('key A\nvalue V"x dword 1', "a quote inside a bare word"),
                (f'key "{U}d83d"', "half of a surrogate pair"),
                ("key caf\u00e9", "not ASCII"),
                ("link A B", "unknown line kind 'link'"),
        ):
            with self.assertRaises(hive.ManifestError, msg=text) as raised:
                hive.parse(text)
            self.assertIn(why, str(raised.exception), text)


class SystemHiveTests(unittest.TestCase):
    """The manifest this repository publishes as system.hiv."""

    @classmethod
    def setUpClass(cls):
        text = (ROOT / "hive" / "system.hive.txt").read_text(encoding="ascii")
        cls.keys = {k.path: k for k in hive.parse(text)}

    def values(self, path):
        return {v.name: v for v in self.keys[path].values}

    def test_boot_content(self):
        select = self.values("Select")
        self.assertEqual({n: v.data for n, v in select.items()},
                         {n: b"\x01\0\0\0" for n in ("Current", "Default", "LastKnownGood")})
        groups = self.values("ControlSet001\\Control\\ServiceGroupOrder")["List"]
        self.assertEqual(groups.type, 7)
        order = groups.data.decode("utf-16-le").split("\0")[:-2]
        self.assertEqual(order[-2:], ["Base", "File System"])
        self.assertEqual(self.keys["ControlSet001\\Control\\Class"].values, [])
        for name in ("Null", "Npfs", "msrpc", "wmilib", "wpprecorder"):
            service = self.values(f"ControlSet001\\Services\\{name}")
            self.assertEqual([service[n].type for n in ("Type", "Start", "ErrorControl")],
                             [4, 4, 4], name)
            self.assertEqual(service["ImagePath"].type, 2, name)
            if "Group" in service:
                self.assertIn(service["Group"].data.decode("utf-16-le").rstrip("\0"), order)

    def test_format_exercise(self):
        test = "ControlSet001\\Control\\NkTest"
        self.assertEqual({v.type for v in self.values(f"{test}\\Types").values()},
                         {0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11})
        sizes = {len(v.data) for v in self.values(f"{test}\\Sizes").values()}
        self.assertLessEqual({0, 1, 2, 3, 4, 5, 16344, 16345}, sizes)
        self.assertGreater(max(sizes), 2 * hive.MAX_CELL_DATA)
        self.assertEqual(self.keys[f"{test}\\Class"].class_name, "NkClass \u03ba")
        self.assertEqual(self.values(test)[""].type, 1)
        children = [p for p in self.keys if p.startswith(f"{test}\\Many\\")]
        self.assertGreater(len(children), 1024)
        names = list(self.values(f"{test}\\Names")) + [
            p.rsplit("\\", 1)[1] for p in self.keys if p.startswith(f"{test}\\Names\\")]
        self.assertTrue(any(n.isascii() for n in names))
        self.assertTrue(any(not n.isascii() and max(n) < "\u0100" for n in names))
        self.assertTrue(any(max(n) >= "\u0100" for n in names))
        self.assertTrue(any(max(n) > "\uffff" for n in names))


class InspectTests(unittest.TestCase):
    def test_clean_hive(self):
        info = hive.inspect(make_hive())
        self.assertEqual((info["version"], info["root_cell"], info["bins_length"]),
                         ("1.5", 0x20, 4096))
        self.assertTrue(info["checksum_ok"] and info["clean"] and info["file_length_matches"])

    def test_what_is_wrong(self):
        self.assertFalse(hive.inspect(make_hive(dirty=True))["clean"])
        self.assertFalse(hive.inspect(make_hive(bad_checksum=True))["checksum_ok"])
        self.assertFalse(hive.inspect(make_hive(extra=b"x"))["file_length_matches"])
        for bad in (b"", b"regf", b"MZ" + b"\0" * 5000):
            with self.assertRaises(ValueError):
                hive.inspect(bad)


class PipelineTests(unittest.TestCase):
    HV = {"id": "hive-system", "manifest": "hive/system.hive.txt", "asset": "system.hiv"}

    def setUp(self):
        self.keys = hive.parse((ROOT / self.HV["manifest"]).read_text(encoding="ascii"))

    def test_entry_records_the_hive(self):
        image = make_hive()
        entry = fixtures.hive_entry(self.HV, self.keys, image)
        self.assertEqual((entry["hive"], entry["asset"], entry["size"]),
                         ("hive-system", "system.hiv", len(image)))
        self.assertEqual(entry["source_sha256"], fixtures.sha256(ROOT / self.HV["manifest"]))
        self.assertEqual(entry["regf"]["version"], "1.5")
        self.assertEqual(entry["keys"], len(self.keys))

    def test_entry_refuses_a_hive_that_will_not_do(self):
        for image in (b"not a hive", make_hive(dirty=True), make_hive(bad_checksum=True),
                      make_hive(extra=b"x"),
                      make_hive(minor=3)):  # no big-data cells before version 1.4
            with self.assertRaises(SystemExit):
                fixtures.hive_entry(self.HV, self.keys, image)

    def test_finalize_merges_the_hive(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            dist.mkdir()
            cfg = Path(tmp) / "fixtures.json"
            cfg.write_text(json.dumps({
                "schema": 1, "upstream": {"repo": "x/y", "commit": "0" * 40, "license": "MS-PL"},
                "configuration": "Release", "archs": ["x64"], "hives": [self.HV],
                "nt_target": "19041", "fixtures": []}))
            (dist / "manifest-x64.json").write_text(json.dumps(
                {"arch": "x64", "bundle": "nk-fixtures-x64.zip", "build": {}, "files": []}))

            def finalize(ok):
                r = subprocess.run([sys.executable, SCRIPT, "--config", str(cfg), "finalize",
                                    "--dist", str(dist), "--tag", "v6"],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode == 0, ok, r.stdout + r.stderr)
                return r.stderr

            self.assertIn("no hive-manifest.json", finalize(False))
            image = make_hive()
            entry = fixtures.hive_entry(self.HV, self.keys, image)
            part = json.dumps({"build": {"run_url": None}, "hives": [entry]})
            (dist / fixtures.HIVE_MANIFEST).write_text(part)
            self.assertIn("system.hiv is missing", finalize(False))
            (dist / "system.hiv").write_bytes(image + b"tampered")
            self.assertIn("not the file its record describes", finalize(False))
            (dist / "system.hiv").write_bytes(image)
            finalize(True)
            self.assertEqual(sorted(p.name for p in dist.iterdir()),
                             ["SHA256SUMS", "manifest.json", "system.hiv"])
            m = json.loads((dist / "manifest.json").read_text())
            self.assertEqual(m["hives"]["files"][0]["sha256"], fixtures.sha256(dist / "system.hiv"))
            self.assertIn("  system.hiv\n", (dist / "SHA256SUMS").read_text())


if __name__ == "__main__":
    unittest.main()
