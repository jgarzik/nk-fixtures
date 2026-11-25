"""Host tests for the parts that do not need Windows: PE parsing, collect, finalize.

Run: python3 -m unittest discover -s tests
"""

import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import fixtures  # noqa: E402
import pe  # noqa: E402

SCRIPT = str(ROOT / "scripts" / "fixtures.py")


def make_pe(machine=0x8664, imports=(("ntoskrnl.exe", ("IoCreateDevice", "IofCompleteRequest")),),
            signed=False):
    """Build a tiny but well-formed PE32+ with one section holding the import table."""
    sect_rva, sect_raw = 0x1000, 0x200
    blob = bytearray()

    def put(b):
        o = len(blob)
        blob.extend(b)
        return sect_rva + o

    descs = bytearray(20 * (len(imports) + 1))
    blob.extend(descs)
    for i, (dll, names) in enumerate(imports):
        hints = [put(struct.pack("<H", 0) + n.encode() + b"\0") for n in names]
        ilt = put(b"".join(struct.pack("<Q", h) for h in hints) + struct.pack("<Q", 0))
        name = put(dll.encode() + b"\0")
        struct.pack_into("<IIIII", blob, 20 * i, ilt, 0, 0, name, ilt)
    blob.extend(b"\0" * (-len(blob) % 0x200))

    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", machine, 1, 0x5F000000, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<I", opt, 56, 0x2000)
    struct.pack_into("<H", opt, 68, 1)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112 + 8 * 1, sect_rva, 20 * (len(imports) + 1))
    if signed:
        struct.pack_into("<II", opt, 112 + 8 * 4, 0x400, 8)
    sect = struct.pack("<8sIIIIIIHHI", b".rdata", len(blob), sect_rva, len(blob), sect_raw,
                       0, 0, 0, 0, 0x40000040)
    hdr = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sect
    return hdr + b"\0" * (sect_raw - len(hdr)) + bytes(blob)


class PeTests(unittest.TestCase):
    def test_imports_and_machine(self):
        info = pe.parse(make_pe())
        self.assertEqual(info["machine"], "x64")
        self.assertEqual(info["imports"], {"ntoskrnl.exe": ["IoCreateDevice", "IofCompleteRequest"]})
        self.assertFalse(info["signed"])
        self.assertEqual(info["size_of_image"], 0x2000)

    def test_arm64_signed_two_dlls(self):
        info = pe.parse(make_pe(0xAA64, (("ntoskrnl.exe", ("DbgPrint",)),
                                         ("WDFLDR.SYS", ("WdfVersionBind",))), signed=True))
        self.assertEqual(info["machine"], "arm64")
        self.assertEqual(sorted(info["imports"]), ["WDFLDR.SYS", "ntoskrnl.exe"])
        self.assertTrue(info["signed"])

    def test_rejects_garbage(self):
        for bad in (b"", b"MZ" + b"\0" * 100, b"\x7fELF" + b"\0" * 100):
            with self.assertRaises(pe.PeError):
                pe.parse(bad)


class NtTargetTests(unittest.TestCase):
    VERS = [{"Version": "10.0.28000", "Tag": "28000", "Code": "0xA000012", "Build": 28000},
            {"Version": "10.0.19041", "Tag": "19041", "Code": "0xA000008", "Build": 19041},
            {"Version": "10.0.22000", "Tag": "22000", "Code": "0xA00000B", "Build": 22000}]

    def test_exact(self):
        v, fell = fixtures.pick_nt_target(self.VERS, "19041", "oldest")
        self.assertEqual((v["Code"], fell), ("0xA000008", False))

    def test_fallback_oldest(self):
        v, fell = fixtures.pick_nt_target(self.VERS[::2], "19041", "oldest")
        self.assertEqual((v["Tag"], fell), ("22000", True))

    def test_no_fallback_dies(self):
        with self.assertRaises(SystemExit):
            fixtures.pick_nt_target(self.VERS[:1], "19041", None)


class PipelineTests(unittest.TestCase):
    """collect + finalize over a fake msbuild output tree."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.cfg = self.dir / "fixtures.json"
        self.cfg.write_text(json.dumps({
            "schema": 1,
            "upstream": {"repo": "x/y", "commit": "0" * 40, "license": "MS-PL"},
            "configuration": "Release", "archs": ["x64", "arm64"],
            "nt_target": "19041", "nt_target_fallback": "oldest",
            "fixtures": [{"id": "wdm-ioctl", "framework": "WDM",
                          "solution": "general/ioctl/wdm/ioctl.sln",
                          "required": ["sioctl.sys"], "optional": ["sioctl.pdb"]}]}))
        self.wds = self.dir / "wds"
        (self.wds / "LICENSE").parent.mkdir(parents=True)
        (self.wds / "LICENSE").write_text("MS-PL\n")
        for plat, machine in (("x64", 0x8664), ("ARM64", 0xAA64)):
            d = self.wds / "general/ioctl/wdm/sys" / plat / "Release"
            d.mkdir(parents=True)
            (d / "sioctl.sys").write_bytes(make_pe(machine))
            (d / "sioctl.pdb").write_bytes(b"pdb")
        # A Debug build must never be picked up.
        dbg = self.wds / "general/ioctl/wdm/sys/x64/Debug"
        dbg.mkdir(parents=True)
        (dbg / "sioctl.sys").write_bytes(make_pe() + b"debug")
        self.dist = self.dir / "dist"

    def fx(self, *args, ok=True):
        r = subprocess.run([sys.executable, SCRIPT, "--config", str(self.cfg), *args],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode == 0, ok, r.stdout + r.stderr)
        return r

    def collect(self, arch):
        return self.fx("collect", "--arch", arch, "--wds", str(self.wds), "--out", str(self.dist))

    def test_collect_finalize(self):
        self.collect("x64")
        self.collect("arm64")
        self.fx("finalize", "--dist", str(self.dist), "--tag", "v1")
        names = sorted(p.name for p in self.dist.iterdir())
        self.assertEqual(names, ["SHA256SUMS", "manifest.json", "nk-fixtures-arm64.zip",
                                 "nk-fixtures-x64.zip", "wdm-ioctl.arm64.sioctl.sys",
                                 "wdm-ioctl.x64.sioctl.sys"])
        m = json.loads((self.dist / "manifest.json").read_text())
        self.assertEqual(m["fixture_set"], "v1")
        sys_x64 = next(f for f in m["files"] if f["arch"] == "x64" and f["name"] == "sioctl.sys")
        self.assertEqual(sys_x64["sha256"], fixtures.sha256(self.dist / "wdm-ioctl.x64.sioctl.sys"))
        self.assertEqual(sys_x64["pe"]["imports"]["ntoskrnl.exe"],
                         ["IoCreateDevice", "IofCompleteRequest"])
        self.assertNotIn("variants", sys_x64)
        with zipfile.ZipFile(self.dist / "nk-fixtures-x64.zip") as z:
            self.assertEqual(sorted(z.namelist()),
                             ["LICENSES/Windows-driver-samples.LICENSE",
                              "wdm-ioctl/sioctl.pdb", "wdm-ioctl/sioctl.sys"])
        sums = (self.dist / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(sums), 5)

    def test_zip_is_deterministic(self):
        self.collect("x64")
        first = (self.dist / "nk-fixtures-x64.zip").read_bytes()
        self.collect("x64")
        self.assertEqual(first, (self.dist / "nk-fixtures-x64.zip").read_bytes())

    def test_differing_copy_is_recorded(self):
        pkg = self.wds / "general/ioctl/wdm/sys/x64/Release/package"
        pkg.mkdir()
        (pkg / "sioctl.sys").write_bytes(make_pe(signed=True))
        r = self.collect("x64")
        self.assertIn("differing copies", r.stdout)
        m = json.loads((self.dist / "manifest-x64.json").read_text())
        entry = next(f for f in m["files"] if f["name"] == "sioctl.sys")
        self.assertEqual(len(entry["variants"]), 1)
        self.assertFalse(entry["pe"]["signed"])

    def test_missing_required_fails(self):
        (self.wds / "general/ioctl/wdm/sys/ARM64/Release/sioctl.sys").unlink()
        self.assertIn("required output", self.collect_fail("arm64"))

    def test_wrong_machine_fails(self):
        (self.wds / "general/ioctl/wdm/sys/ARM64/Release/sioctl.sys").write_bytes(make_pe(0x8664))
        self.assertIn("expected arm64", self.collect_fail("arm64"))

    def collect_fail(self, arch):
        return self.fx("collect", "--arch", arch, "--wds", str(self.wds),
                       "--out", str(self.dist), ok=False).stderr

    def test_finalize_requires_all_archs(self):
        self.collect("x64")
        r = self.fx("finalize", "--dist", str(self.dist), "--tag", "v1", ok=False)
        self.assertIn("missing arch", r.stderr)


if __name__ == "__main__":
    unittest.main()
