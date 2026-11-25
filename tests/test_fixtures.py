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
            signed=False, exports=None):
    """Build a tiny but well-formed PE32+ with one section holding the import table.

    `imports`: a name that starts with "#" is an import by that ordinal.
    `exports`: (library name, ordinal base, {ordinal: name or None}).
    """
    sect_rva, sect_raw = 0x1000, 0x200
    blob = bytearray()

    def put(b):
        o = len(blob)
        blob.extend(b)
        return sect_rva + o

    descs = bytearray(20 * (len(imports) + 1))
    blob.extend(descs)
    for i, (dll, names) in enumerate(imports):
        hints = [(1 << 63) | int(n[1:]) if n.startswith("#")
                 else put(struct.pack("<H", 0) + n.encode() + b"\0") for n in names]
        ilt = put(b"".join(struct.pack("<Q", h) for h in hints) + struct.pack("<Q", 0))
        name = put(dll.encode() + b"\0")
        struct.pack_into("<IIIII", blob, 20 * i, ilt, 0, 0, name, ilt)
    export_dir = None
    if exports:
        dll, base, funcs = exports
        count = max(funcs) - base + 1
        named = sorted((name, n) for n, name in funcs.items() if name)
        eat = put(b"".join(struct.pack("<I", 0x1800 + 16 * (base + i) if base + i in funcs else 0)
                           for i in range(count)))
        strings = [put(name.encode() + b"\0") for name, _ in named]
        names = put(b"".join(struct.pack("<I", r) for r in strings))
        ords = put(b"".join(struct.pack("<H", n - base) for _, n in named))
        export_dir = put(struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, put(dll.encode() + b"\0"), base,
                                     count, len(named), eat, names, ords))
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
    if export_dir:
        struct.pack_into("<II", opt, 112, export_dir, 40)
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

    def test_import_by_ordinal(self):
        info = pe.parse(make_pe(imports=(("nkc-lib.sys", ("NkcLibAdd", "#7")),)))
        self.assertEqual(info["imports"], {"nkc-lib.sys": ["#7", "NkcLibAdd"]})
        self.assertNotIn("exports", info)
        self.assertEqual(pe.export_list(info), [])

    def test_exports_by_name_and_by_ordinal_only(self):
        # Ordinals 3..7: 3 and 5 named, 7 without a name, 4 and 6 unused.
        info = pe.parse(make_pe(exports=("nkc-lib.sys", 3, {3: "Beta", 5: "Alpha", 7: None})))
        self.assertEqual(info["exports"], {"name": "nkc-lib.sys", "ordinal_base": 3,
                                           "by_name": {"Alpha": 5, "Beta": 3},
                                           "by_ordinal_only": [7]})
        self.assertEqual(pe.export_list(info), ["#7", "Alpha", "Beta"])

    def test_rejects_garbage(self):
        for bad in (b"", b"MZ" + b"\0" * 100, b"\x7fELF" + b"\0" * 100):
            with self.assertRaises(pe.PeError):
                pe.parse(bad)


def abi_blob(facts, terminate=True):
    """Bytes shaped like the probe's table, surrounded by unrelated data."""
    def entry(name, value):
        return name.encode().ljust(fixtures.ABI_NAME_LEN, b"\0") + value.to_bytes(8, "little")
    body = entry("NKABI-BEGIN v1", 8) + b"".join(entry(n, v) for n, v in facts)
    return b"\x90" * 37 + body + (entry("NKABI-END", 0) if terminate else b"") + b"tail"


class AbiTableTests(unittest.TestCase):
    FACTS = [("sizeof DEVICE_OBJECT", 0x150),
             ("offsetof IRP Tail.Overlay.CurrentStackLocation", 0xB8)]

    def test_extracts_facts_between_markers(self):
        got = fixtures.abi_table(abi_blob(self.FACTS))
        self.assertEqual(got, [("NKABI-BEGIN v1", 8)] + self.FACTS)

    def test_image_without_table(self):
        self.assertIsNone(fixtures.abi_table(make_pe()))

    def test_damaged_table_is_an_error(self):
        with self.assertRaises(ValueError):
            fixtures.abi_table(abi_blob(self.FACTS, terminate=False))

    def test_every_table_in_the_image_is_read(self):
        second = [("sizeof DISPATCHER_CONTEXT", 80)]
        got = fixtures.abi_table(abi_blob(self.FACTS) + abi_blob(second))
        self.assertEqual(got, [("NKABI-BEGIN v1", 8)] + self.FACTS + second)

    def test_a_fact_recorded_twice_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "twice: sizeof DEVICE_OBJECT"):
            fixtures.abi_table(abi_blob(self.FACTS) + abi_blob(self.FACTS[:1]))

    def test_a_damaged_second_table_is_an_error(self):
        with self.assertRaises(ValueError):
            fixtures.abi_table(abi_blob(self.FACTS) + abi_blob(self.FACTS, terminate=False))

    def test_probe_names_fit_the_table(self):
        """Every fact name in the probe must fit, or MSVC rejects the build."""
        import re
        probe = ROOT / "abi-probe"
        limit = int(re.search(r"#define NKABI_NAME_LEN (\d+)",
                              (probe / "probe.h").read_text()).group(1))
        self.assertEqual(limit, fixtures.ABI_NAME_LEN)
        sources = sorted(probe.glob("*.c"))
        self.assertEqual([p.name for p in sources], ["probe-unwind.c", "probe.c"])
        project = (probe / "abi-probe.vcxproj").read_text()
        names = []
        for path in sources:
            self.assertIn(f'<ClCompile Include="{path.name}"', project)
            src = path.read_text()
            names += [f"sizeof {m}" for m in re.findall(r"^\s*SZ\((\w+)\)", src, re.M)]
            names += [f"offsetof {a} {b}"
                      for a, b in re.findall(r"^\s*OFF\((\w+), ([\w.\[\]]+)\)", src, re.M)]
            names += re.findall(r'^\s*\{ "([^"]+)"', src, re.M)
            # Nothing that looks like a fact may escape the patterns above.
            self.assertEqual(len(re.findall(r"^\s*(?:SZ|OFF)\(", src, re.M)),
                             len(re.findall(r"^\s*(?:SZ\(\w+\)|OFF\(\w+, [\w.\[\]]+\))$",
                                            src, re.M)), path.name)
        self.assertGreater(len(names), 500)
        self.assertEqual(len(names), len(set(names)), "duplicate fact name")
        for n in names:
            self.assertLess(len(n), limit, n)


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

    def test_abi_table_is_published_as_text(self):
        cfg = json.loads(self.cfg.read_text())
        cfg["fixtures"].append({"id": "abi-probe", "framework": "WDM", "abi_table": True,
                                "solution": "_nk/abi-probe/abi-probe.vcxproj",
                                "required": ["abi-probe.sys"], "optional": []})
        self.cfg.write_text(json.dumps(cfg))
        d = self.wds / "_nk/abi-probe/x64/Release"
        d.mkdir(parents=True)
        (d / "abi-probe.sys").write_bytes(make_pe() + abi_blob([("sizeof IRP", 208)]))
        self.collect("x64")
        self.assertEqual((self.dist / "abi-probe.x64.txt").read_text(),
                         "NKABI-BEGIN v1 8\nsizeof IRP 208\n")
        m = json.loads((self.dist / "manifest-x64.json").read_text())
        entry = next(f for f in m["files"] if f["name"] == "abi-probe.sys")
        self.assertEqual(entry["abi_table"]["facts"], 2)
        # A probe image that lost its table must not be published.
        (d / "abi-probe.sys").write_bytes(make_pe())
        self.assertIn("no ABI table", self.collect_fail("x64"))

    def linkage(self, expect, image):
        """collect a fixture that states `expect`, built as `image`."""
        cfg = json.loads(self.cfg.read_text())
        cfg["fixtures"] = [{"id": "nkc-x", "framework": "WDM", "solution": "_nk/nkc/nkc-x.vcxproj",
                            "required": ["nkc-x.sys"], "optional": [], "expect": expect}]
        self.cfg.write_text(json.dumps(cfg))
        d = self.wds / "_nk/nkc/nkc-x/x64/Release"
        d.mkdir(parents=True, exist_ok=True)
        (d / "nkc-x.sys").write_bytes(image)

    def test_expected_imports(self):
        want = {"imports": {"nkc-lib.sys": ["NkcLibAdd", "#7"]}}
        self.linkage(want, make_pe(imports=(("nkc-lib.sys", ("#7", "NkcLibAdd")),)))
        self.collect("x64")
        m = json.loads((self.dist / "manifest-x64.json").read_text())
        self.assertEqual(m["files"][0]["pe"]["imports"], {"nkc-lib.sys": ["#7", "NkcLibAdd"]})
        # The linker bound the ordinal-only export by a name instead.
        self.linkage(want, make_pe(imports=(("nkc-lib.sys", ("NkcLibByOrdinal", "NkcLibAdd")),)))
        self.assertIn("imports from nkc-lib.sys are", self.collect_fail("x64"))
        # The import library named some other file.
        self.linkage(want, make_pe(imports=(("nkc-lib.dll", ("#7", "NkcLibAdd")),)))
        self.assertIn("imports from nkc-lib.sys are None", self.collect_fail("x64"))

    def test_expected_exports(self):
        want = {"exports": ["#7", "Alpha", "Beta"]}
        self.linkage(want, make_pe(exports=("nkc-x.sys", 3, {3: "Beta", 5: "Alpha", 7: None})))
        self.collect("x64")
        m = json.loads((self.dist / "manifest-x64.json").read_text())
        self.assertEqual(m["files"][0]["pe"]["exports"]["by_ordinal_only"], [7])
        self.linkage(want, make_pe(exports=("nkc-x.sys", 3, {3: "Beta", 5: "Alpha", 7: "Named"})))
        self.assertIn("exports are", self.collect_fail("x64"))
        self.linkage(want, make_pe())
        self.assertIn("exports are []", self.collect_fail("x64"))

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


class ConfigTests(unittest.TestCase):
    """fixtures.json itself."""

    def setUp(self):
        self.fixtures = {f["id"]: f for f in fixtures.load_config(ROOT / "fixtures.json")["fixtures"]}

    def test_local_fixtures_have_their_sources(self):
        for fx in self.fixtures.values():
            if "local" in fx:
                project = ROOT / fx["local"] / Path(fx["solution"]).name
                self.assertTrue(project.is_file(), project)
                self.assertIn(f"<TargetName>{Path(fx['required'][0]).stem}</TargetName>",
                              project.read_text(), project)

    def test_every_nkc_project_is_a_fixture(self):
        projects = {p.stem for p in (ROOT / "nkc").glob("*.vcxproj")}
        self.assertEqual(projects, {i for i, f in self.fixtures.items() if f.get("local") == "nkc"})

    def test_export_driver_and_its_importers_agree(self):
        exported = set(self.fixtures["nkc-lib"]["expect"]["exports"])
        user = set(self.fixtures["nkc-libuser"]["expect"]["imports"]["nkc-lib.sys"])
        bad = set(self.fixtures["nkc-libbad"]["expect"]["imports"]["nkc-lib.sys"])
        self.assertLessEqual(user, exported)
        self.assertIn("#7", user)
        self.assertEqual(bad - exported, {"NkcLibAbsent"})
        # The module definitions say the same.
        def names(path):
            lines = (ROOT / "nkc" / path).read_text().split("EXPORTS", 1)[1].split("\n")
            return [line.split() for line in lines if line.strip()]
        lib = names("nkc-lib.def")
        self.assertEqual({"#" + w[1][1:] if "NONAME" in w else w[0] for w in lib}, exported)
        self.assertEqual({w[0] for w in names("nkc-libbad.def")}, bad)


if __name__ == "__main__":
    unittest.main()
