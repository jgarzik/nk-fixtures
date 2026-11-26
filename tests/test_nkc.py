"""Host tests for the conformance drivers' sources: what can be held to
without a compiler.

Run: python3 -m unittest discover -s tests
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NKC = ROOT / "nkc"


def undoc_names():
    """The routines nkc-undoc.h declares or gives a pointer type for."""
    text = (NKC / "nkc-undoc.h").read_text()
    code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    protos = re.findall(r"\bNTAPI\s+(\w+)\s*\(", code)
    return [n for n in protos if not n.endswith("_CALLBACK")]


class NkcSourceTests(unittest.TestCase):
    def test_project_guids_are_unique(self):
        seen = {}
        for project in sorted(NKC.glob("*.vcxproj")):
            guids = re.findall(r"<ProjectGuid>(\{[0-9A-F-]+\})</ProjectGuid>", project.read_text())
            self.assertEqual(len(guids), 1, project.name)
            self.assertNotIn(guids[0], seen, f"{project.name} and {seen.get(guids[0])}")
            seen[guids[0]] = project.name

    def test_a_project_compiles_its_own_source(self):
        for project in sorted(NKC.glob("*.vcxproj")):
            self.assertIn(f'<ClCompile Include="{project.stem}.c" />', project.read_text(),
                          project.name)
            self.assertTrue((NKC / f"{project.stem}.c").is_file(), project.name)

    def test_every_driver_has_a_row_in_the_readme(self):
        readme = (ROOT / "README.md").read_text()
        for project in sorted(NKC.glob("*.vcxproj")):
            self.assertRegex(readme, rf"(?m)^\| `{re.escape(project.stem)}` \|", project.name)

    def test_a_device_is_named_as_the_readme_says(self):
        readme = (ROOT / "README.md").read_text()
        for source in sorted(NKC.glob("*.c")):
            device = re.search(r'#define NKC_DEVICE L"\\\\Device\\\\(\w+)"', source.read_text())
            if device:
                self.assertRegex(readme,
                                 rf"(?m)^\| `{re.escape(source.stem)}` \| `{device.group(1)}` \|",
                                 source.name)

    def test_every_undocumented_routine_is_used(self):
        """nkc-undoc.h: "an entry nothing calls is removed"."""
        sources = {p.name: re.sub(r"/\*.*?\*/", "", p.read_text(), flags=re.S)
                   for p in NKC.glob("*.c")}
        for name in undoc_names():
            users = [f for f, text in sources.items() if re.search(rf"\b{name}\b", text)]
            self.assertTrue(users, f"{name} is declared in nkc-undoc.h and used nowhere")
            for user in users:
                self.assertIn('#include "nkc-undoc.h"', sources[user],
                              f"{user} uses {name} without nkc-undoc.h")

    def test_a_list_code_in_a_comment_is_a_list_the_driver_has(self):
        """A driver with NKC_LISTS n names codes 0x222000 .. 0x222000 + 4(n-1)."""
        for source in sorted(NKC.glob("*.c")):
            text = source.read_text()
            lists = re.search(r"^#define NKC_LISTS (\d+)$", text, re.M)
            if not lists:
                continue
            self.assertIn("static VOID NkcRunList(ULONG List, NKC_LOG *Log)", text, source.name)
            head = text.split("*/", 1)[0]
            for n in range(int(lists.group(1))):
                self.assertIn(f"0x{0x222000 + 4 * n:06X}", head, f"{source.name}: list {n}")


if __name__ == "__main__":
    unittest.main()
