import json
import os
import unittest

import pe
import pdb
import resolver
import signatures
from pdb import SectionEntry, build_pdb
from pdb.testutil import parse_msf, parse_records


TESTDATA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testdata", "wtsapi32")
)
DLL_PATH = os.path.join(TESTDATA_DIR, "wtsapi32.dll")
SIGS_PATH = os.path.join(TESTDATA_DIR, "signatures.jsonc")
EXPECTED_PATH = os.path.join(TESTDATA_DIR, "expected.json")

class TestGeneratedPdbAgainstRealBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(DLL_PATH, "rb") as f:
            cls.image = pe.PEImage.parse(f.read())
        cls.sig_entries = signatures.load_signatures(SIGS_PATH)
        with open(EXPECTED_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        cls.expected = data["functions"] + data["labels"]
        cls.expected_kinds = {
            **{f["name"]: "function" for f in data["functions"]},
            **{l["name"]: "label" for l in data["labels"]},
        }

        cls.library = os.path.basename(DLL_PATH)
        cls.resolution = resolver.resolve_signatures(
            cls.sig_entries, cls.image, cls.library
        )
        cls.resolved = {n: (r, k) for n, r, k in cls.resolution.symbols}

    def test_signatures_resolve_exactly_to_expected(self):
        self.assertEqual(self.resolution.errors, [])
        self.assertEqual(self.resolution.skipped, [])
        self.assertEqual(
            set(self.resolved), {f["name"] for f in self.expected}
        )
        for func in self.expected:
            rva, kind = self.resolved[func["name"]]
            self.assertEqual(
                rva,
                func["rva"],
                f"signature for {func['name']} resolved to wrong RVA",
            )

    def test_generated_pdb_records_point_to_expected_offsets(self):
        guid, age = self.image.debug_cv
        symbols = []
        for name, rva, kind in self.resolution.symbols:
            segment, offset = pe.rva_to_section(self.image, rva)
            self.assertIsNotNone(segment, f"{name}: RVA 0x{rva:X} not in any section")
            flags = (
                pdb.PUBSYM_FUNCTION if kind == "function" else pdb.PUBSYM_DATA
            )
            symbols.append((name, segment, offset, flags))

        blob = build_pdb(
            [
                SectionEntry(sec.characteristics, sec.vsize)
                for sec in self.image.sections
            ],
            self.image.section_headers_blob(),
            symbols,
            guid,
            age,
            timestamp=0,
        )

        streams = parse_msf(blob)
        records = {
            r["name"]: (r["segment"], r["off"], r["flags"])
            for r in parse_records(streams[7])
        }
        self.assertEqual(set(records), {f["name"] for f in self.expected})

        for func in self.expected:
            self.assertIn(func["name"], records)
            segment, offset, flags = records[func["name"]]
            self.assertEqual(
                flags,
                pdb.PUBSYM_FUNCTION
                if self.expected_kinds[func["name"]] == "function"
                else pdb.PUBSYM_DATA,
            )
            section = self.image.sections[segment - 1]
            rva = section.va + offset
            self.assertEqual(
                rva,
                func["rva"],
                f"PDB points {func['name']} to RVA 0x{rva:X}, expected 0x{func['rva']:X}",
            )


if __name__ == "__main__":
    unittest.main()
