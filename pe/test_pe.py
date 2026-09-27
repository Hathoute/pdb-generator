import unittest
import uuid

import pe
from pe.testutil import build_pe


class TestPEImage(unittest.TestCase):
    def test_parse_sections_and_exec_filter(self):
        pe_bytes = build_pe(
            [
                {"name": ".text", "vsize": 0x20, "raw": b"\x48\x8b\xc4\x55" + b"\x90" * 12, "exec": True},
                {"name": ".rdata", "vsize": 0x10, "raw": b"\xde\xad\xbe\xef" * 4, "exec": False},
            ]
        )
        img = pe.PEImage.parse(pe_bytes)
        self.assertEqual([s.name for s in img.sections], [".text", ".rdata"])
        regions = img.exec_scan_regions()
        self.assertEqual(len(regions), 1)
        rva, blob = regions[0]
        self.assertEqual(rva, 0x1000)
        self.assertEqual(blob[:4], b"\x48\x8b\xc4\x55")

    def test_rva_to_offset(self):
        pe_bytes = build_pe(
            [
                {"name": ".text", "vsize": 0x20, "raw": b"\x90" * 0x20, "exec": True},
                {"name": ".rdata", "vsize": 0x10, "raw": b"\xde\xad\xbe\xef" * 4, "exec": False},
            ]
        )
        img = pe.PEImage.parse(pe_bytes)
        rdata = img.sections[1]
        off = img.rva_to_offset(rdata.va + 4)
        self.assertEqual(pe_bytes[off : off + 4], b"\xde\xad\xbe\xef")

    def test_debug_cv_extracted(self):
        guid = uuid.UUID("01234567-89ab-cdef-0123-456789abcdef")
        pe_bytes = build_pe(
            [{"name": ".text", "vsize": 0x20, "raw": b"\x90" * 0x20, "exec": True}],
            debug_cv={"guid": guid, "age": 7},
        )
        img = pe.PEImage.parse(pe_bytes)
        self.assertEqual(img.debug_cv, (guid, 7))

    def test_no_debug_dir_gives_none(self):
        pe_bytes = build_pe([{"name": ".text", "vsize": 0x20, "raw": b"\x90" * 0x20, "exec": True}])
        img = pe.PEImage.parse(pe_bytes)
        self.assertIsNone(img.debug_cv)

    def test_bad_magic_raises(self):
        with self.assertRaises(pe.PeError):
            pe.PEImage.parse(b"not a pe file at all........")

    def test_section_headers_blob(self):
        pe_bytes = build_pe(
            [
                {"name": ".text", "vsize": 0x20, "raw": b"\x90" * 0x20, "exec": True},
                {"name": ".rdata", "vsize": 0x10, "raw": b"\xde\xad\xbe\xef" * 4, "exec": False},
            ]
        )
        img = pe.PEImage.parse(pe_bytes)
        blob = img.section_headers_blob()
        self.assertEqual(len(blob), 80)
        self.assertTrue(blob.startswith(b".text\x00\x00\x00"))
        self.assertEqual(blob[40:46], b".rdata")


class TestRvaToSection(unittest.TestCase):
    def _image(self):
        return pe.PEImage.parse(
            build_pe(
                [
                    {"name": ".text", "vsize": 0x40, "raw": b"\x90" * 0x40, "exec": True},
                    {"name": ".rdata", "vsize": 0x20, "raw": b"\x00" * 0x20, "exec": False},
                ]
            )
        )

    def test_maps_to_one_based_section_and_offset(self):
        img = self._image()
        self.assertEqual(pe.rva_to_section(img, 0x1000), (1, 0))
        self.assertEqual(pe.rva_to_section(img, 0x1010), (1, 0x10))
        self.assertEqual(pe.rva_to_section(img, 0x2008), (2, 8))

    def test_outside_sections_returns_none(self):
        img = self._image()
        self.assertIsNone(pe.rva_to_section(img, 0x0FFF))
        self.assertIsNone(pe.rva_to_section(img, 0x3000))


if __name__ == "__main__":
    unittest.main()
