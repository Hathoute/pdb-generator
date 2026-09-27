import unittest

import pe
from pe.testutil import build_pe, make_image
from resolver import SignatureError, resolve_signatures


class TestResolveSignatures(unittest.TestCase):
    def test_success(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55"), (0x40, b"\x40\x53\x48")])
        sigs = {
            "A": {"library": "server.dll", "windows": "48 8B C4 55"},
            "B": {"library": "server.dll", "windows": "40 53 48"},
        }
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.skipped, [])
        self.assertEqual(res.symbols, [("A", 0x1010), ("B", 0x1040)])

    def test_skip_other_library(self):
        img = make_image()
        sigs = {"A": {"library": "engine2.dll", "windows": "48 8B C4 55"}}
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.skipped, [("A", "engine2.dll")])
        self.assertEqual(res.symbols, [])

    def test_not_found(self):
        img = make_image()
        sigs = {"A": {"library": "server.dll", "windows": "48 8B C4 55"}}
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].name, "A")
        self.assertEqual(res.errors[0].kind, "not_found")
        self.assertEqual(res.symbols, [])

    def test_ambiguous(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55\x11"), (0x50, b"\x48\x8b\xc4\x55\x22")])
        sigs = {"A": {"library": "server.dll", "windows": "48 8B C4 55"}}
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].kind, "ambiguous")
        self.assertIn("0x1010", res.errors[0].detail)
        self.assertIn("0x1050", res.errors[0].detail)

    def test_same_rva_clash(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55")])
        sigs = {
            "A": {"library": "server.dll", "windows": "48 8B C4 55"},
            "B": {"library": "server.dll", "windows": "48 8B C4"},
        }
        res = resolve_signatures(sigs, img, "server.dll")
        kinds = sorted(e.kind for e in res.errors)
        self.assertEqual(kinds, ["clash", "clash"])
        names = sorted(e.name for e in res.errors)
        self.assertEqual(names, ["A", "B"])

    def test_bad_pattern_reported(self):
        img = make_image()
        sigs = {"A": {"library": "server.dll", "windows": "48 ZZ"}}
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].kind, "bad_pattern")

    def test_non_exec_section_not_scanned(self):
        spec = [
            {"name": ".text", "vsize": 0x40, "raw": b"\x00" * 0x40, "exec": True},
            {
                "name": ".rdata",
                "vsize": 0x40,
                "raw": b"\x00" * 0x10 + b"\x48\x8b\xc4\x55" + b"\x00" * 0x2c,
                "exec": False,
            },
        ]
        img = pe.PEImage.parse(build_pe(spec))
        sigs = {"A": {"library": "server.dll", "windows": "48 8B C4 55"}}
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors[0].kind, "not_found")

    def test_all_errors_collected_not_failfast(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55\x11"), (0x50, b"\x48\x8b\xc4\x55\x22")])
        sigs = {
            "Amb": {"library": "server.dll", "windows": "48 8B C4 55"},
            "Missing": {"library": "server.dll", "windows": "11 22 33 44 55 66 77 88 99 AA BB CC"},
        }
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(sorted(e.name for e in res.errors), ["Amb", "Missing"])


if __name__ == "__main__":
    unittest.main()
