import unittest

import pe
import signatures
from pe.testutil import build_pe, make_image
from resolver import SignatureError, resolve_signatures

PUBSYM_FUNCTION = "function"
PUBSYM_LABEL = "label"


def _sigs(functions=None, labels=None):
    return signatures.SignatureFile(functions=functions or {}, labels=labels or {})


def _fn(pattern, library="server.dll"):
    return {"library": library, "windows": pattern}


class TestResolveFunctions(unittest.TestCase):
    def test_success(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55"), (0x40, b"\x40\x53\x48")])
        sigs = _sigs(
            functions={
                "A": _fn("48 8B C4 55"),
                "B": _fn("40 53 48"),
            }
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.skipped, [])
        self.assertEqual(
            res.symbols, [("A", 0x1010, "function"), ("B", 0x1040, "function")]
        )

    def test_skip_other_library(self):
        img = make_image()
        sigs = _sigs(functions={"A": _fn("48 8B C4 55", "engine2.dll")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.skipped, [("A", "engine2.dll")])
        self.assertEqual(res.symbols, [])

    def test_not_found(self):
        img = make_image()
        sigs = _sigs(functions={"A": _fn("48 8B C4 55")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].name, "A")
        self.assertEqual(res.errors[0].kind, "not_found")
        self.assertEqual(res.symbols, [])

    def test_ambiguous(self):
        img = make_image(
            [(0x10, b"\x48\x8b\xc4\x55\x11"), (0x50, b"\x48\x8b\xc4\x55\x22")]
        )
        sigs = _sigs(functions={"A": _fn("48 8B C4 55")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].kind, "ambiguous")
        self.assertIn("0x1010", res.errors[0].detail)
        self.assertIn("0x1050", res.errors[0].detail)

    def test_same_rva_clash(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55")])
        sigs = _sigs(
            functions={
                "A": _fn("48 8B C4 55"),
                "B": _fn("48 8B C4"),
            }
        )
        res = resolve_signatures(sigs, img, "server.dll")
        kinds = sorted(e.kind for e in res.errors)
        self.assertEqual(kinds, ["clash", "clash"])
        names = sorted(e.name for e in res.errors)
        self.assertEqual(names, ["A", "B"])

    def test_bad_pattern_reported(self):
        img = make_image()
        sigs = _sigs(functions={"A": _fn("48 ZZ")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0].kind, "bad_pattern")

    def test_non_exec_section_not_scanned_for_functions(self):
        spec = [
            {"name": ".text", "vsize": 0x40, "raw": b"\x00" * 0x40, "exec": True},
            {
                "name": ".rdata",
                "vsize": 0x40,
                "raw": b"\x00" * 0x10 + b"\x48\x8b\xc4\x55" + b"\x00" * 0x2C,
                "exec": False,
            },
        ]
        img = pe.PEImage.parse(build_pe(spec))
        sigs = _sigs(functions={"A": _fn("48 8B C4 55")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors[0].kind, "not_found")

    def test_all_errors_collected_not_failfast(self):
        img = make_image(
            [(0x10, b"\x48\x8b\xc4\x55\x11"), (0x50, b"\x48\x8b\xc4\x55\x22")]
        )
        sigs = _sigs(
            functions={
                "Amb": _fn("48 8B C4 55"),
                "Missing": _fn("11 22 33 44 55 66 77 88 99 AA BB CC"),
            }
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(sorted(e.name for e in res.errors), ["Amb", "Missing"])


class TestResolveLabels(unittest.TestCase):
    def test_label_found_in_non_exec_section(self):
        spec = [
            {"name": ".text", "vsize": 0x40, "raw": b"\x00" * 0x40, "exec": True},
            {
                "name": ".rdata",
                "vsize": 0x40,
                "raw": b"\x00" * 0x10 + b"\x11\x22\x33\x44" + b"\x00" * 0x2C,
                "exec": False,
            },
        ]
        img = pe.PEImage.parse(build_pe(spec))
        sigs = _sigs(labels={"g_Thing": _fn("11 22 33 44")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.symbols, [("g_Thing", 0x2010, "label")])

    def test_label_not_matched_in_exec_only_image(self):
        img = make_image()
        sigs = _sigs(labels={"g_Thing": _fn("48 8B C4 55")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors[0].kind, "not_found")

    def test_label_flags_kind(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55"), (0x30, b"\x11\x22\x33\x44")])
        sigs = _sigs(
            functions={"A": _fn("48 8B C4 55")}, labels={"L": _fn("11 22 33 44")}
        )
        res = resolve_signatures(sigs, img, "server.dll")
        kinds = {name: kind for name, _, kind in res.symbols}
        self.assertEqual(
            kinds, {"A": "function", "L": "label"}
        )

    def test_cross_group_duplicate_name_clash(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55")])
        sigs = _sigs(
            functions={"A": _fn("48 8B C4")}, labels={"A": _fn("48 8B C4 55")}
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual([e.kind for e in res.errors], ["clash"])
        self.assertEqual(res.symbols, [])

    def test_cross_group_same_rva_clash(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55")])
        sigs = _sigs(
            functions={"A": _fn("48 8B C4 55")}, labels={"L": _fn("48 8B C4")}
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(
            sorted((e.name, e.kind) for e in res.errors),
            [("A", "clash"), ("L", "clash")],
        )
        self.assertEqual(res.symbols, [])

    def test_label_skip_other_library(self):
        img = make_image()
        sigs = _sigs(labels={"L": _fn("48 8B C4 55", "engine2.dll")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.skipped, [("L", "engine2.dll")])


if __name__ == "__main__":
    unittest.main()
