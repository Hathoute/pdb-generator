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


def _lbl(pattern, mode="pattern", rip_offset=None, library="server.dll"):
    entry = {"library": library, "windows": pattern, "mode": mode}
    if rip_offset is not None:
        entry["rip_offset"] = rip_offset
    return entry


def _lea_rdata(disp):
    """lea rax, [rip+disp32] followed by two nops."""
    return b"\x48\x8d\x05" + disp.to_bytes(4, "little", signed=True) + b"\x90\x90"


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


class TestResolveLabelsPatternMode(unittest.TestCase):
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
        sigs = _sigs(labels={"g_Thing": _lbl("11 22 33 44")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.symbols, [("g_Thing", 0x2010, "label")])

    def test_label_not_matched_anywhere(self):
        img = make_image()
        sigs = _sigs(labels={"g_Thing": _lbl("48 8B C4 55")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors[0].kind, "not_found")

    def test_label_skip_other_library(self):
        img = make_image()
        sigs = _sigs(labels={"L": _lbl("48 8B C4 55", library="engine2.dll")})
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.skipped, [("L", "engine2.dll")])


class TestResolveLabelsRipMode(unittest.TestCase):
    def _img_with_anchor(self, disp):
        # .text (0x1000): lea at 0x1010; .rdata at 0x2000 with vsize beyond raw
        spec = [
            {
                "name": ".text",
                "vsize": 0x40,
                "raw": b"\x00" * 0x10 + _lea_rdata(disp) + b"\x00" * 0x36,
                "exec": True,
            },
            {
                "name": ".rdata",
                "vsize": 0x100,
                "raw": b"\xde\xad" * 8,
                "exec": False,
            },
        ]
        return pe.PEImage.parse(build_pe(spec))

    def test_rip_anchor_decodes_label_rva(self):
        # instruction at 0x1010, len 7, disp points to 0x2010
        disp = 0x2010 - (0x1010 + 7)
        img = self._img_with_anchor(disp)
        sigs = _sigs(
            labels={
                "g_Thing": _lbl(
                    "48 8D 05 ?? ?? ?? ?? 90 90", mode="rip", rip_offset=3
                )
            }
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.symbols, [("g_Thing", 0x2010, "label")])

    def test_rip_anchor_resolves_into_bss_beyond_raw(self):
        disp = 0x2080 - (0x1010 + 7)
        img = self._img_with_anchor(disp)
        sigs = _sigs(
            labels={
                "g_Bss": _lbl("48 8D 05 ?? ?? ?? ?? 90 90", mode="rip", rip_offset=3)
            }
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.symbols, [("g_Bss", 0x2080, "label")])

    def test_rip_anchor_too_few_matches(self):
        img = make_image()
        sigs = _sigs(
            labels={
                "g_Ghost": _lbl("48 8D 05 ?? ?? ?? ?? 90 90", mode="rip", rip_offset=3)
            }
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors[0].kind, "not_found")

    def test_rip_anchor_ambiguous(self):
        spec = [
            {
                "name": ".text",
                "vsize": 0x60,
                "raw": b"\x00" * 0x10
                + _lea_rdata(0x10)
                + b"\x00" * 0x10
                + _lea_rdata(0x20)
                + b"\x00" * 0x30,
                "exec": True,
            },
            {"name": ".rdata", "vsize": 0x40, "raw": b"\x00" * 0x40, "exec": False},
        ]
        img = pe.PEImage.parse(build_pe(spec))
        sigs = _sigs(
            labels={"g_Twin": _lbl("48 8D 05 ?? ?? ?? ??", mode="rip", rip_offset=3)}
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors[0].kind, "ambiguous")
        # lea at 0x1010 ends 0x1017 -> target 0x1017 + 0x10 = 0x1027
        # lea at 0x1029 ends 0x1030 -> target 0x1030 + 0x20 = 0x1050
        self.assertIn("0x1027", res.errors[0].detail)
        self.assertIn("0x1050", res.errors[0].detail)

    def test_rip_anchor_multiple_matches_same_target_not_ambiguous(self):
        # second anchor at 0x1029 (ends 0x1030) gets a compensating disp so both
        # decode to the same target 0x1027
        spec = [
            {
                "name": ".text",
                "vsize": 0x60,
                "raw": b"\x00" * 0x10
                + _lea_rdata(0x10)
                + b"\x00" * 0x10
                + _lea_rdata(0x1027 - 0x1030)
                + b"\x00" * 0x30,
                "exec": True,
            },
            {"name": ".rdata", "vsize": 0x40, "raw": b"\x00" * 0x40, "exec": False},
        ]
        img = pe.PEImage.parse(build_pe(spec))
        sigs = _sigs(
            labels={"g_One": _lbl("48 8D 05 ?? ?? ?? ??", mode="rip", rip_offset=3)}
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors, [])
        self.assertEqual(res.symbols, [("g_One", 0x1027, "label")])

    def test_rip_offset_out_of_range_is_bad_pattern(self):
        img = make_image()
        sigs = _sigs(
            labels={
                "g_Bad": _lbl("48 8D 05", mode="rip", rip_offset=8)
            }
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors[0].kind, "bad_pattern")
        self.assertIn("rip_offset", res.errors[0].detail)

    def test_rip_anchor_decoding_outside_sections_is_bad_ref(self):
        disp = -(0x1010 + 7) - 0x10
        img = self._img_with_anchor(disp)
        sigs = _sigs(
            labels={
                "g_Off": _lbl("48 8D 05 ?? ?? ?? ?? 90 90", mode="rip", rip_offset=3)
            }
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(res.errors[0].kind, "bad_ref")
        self.assertEqual(res.symbols, [])


class TestResolveCrossGroup(unittest.TestCase):
    def test_label_flags_kind(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55"), (0x30, b"\x11\x22\x33\x44")])
        sigs = _sigs(
            functions={"A": _fn("48 8B C4 55")},
            labels={"L": _lbl("11 22 33 44")},
        )
        res = resolve_signatures(sigs, img, "server.dll")
        kinds = {name: kind for name, _, kind in res.symbols}
        self.assertEqual(
            kinds, {"A": "function", "L": "label"}
        )

    def test_cross_group_duplicate_name_clash(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55")])
        sigs = _sigs(
            functions={"A": _fn("48 8B C4")}, labels={"A": _lbl("48 8B C4 55")}
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual([e.kind for e in res.errors], ["clash"])
        self.assertEqual(res.symbols, [])

    def test_cross_group_same_rva_clash(self):
        img = make_image([(0x10, b"\x48\x8b\xc4\x55")])
        sigs = _sigs(
            functions={"A": _fn("48 8B C4 55")}, labels={"L": _lbl("48 8B C4")}
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(
            sorted((e.name, e.kind) for e in res.errors),
            [("A", "clash"), ("L", "clash")],
        )
        self.assertEqual(res.symbols, [])

    def test_rip_label_and_function_same_rva_clash(self):
        # function A at 0x1000; lea at 0x1005 decoding back to 0x1000 -> RVA clash
        disp = 0x1000 - (0x1005 + 7)
        spec = [
            {
                "name": ".text",
                "vsize": 0x40,
                "raw": b"\x11\x22\x33\x44\x55" + _lea_rdata(disp) + b"\x00" * 0x32,
                "exec": True,
            },
        ]
        img = pe.PEImage.parse(build_pe(spec))
        sigs = _sigs(
            functions={"A": _fn("11 22 33 44 55")},
            labels={
                "g_Self": _lbl(
                    "48 8D 05 ?? ?? ?? ?? 90 90", mode="rip", rip_offset=3
                )
            },
        )
        res = resolve_signatures(sigs, img, "server.dll")
        self.assertEqual(
            sorted((e.name, e.kind) for e in res.errors),
            [("A", "clash"), ("g_Self", "clash")],
        )
        self.assertEqual(res.symbols, [])


if __name__ == "__main__":
    unittest.main()
