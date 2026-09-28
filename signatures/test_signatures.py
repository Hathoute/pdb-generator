import json
import os
import tempfile
import unittest

from signatures import (
    PatternError,
    SignatureFileError,
    compile_pattern,
    find_matches,
    load_signatures,
)


class TestCompilePattern(unittest.TestCase):
    def test_concrete_bytes(self):
        pat = compile_pattern("48 8B C4 55")
        self.assertEqual(pat.size, 4)
        self.assertEqual(pat.mask, b"\xff\xff\xff\xff")
        self.assertEqual(pat.data, b"\x48\x8b\xc4\x55")

    def test_double_question_mark_is_wildcard(self):
        pat = compile_pattern("48 ?? C4")
        self.assertEqual(pat.data, b"\x48\x00\xc4")
        self.assertEqual(pat.mask, b"\xff\x00\xff")

    def test_single_question_mark_is_wildcard(self):
        pat = compile_pattern("40 53 48 83 EC ? 80 B9 ? ? ? ? ?")
        self.assertEqual(pat.mask.count(b"\x00"[0]), 6)

    def test_leading_wildcards(self):
        pat = compile_pattern("?? ?? 48 8B")
        self.assertEqual(pat.mask, b"\x00\x00\xff\xff")

    def test_lowercase_hex_accepted(self):
        pat = compile_pattern("ab cd")
        self.assertEqual(pat.data, b"\xab\xcd")

    def test_invalid_hex_raises(self):
        with self.assertRaises(PatternError):
            compile_pattern("48 ZZ")

    def test_single_nibble_raises(self):
        with self.assertRaises(PatternError):
            compile_pattern("4 8")

    def test_empty_pattern_raises(self):
        with self.assertRaises(PatternError):
            compile_pattern("")

    def test_all_wildcards_raises(self):
        with self.assertRaises(PatternError):
            compile_pattern("?? ?? ??")

    def test_extra_whitespace_ok(self):
        pat = compile_pattern("  48   8B  ")
        self.assertEqual(pat.data, b"\x48\x8b")


class TestFindMatches(unittest.TestCase):
    def test_no_match(self):
        pat = compile_pattern("48 8B C4")
        self.assertEqual(find_matches(b"\x00\x01\x02\x03", pat), [])

    def test_single_match(self):
        pat = compile_pattern("48 8B")
        self.assertEqual(find_matches(b"\x00\x48\x8b\x02", pat), [1])

    def test_multiple_matches(self):
        pat = compile_pattern("48 8B")
        self.assertEqual(find_matches(b"\x48\x8b\x00\x48\x8b", pat), [0, 3])

    def test_wildcard_match(self):
        pat = compile_pattern("48 ?? 8B")
        self.assertEqual(find_matches(b"\x48\xff\x8b\x00", pat), [0])

    def test_wildcard_mismatch(self):
        pat = compile_pattern("48 ?? 8B")
        self.assertEqual(find_matches(b"\x48\xff\x8c", pat), [])

    def test_leading_wildcard_match(self):
        pat = compile_pattern("?? 8B")
        self.assertEqual(find_matches(b"\x77\x8b", pat), [0])

    def test_trailing_wildcard_match(self):
        pat = compile_pattern("8B ??")
        self.assertEqual(find_matches(b"\x8b\x77", pat), [0])

    def test_overlapping_match_not_reported_twice(self):
        pat = compile_pattern("AA AA")
        self.assertEqual(find_matches(b"\xaa\xaa\xaa", pat), [0, 1])


class TestLoadSignatures(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".jsonc")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return path

    def _write_json(self, root):
        return self._write(json.dumps(root))

    def test_parses_functions_and_labels(self):
        path = self._write_json(
            {
                "functions": {
                    "Fn": {"library": "server.dll", "windows": "48 89 5C"}
                },
                "labels": {
                    "Lbl": {
                        "library": "server.dll",
                        "windows": "AA BB CC",
                        "mode": "pattern",
                    }
                },
            }
        )
        sigs = load_signatures(path)
        self.assertEqual(list(sigs.functions), ["Fn"])
        self.assertEqual(list(sigs.labels), ["Lbl"])
        self.assertEqual(sigs.functions["Fn"]["windows"], "48 89 5C")

    def test_empty_groups_ok(self):
        path = self._write_json({"functions": {}, "labels": {}})
        sigs = load_signatures(path)
        self.assertEqual(sigs.functions, {})
        self.assertEqual(sigs.labels, {})

    def test_missing_functions_root_raises(self):
        path = self._write_json({"labels": {}})
        with self.assertRaises(SignatureFileError) as cm:
            load_signatures(path)
        self.assertIn("functions", str(cm.exception))

    def test_missing_labels_root_raises(self):
        path = self._write_json({"functions": {}})
        with self.assertRaises(SignatureFileError) as cm:
            load_signatures(path)
        self.assertIn("labels", str(cm.exception))

    def test_legacy_signatures_root_rejected(self):
        path = self._write_json({"signatures": {"A": {"windows": "48 8B"}}})
        with self.assertRaises(SignatureFileError):
            load_signatures(path)

    def test_non_object_root_raises(self):
        path = self._write("[]")
        with self.assertRaises(SignatureFileError):
            load_signatures(path)

    def test_function_entry_without_windows_raises(self):
        path = self._write_json({"functions": {"A": {"library": "x.dll"}}, "labels": {}})
        with self.assertRaises(SignatureFileError) as cm:
            load_signatures(path)
        self.assertIn("A", str(cm.exception))

    def test_label_entry_without_windows_raises(self):
        path = self._write_json({"functions": {}, "labels": {"L": {"library": "x.dll"}}})
        with self.assertRaises(SignatureFileError) as cm:
            load_signatures(path)
        self.assertIn("L", str(cm.exception))

    def test_label_entry_without_mode_raises(self):
        path = self._write_json(
            {"functions": {}, "labels": {"L": {"library": "x.dll", "windows": "AA BB"}}}
        )
        with self.assertRaises(SignatureFileError) as cm:
            load_signatures(path)
        self.assertIn("mode", str(cm.exception))

    def test_label_entry_unknown_mode_raises(self):
        path = self._write_json(
            {
                "functions": {},
                "labels": {
                    "L": {"library": "x.dll", "windows": "AA BB", "mode": "blink"}
                },
            }
        )
        with self.assertRaises(SignatureFileError) as cm:
            load_signatures(path)
        self.assertIn("mode", str(cm.exception))

    def test_rip_label_requires_rip_offset(self):
        path = self._write_json(
            {
                "functions": {},
                "labels": {
                    "L": {"library": "x.dll", "windows": "AA BB", "mode": "rip"}
                },
            }
        )
        with self.assertRaises(SignatureFileError) as cm:
            load_signatures(path)
        self.assertIn("rip_offset", str(cm.exception))

    def test_pattern_label_rejects_rip_offset(self):
        path = self._write_json(
            {
                "functions": {},
                "labels": {
                    "L": {
                        "library": "x.dll",
                        "windows": "AA BB",
                        "mode": "pattern",
                        "rip_offset": 2,
                    }
                },
            }
        )
        with self.assertRaises(SignatureFileError):
            load_signatures(path)

    def test_rip_label_with_rip_offset_ok(self):
        path = self._write_json(
            {
                "functions": {},
                "labels": {
                    "L": {
                        "library": "x.dll",
                        "windows": "48 8B 05 ?? ?? ?? ?? 90",
                        "mode": "rip",
                        "rip_offset": 3,
                    }
                },
            }
        )
        sigs = load_signatures(path)
        self.assertEqual(sigs.labels["L"]["rip_offset"], 3)

    def test_function_entry_with_mode_rejected(self):
        path = self._write_json(
            {
                "functions": {
                    "F": {"library": "x.dll", "windows": "AA BB", "mode": "pattern"}
                },
                "labels": {},
            }
        )
        with self.assertRaises(SignatureFileError) as cm:
            load_signatures(path)
        self.assertIn("F", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
