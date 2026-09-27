import unittest

from signatures import PatternError, compile_pattern, find_matches


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


if __name__ == "__main__":
    unittest.main()
