import os
import tempfile
import unittest

import jsonc


class TestStripJsoncComments(unittest.TestCase):
    def test_line_comment_removed(self):
        src = '{\n  // hello\n  "a": 1\n}\n'
        stripped = jsonc.strip_jsonc_comments(src)
        self.assertEqual(stripped, '{\n  \n  "a": 1\n}\n')

    def test_block_comment_removed(self):
        src = '{ /* multi\nline */ "a": 1 }'
        stripped = jsonc.strip_jsonc_comments(src)
        self.assertEqual(jsonc.loads(stripped), {"a": 1})

    def test_comment_markers_inside_strings_preserved(self):
        src = '{"a": "http://x // y /* z */"}'
        stripped = jsonc.strip_jsonc_comments(src)
        self.assertEqual(jsonc.loads(stripped), {"a": "http://x // y /* z */"})

    def test_escaped_quote_inside_string(self):
        src = '{"a": "\\" // not a comment"}'
        stripped = jsonc.strip_jsonc_comments(src)
        self.assertEqual(jsonc.loads(stripped), {"a": '" // not a comment'})

    def test_block_comment_opens_inside_string_is_not_comment(self):
        src = '{"a": "/*"}'
        stripped = jsonc.strip_jsonc_comments(src)
        self.assertEqual(jsonc.loads(stripped), {"a": "/*"})


class TestLoad(unittest.TestCase):
    def test_load_parses_jsonc_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sigs.jsonc")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{\n  // comment\n  "a": 1\n}\n')
            self.assertEqual(jsonc.load(path), {"a": 1})

    def test_load_reports_path_in_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "broken.jsonc")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{ not jsonc")
            with self.assertRaises(jsonc.JsoncError) as ctx:
                jsonc.load(path)
            self.assertIn("broken.jsonc", str(ctx.exception))
            self.assertIn("JSONC", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
