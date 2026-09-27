import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

from pdb.testutil import parse_msf, parse_records
from pe.testutil import build_pe


class TestCliEndToEnd(unittest.TestCase):
    def run_cli(self, sigs_text, sections_spec=None, debug_cv=None):
        self.tmp = tempfile.TemporaryDirectory()
        dll_path = os.path.join(self.tmp.name, "server.dll")
        sig_path = os.path.join(self.tmp.name, "signatures.jsonc")
        pdb_path = os.path.join(self.tmp.name, "server.pdb")
        if sections_spec is None:
            sections_spec = [
                {
                    "name": ".text",
                    "vsize": 0x100,
                    "raw": b"\x00" * 0x10
                    + b"\x48\x8b\xc4\x55"
                    + b"\x00" * 0x2c
                    + b"\x40\x53\x48"
                    + b"\x00" * 0xED,
                    "exec": True,
                }
            ]
        with open(dll_path, "wb") as f:
            f.write(build_pe(sections_spec, debug_cv))
        with open(sig_path, "w") as f:
            f.write(sigs_text)
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(os.path.dirname(__file__), "make_pdb.py"),
                "--dll",
                dll_path,
                "--sig",
                sig_path,
                "--out",
                pdb_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc, pdb_path

    def test_success_writes_pdb(self):
        proc, pdb_path = self.run_cli(
            json.dumps(
                {
                    "signatures": {
                        "FuncA": {"library": "server.dll", "windows": "48 8B C4 55"},
                        "FuncB": {"library": "server.dll", "windows": "40 53 48"},
                    }
                }
            )
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(pdb_path))
        streams = parse_msf(open(pdb_path, "rb").read())
        records = parse_records(streams[7])
        self.assertEqual(sorted(r["name"] for r in records), ["FuncA", "FuncB"])

    def test_reuses_dll_guid_and_age(self):
        guid = uuid.UUID("11112222-3333-4444-5555-666677778888")
        proc, pdb_path = self.run_cli(
            json.dumps(
                {"signatures": {"FuncA": {"library": "server.dll", "windows": "48 8B C4 55"}}}
            ),
            debug_cv={"guid": guid, "age": 9},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        streams = parse_msf(open(pdb_path, "rb").read())
        info = streams[1]
        self.assertEqual(info[12:28], guid.bytes_le)
        (age,) = struct.unpack_from("<I", info, 8)
        self.assertEqual(age, 9)

    def test_not_found_fails_without_pdb(self):
        proc, pdb_path = self.run_cli(
            json.dumps(
                {"signatures": {"Ghost": {"library": "server.dll", "windows": "11 22 33 44"}}}
            )
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Ghost", proc.stderr)
        self.assertIn("not_found", proc.stderr.lower())
        self.assertFalse(os.path.exists(pdb_path))

    def test_ambiguous_fails_without_pdb(self):
        spec = [
            {
                "name": ".text",
                "vsize": 0x100,
                "raw": b"\x00" * 0x10
                + b"\x48\x8b\xc4\x55\x00"
                + b"\x00" * 0x20
                + b"\x48\x8b\xc4\x55\x00"
                + b"\x00" * 0xDB,
                "exec": True,
            }
        ]
        proc, pdb_path = self.run_cli(
            json.dumps(
                {"signatures": {"Twin": {"library": "server.dll", "windows": "48 8B C4 55 00"}}}
            ),
            sections_spec=spec,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("ambiguous", proc.stderr.lower())
        self.assertFalse(os.path.exists(pdb_path))

    def test_clash_fails_without_pdb(self):
        proc, pdb_path = self.run_cli(
            json.dumps(
                {
                    "signatures": {
                        "A": {"library": "server.dll", "windows": "48 8B C4 55"},
                        "B": {"library": "server.dll", "windows": "48 8B C4"},
                    }
                }
            )
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("clash", proc.stderr.lower())
        self.assertFalse(os.path.exists(pdb_path))

    def test_other_library_skipped_with_warning(self):
        proc, pdb_path = self.run_cli(
            json.dumps(
                {
                    "signatures": {
                        "Elsewhere": {"library": "engine2.dll", "windows": "11 22 33 44"},
                        "FuncA": {"library": "server.dll", "windows": "48 8B C4 55"},
                    }
                }
            )
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Elsewhere", proc.stdout)
        self.assertIn("engine2.dll", proc.stdout)
        self.assertTrue(os.path.exists(pdb_path))

    def test_bad_jsonc_fails(self):
        proc, _ = self.run_cli("{ this is not jsonc")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("JSONC", proc.stderr)

    def test_bad_pattern_fails(self):
        proc, pdb_path = self.run_cli(
            json.dumps(
                {"signatures": {"Bad": {"library": "server.dll", "windows": "48 ZZ"}}}
            )
        )
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(os.path.exists(pdb_path))

    def tearDown(self):
        if hasattr(self, "tmp"):
            self.tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
