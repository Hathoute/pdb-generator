import unittest

from pdb import MsfBuilder
from pdb.testutil import BLOCK, parse_msf


class TestMsfBuilder(unittest.TestCase):
    def test_small_streams_roundtrip(self):
        msf = MsfBuilder()
        i0 = msf.add_stream(b"")
        i1 = msf.add_stream(b"hello pdb")
        i2 = msf.add_stream(b"x" * BLOCK)
        i3 = msf.add_stream(b"y" * (BLOCK + 1))
        self.assertEqual([i0, i1, i2, i3], [0, 1, 2, 3])
        streams = parse_msf(msf.serialize())
        self.assertEqual(streams[0], b"")
        self.assertEqual(streams[1], b"hello pdb")
        self.assertEqual(streams[2], b"x" * BLOCK)
        self.assertEqual(streams[3], b"y" * (BLOCK + 1))

    def test_large_stream_roundtrip(self):
        payload = bytes(range(256)) * 200 + b"tail"
        msf = MsfBuilder()
        msf.add_stream(payload)
        streams = parse_msf(msf.serialize())
        self.assertEqual(streams[0], payload)

    def test_directory_spanning_multiple_blocks(self):
        msf = MsfBuilder()
        payloads = [bytes([i & 0xFF]) * (100 + i % 7) for i in range(500)]
        for p in payloads:
            msf.add_stream(p)
        streams = parse_msf(msf.serialize())
        self.assertEqual(len(streams), 500)
        for i, p in enumerate(payloads):
            self.assertEqual(streams[i], p)

    def test_file_size_is_block_multiple(self):
        msf = MsfBuilder()
        msf.add_stream(b"abc")
        data = msf.serialize()
        self.assertEqual(len(data) % BLOCK, 0)
        self.assertGreater(len(data), 0)


if __name__ == "__main__":
    unittest.main()
