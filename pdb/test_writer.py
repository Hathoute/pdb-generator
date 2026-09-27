import struct
import unittest
import uuid

from pdb import (
    DBI_V70,
    GSI_VERHDR,
    IMPL_VC70,
    PUBSYM_DATA,
    PUBSYM_FUNCTION,
    S_PUB32,
    TPI_V80,
    SectionEntry,
    build_pdb,
    encode_pub32,
    hash_string_v1,
)
from pdb.testutil import parse_msf, parse_records


class TestPub32(unittest.TestCase):
    def test_roundtrip(self):
        rec = encode_pub32("SomeFunc", offset=0x1234, segment=1)
        (rec_len,) = struct.unpack_from("<H", rec, 0)
        self.assertEqual(2 + rec_len, len(rec))
        self.assertEqual(len(rec) % 4, 0)
        (kind, flags, off, seg) = struct.unpack_from("<HIIH", rec, 2)
        self.assertEqual(kind, S_PUB32)
        self.assertEqual(flags, PUBSYM_FUNCTION)
        self.assertEqual(off, 0x1234)
        self.assertEqual(seg, 1)
        name = rec[14:].split(b"\x00")[0].decode()
        self.assertEqual(name, "SomeFunc")

    def test_padding_zeroed(self):
        rec = encode_pub32("abc", offset=0, segment=1)
        self.assertEqual(len(rec) % 4, 0)
        self.assertEqual(len(rec), 20)
        self.assertEqual(rec[14:], b"abc\x00\x00\x00")


def hash_v1_reference(name: bytes) -> int:
    result = 0
    n = len(name)
    idx = 0
    while idx + 4 <= n:
        result ^= struct.unpack_from("<I", name, idx)[0]
        idx += 4
    rem = n - idx
    if rem >= 2:
        result ^= struct.unpack_from("<H", name, idx)[0]
        idx += 2
        rem -= 2
    if rem == 1:
        result ^= name[idx]
    result |= 0x20202020
    result ^= result >> 11
    result &= 0xFFFFFFFF
    return result ^ (result >> 16)


class TestHashV1(unittest.TestCase):
    def test_matches_independent_transcription(self):
        for s in [
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"abcde",
            b"CBaseEntity::TakeDamageOld",
            b"UTIL_Remove",
            b"ZZZZ_zz__09-AaBb",
        ]:
            self.assertEqual(
                hash_string_v1(s),
                hash_v1_reference(s),
                f"mismatch for {s!r}",
            )


class TestBuildPdb(unittest.TestCase):
    def _fixture(self):
        sections = [
            SectionEntry(characteristics=0x60000020, vsize=0x100),
            SectionEntry(characteristics=0x40000040, vsize=0x100),
        ]
        section_headers = bytes(range(256))[:80]
        symbols = [
            ("Beta", 1, 0x40),
            ("Alpha", 1, 0x10),
            ("CBase::X", 1, 0x12),
        ]
        return sections, section_headers, symbols

    def _build(self):
        sections, section_headers, symbols = self._fixture()
        guid = uuid.UUID("aaaabbbb-cccc-dddd-eeee-ffff00001111")
        data = build_pdb(
            sections, section_headers, symbols, guid=guid, age=3, timestamp=123456
        )
        return sections, section_headers, symbols, guid, data

    def test_stream_count_and_sizes(self):
        _, _, _, _, data = self._build()
        streams = parse_msf(data)
        self.assertEqual(len(streams), 9)
        self.assertEqual(streams[0], b"")

    def test_info_stream(self):
        _, _, _, guid, data = self._build()
        streams = parse_msf(data)
        info = streams[1]
        version, sig, age = struct.unpack_from("<III", info, 0)
        self.assertEqual(version, IMPL_VC70)
        self.assertEqual(sig, 123456)
        self.assertEqual(age, 3)
        self.assertEqual(info[12:28], guid.bytes_le)
        (feature,) = struct.unpack_from("<I", info, 48)
        self.assertEqual(feature, 0x494E494D)

    def test_tpi_ipi_empty(self):
        _, _, _, _, data = self._build()
        streams = parse_msf(data)
        for idx in (2, 4):
            tpi = streams[idx]
            self.assertEqual(len(tpi), 56)
            version, hsize, begin, end, nbytes = struct.unpack_from("<IIIII", tpi, 0)
            self.assertEqual(version, TPI_V80)
            self.assertEqual(hsize, 56)
            self.assertEqual(begin, 0x1000)
            self.assertEqual(end, 0x1000)
            self.assertEqual(nbytes, 0)

    def test_dbi_header(self):
        _, _, _, _, data = self._build()
        streams = parse_msf(data)
        dbi = streams[3]
        self.assertGreaterEqual(len(dbi), 64)
        fields = struct.unpack_from("<iIIHHHHHHiiiiiIiiHHI", dbi, 0)
        (
            vsig, vhdr, age, gss, build, pss, dlver, symrec, rbld,
            modi, seccontr, secmap, fileinfo, typesrv, mfc, optdbg, ec,
            flags, machine, reserved,
        ) = fields
        self.assertEqual(vsig, -1)
        self.assertEqual(vhdr, DBI_V70)
        self.assertEqual(gss, 5)
        self.assertEqual(pss, 6)
        self.assertEqual(symrec, 7)
        self.assertEqual(machine, 0x8664)
        self.assertEqual(
            len(dbi), 64 + modi + seccontr + secmap + fileinfo + typesrv + ec + optdbg
        )

    def test_dbi_optional_dbg_header(self):
        _, _, _, _, data = self._build()
        streams = parse_msf(data)
        dbi = streams[3]
        (modi, seccontr, secmap, fileinfo, typesrv, mfc, optdbg, ec) = struct.unpack_from(
            "<iiiiiIii", dbi, 24
        )
        dbg = struct.unpack_from(
            "<11H", dbi, 64 + modi + seccontr + secmap + fileinfo + typesrv + ec
        )
        for i, v in enumerate(dbg):
            expected = 8 if i == 6 else 0xFFFF
            self.assertEqual(v, expected, f"dbg stream slot {i}")

    def test_dbi_section_map(self):
        sections, _, _, _, data = self._build()
        streams = parse_msf(data)
        dbi = streams[3]
        (modi, seccontr, secmap_sz) = struct.unpack_from("<iii", dbi, 24)
        base = 64 + modi + seccontr
        sec, sec_log = struct.unpack_from("<HH", dbi, base)
        self.assertEqual(sec, sec_log)
        self.assertEqual(sec, len(sections) + 1)
        for i, s in enumerate(sections):
            e = dbi[base + 4 + 20 * i : base + 24 + 20 * i]
            (flags, ovl, group, frame, secname, classname, off, seclen) = struct.unpack(
                "<HHHHHHII", e
            )
            self.assertEqual(frame, i + 1)
            self.assertEqual(secname, 0xFFFF)
            self.assertEqual(seclen, s.vsize)
            expect_exec = 4 if s.characteristics & 0x20000000 else 0
            self.assertEqual(flags & 4, expect_exec)

    def test_globals_hash_empty(self):
        _, _, _, _, data = self._build()
        streams = parse_msf(data)
        gs = streams[5]
        ver_sig, ver_hdr, hr_size, num_buckets = struct.unpack_from("<IIII", gs, 0)
        self.assertEqual(ver_sig, 0xFFFFFFFF)
        self.assertEqual(ver_hdr, GSI_VERHDR)
        self.assertEqual(hr_size, 0)
        self.assertEqual(num_buckets, 32768)
        self.assertEqual(gs[16:], b"\x00" * (len(gs) - 16))

    def test_data_public_flag_emitted(self):
        sections = [SectionEntry(characteristics=0x60000020, vsize=0x100)]
        section_headers = bytes(range(256))[:40]
        data = build_pdb(
            sections,
            section_headers,
            [
                ("Fn", 1, 0x10, PUBSYM_FUNCTION),
                ("Lbl", 1, 0x20, PUBSYM_DATA),
            ],
            guid=uuid.UUID("aaaabbbb-cccc-dddd-eeee-ffff00001111"),
            age=3,
            timestamp=123456,
        )
        streams = parse_msf(data)
        records = {r["name"]: r for r in parse_records(streams[7])}
        self.assertEqual(records["Fn"]["flags"], PUBSYM_FUNCTION)
        self.assertEqual(records["Lbl"]["flags"], PUBSYM_DATA)

    def test_records_stream_sorted_by_name(self):
        _, _, _, _, data = self._build()
        streams = parse_msf(data)
        records = parse_records(streams[7])
        names = [r["name"] for r in records]
        self.assertEqual(names, ["Alpha", "Beta", "CBase::X"])
        self.assertEqual(records[0]["segment"], 1)
        self.assertEqual(records[0]["off"], 0x10)

    def test_publics_stream_hash_blob(self):
        _, _, _, _, data = self._build()
        streams = parse_msf(data)
        pubs = streams[6]
        sym_hash, addr_map, num_thunks, size_thunk = struct.unpack_from("<IIII", pubs, 0)
        records = parse_records(streams[7])
        self.assertEqual(addr_map, 4 * len(records))

        blob = pubs[28 : 28 + sym_hash]
        ver_sig, ver_hdr, hr_size, num_buckets = struct.unpack_from("<IIII", blob, 0)
        self.assertEqual(ver_sig, 0xFFFFFFFF)
        self.assertEqual(ver_hdr, GSI_VERHDR)
        self.assertEqual(hr_size, 8 * len(records))

        hash_recs = struct.unpack_from(f"<{2 * len(records)}I", blob, 16)
        hash_recs = list(zip(hash_recs[0::2], hash_recs[1::2]))
        bitmap_words = struct.unpack_from("<8192I", blob, 16 + 8 * len(records))
        n_bucket_entries = (len(blob) - 16 - 8 * len(records) - 32768) // 4
        bucket_starts = (
            struct.unpack_from(f"<{n_bucket_entries}I", blob, 16 + 8 * len(records) + 32768)
            if n_bucket_entries
            else ()
        )

        by_off = {r["stream_off"]: r for r in records}
        seen_names = []
        for (off_plus_one, cref) in hash_recs:
            r = by_off[off_plus_one - 1]
            self.assertEqual(cref, 1)
            seen_names.append(r["name"])
        self.assertEqual(sorted(seen_names), sorted(r["name"] for r in records))

        non_empty = 0
        for w_idx, word in enumerate(bitmap_words):
            for b in range(32):
                if word & (1 << b):
                    non_empty += 1
        self.assertEqual(non_empty, n_bucket_entries)

        for start in bucket_starts:
            self.assertEqual(start % 12, 0)

        addrmap = struct.unpack_from(f"<{len(records)}I", pubs, 28 + len(blob))
        self.assertEqual(len(addrmap), len(records))

    def test_addrmap_sorted_by_address(self):
        _, _, _, _, data = self._build()
        streams = parse_msf(data)
        pubs = streams[6]
        sym_hash = struct.unpack_from("<I", pubs, 0)[0]
        records = parse_records(streams[7])
        addrmap = struct.unpack_from(f"<{len(records)}I", pubs, 28 + sym_hash)
        addr_sorted = sorted(records, key=lambda r: (r["segment"], r["off"], r["name"]))
        self.assertEqual([a for a in addrmap], [r["stream_off"] for r in addr_sorted])

    def test_section_headers_stream(self):
        _, section_headers, _, _, data = self._build()
        streams = parse_msf(data)
        self.assertEqual(streams[8], section_headers)


if __name__ == "__main__":
    unittest.main()
