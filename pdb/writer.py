from __future__ import annotations

import struct
import uuid as uuid_mod
from dataclasses import dataclass

from .msf import MsfBuilder


PUBSYM_FUNCTION = 0x2
S_PUB32 = 0x110E
IPHR_HASH = 0x3FFFF
GSI_VERHDR = (0x0EFFE0000 + 19990810) & 0xFFFFFFFF
IMPL_VC70 = 20000404
DBI_V70 = 19990903
TPI_V80 = 20040203
FEATURE_MINIMAL_DEBUG_INFO = 0x494E494D
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_16BIT = 0x00020000
INVALID_STREAM_INDEX = 0xFFFF
DBG_SECTION_HEADER_SLOT = 6
DBG_SECTION_HEADER_STREAM = 8


@dataclass(frozen=True)
class SectionEntry:
    characteristics: int
    vsize: int


def encode_pub32(
    name: str, offset: int, segment: int, flags: int = PUBSYM_FUNCTION
) -> bytes:
    body = struct.pack("<HIIH", S_PUB32, flags, offset, segment)
    body += name.encode("utf-8") + b"\x00"
    total = (2 + len(body) + 3) & ~3
    return struct.pack("<H", total - 2) + body + b"\x00" * (total - 2 - len(body))


def hash_string_v1(name: bytes) -> int:
    result = 0
    n = len(name)
    idx = 0
    while idx + 4 <= n:
        (value,) = struct.unpack_from("<I", name, idx)
        result ^= value
        idx += 4
    rem = n - idx
    if rem >= 2:
        (value,) = struct.unpack_from("<H", name, idx)
        result ^= value
        idx += 2
        rem -= 2
    if rem == 1:
        result ^= name[idx]
    result |= 0x20202020
    result ^= result >> 11
    result &= 0xFFFFFFFF
    return result ^ (result >> 16)


def _secmap_flags(chars: int) -> int:
    flags = 0
    if chars & IMAGE_SCN_MEM_READ:
        flags |= 0x1
    if chars & IMAGE_SCN_MEM_WRITE:
        flags |= 0x2
    if chars & IMAGE_SCN_MEM_EXECUTE:
        flags |= 0x4
    if not chars & IMAGE_SCN_MEM_16BIT:
        flags |= 0x8
    flags |= 0x100
    return flags


def _build_section_map(sections: list[SectionEntry]) -> bytes:
    entries = []
    for i, sec in enumerate(sections):
        entries.append(
            struct.pack(
                "<HHHHHHII",
                _secmap_flags(sec.characteristics),
                0,
                0,
                i + 1,
                0xFFFF,
                0xFFFF,
                0,
                sec.vsize,
            )
        )
    entries.append(
        struct.pack(
            "<HHHHHHII",
            0x8 | 0x200,
            0,
            0,
            len(sections) + 1,
            0xFFFF,
            0xFFFF,
            0,
            0xFFFFFFFF,
        )
    )
    return struct.pack("<HH", len(entries), len(entries)) + b"".join(entries)


def _build_gsi_hash_blob(pubs: list[dict]) -> bytes:
    buckets: dict[int, list[dict]] = {}
    for p in pubs:
        bucket = hash_string_v1(p["name"].encode("utf-8")) % IPHR_HASH
        buckets.setdefault(bucket, []).append(p)

    bitmap = [0] * ((IPHR_HASH + 32) // 32)
    hash_records = bytearray()
    bucket_starts: list[int] = []
    for bucket in sorted(buckets):
        entries = sorted(
            buckets[bucket],
            key=lambda p: (
                len(p["name"].encode("utf-8")),
                p["name"].encode("utf-8").lower(),
                p["sym_off"],
            ),
        )
        bucket_starts.append((len(hash_records) // 8) * 12)
        for p in entries:
            hash_records += struct.pack("<II", p["sym_off"] + 1, 1)
        bitmap[bucket // 32] |= 1 << (bucket % 32)

    num_buckets = len(bitmap) * 4 + len(bucket_starts) * 4
    header = struct.pack(
        "<IIII", 0xFFFFFFFF, GSI_VERHDR, len(hash_records), num_buckets
    )
    bitmap_bytes = struct.pack(f"<{len(bitmap)}I", *bitmap)
    buckets_bytes = (
        struct.pack(f"<{len(bucket_starts)}I", *bucket_starts) if bucket_starts else b""
    )
    return header + bytes(hash_records) + bitmap_bytes + buckets_bytes


def _build_empty_gsi_stream() -> bytes:
    bitmap_words = (IPHR_HASH + 32) // 32
    header = struct.pack("<IIII", 0xFFFFFFFF, GSI_VERHDR, 0, bitmap_words * 4)
    return header + b"\x00" * (bitmap_words * 4)


def build_pdb(
    sections: list[SectionEntry],
    section_headers: bytes,
    symbols: list[tuple[str, int, int]],
    guid: uuid_mod.UUID,
    age: int,
    timestamp: int,
) -> bytes:
    pubs: list[dict] = [
        {"name": name, "segment": segment, "offset": offset}
        for name, segment, offset in symbols
    ]

    pubs.sort(key=lambda p: p["name"].encode("utf-8"))
    record_stream = bytearray()
    sym_off = 0
    for p in pubs:
        rec = encode_pub32(p["name"], p["offset"], p["segment"])
        p["sym_off"] = sym_off
        record_stream += rec
        sym_off += len(rec)

    psh_blob = _build_gsi_hash_blob(pubs)
    addr_sorted = sorted(pubs, key=lambda p: (p["segment"], p["offset"], p["name"]))
    publics_stream = (
        struct.pack(
            "<IIIIH2xII", len(psh_blob), 4 * len(pubs), 0, 0, 0, 0, 0
        )
        + psh_blob
        + b"".join(struct.pack("<I", p["sym_off"]) for p in addr_sorted)
    )

    globals_stream = _build_empty_gsi_stream()

    secmap = _build_section_map(sections)
    fileinfo = struct.pack("<HH", 0, 0)
    ec = (
        struct.pack("<III", 0xEFFEEFFE, 1, 1)
        + b"\x00"
        + struct.pack("<II", 1, 0)
        + struct.pack("<I", 0)
    )
    dbg_streams = [INVALID_STREAM_INDEX] * 11
    dbg_streams[DBG_SECTION_HEADER_SLOT] = DBG_SECTION_HEADER_STREAM

    dbi_header = struct.pack(
        "<iIIHHHHHHiiiiiIiiHHI",
        -1,
        DBI_V70,
        age,
        5,
        0,
        6,
        0,
        7,
        0,
        0,
        0,
        len(secmap),
        len(fileinfo),
        0,
        0,
        11 * 2,
        len(ec),
        0,
        0x8664,
        0,
    )
    dbi = dbi_header + secmap + fileinfo + ec + struct.pack("<11H", *dbg_streams)

    tpi_header = struct.pack(
        "<IIIIIHHIIiIiIiI",
        TPI_V80,
        56,
        0x1000,
        0x1000,
        0,
        INVALID_STREAM_INDEX,
        INVALID_STREAM_INDEX,
        4,
        0x3FFFF,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    named_map = (
        struct.pack("<I", 0)
        + struct.pack("<III", 0, 1, 0)
        + struct.pack("<I", 0)
    )
    info_stream = (
        struct.pack("<III", IMPL_VC70, timestamp, age)
        + guid.bytes_le
        + named_map
        + struct.pack("<I", FEATURE_MINIMAL_DEBUG_INFO)
    )

    msf = MsfBuilder()
    msf.add_stream(b"")
    msf.add_stream(info_stream)
    msf.add_stream(tpi_header)
    msf.add_stream(dbi)
    msf.add_stream(tpi_header)
    msf.add_stream(globals_stream)
    msf.add_stream(publics_stream)
    msf.add_stream(bytes(record_stream))
    msf.add_stream(section_headers)
    return msf.serialize()
