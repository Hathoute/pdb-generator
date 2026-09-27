import struct

from .writer import S_PUB32


MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
BLOCK = 4096


def parse_msf(data: bytes):
    assert data[: len(MSF_MAGIC)] == MSF_MAGIC, "bad msf magic"
    block_size, fpm_block, num_blocks, dir_bytes, _unk, block_map_addr = struct.unpack_from(
        "<IIIIII", data, 0x20
    )
    assert block_size == BLOCK
    assert len(data) == num_blocks * block_size, (len(data), num_blocks, block_size)
    assert fpm_block in (1, 2)

    bm_off = block_map_addr * block_size
    n_dir_blocks = (dir_bytes + block_size - 1) // block_size
    dir_block_nums = struct.unpack_from(f"<{n_dir_blocks}I", data, bm_off)
    directory = b"".join(
        data[b * block_size : b * block_size + block_size] for b in dir_block_nums
    )[:dir_bytes]

    (num_streams,) = struct.unpack_from("<I", directory, 0)
    sizes = struct.unpack_from(f"<{num_streams}I", directory, 4)
    cursor = 4 + 4 * num_streams
    streams = []
    for size in sizes:
        if size == 0xFFFFFFFF:
            streams.append(None)
            continue
        n_blocks = (size + block_size - 1) // block_size
        blocks = struct.unpack_from(f"<{n_blocks}I", directory, cursor)
        cursor += 4 * n_blocks
        blob = b"".join(
            data[b * block_size : b * block_size + block_size] for b in blocks
        )[:size]
        streams.append(blob)
    return streams


def parse_records(blob):
    records = []
    off = 0
    while off < len(blob):
        (rec_len,) = struct.unpack_from("<H", blob, off)
        rec = blob[off + 2 : off + 2 + rec_len]
        (kind,) = struct.unpack_from("<H", rec, 0)
        total = 2 + rec_len
        assert total % 4 == 0, f"record at {off} not 4-aligned: {total}"
        if kind == S_PUB32:
            flags, sym_off, segment = struct.unpack_from("<IIH", rec, 2)
            name = rec[12:].split(b"\x00")[0].decode()
            records.append(
                {
                    "kind": kind,
                    "flags": flags,
                    "off": sym_off,
                    "segment": segment,
                    "name": name,
                    "stream_off": off,
                }
            )
        else:
            records.append({"kind": kind, "stream_off": off})
        off += total
    assert off == len(blob)
    return records
