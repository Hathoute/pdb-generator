from __future__ import annotations

import struct


MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


class MsfBuilder:
    def __init__(self, block_size: int = 4096):
        self.block_size = block_size
        self.streams: list[bytes] = []

    def add_stream(self, data: bytes) -> int:
        self.streams.append(bytes(data))
        return len(self.streams) - 1

    def serialize(self) -> bytes:
        B = self.block_size
        num_streams = len(self.streams)
        stream_blocks = [(len(s) + B - 1) // B for s in self.streams]
        total_stream_blocks = sum(stream_blocks)

        dir_bytes = 4 + 4 * num_streams + 4 * total_stream_blocks
        n_dir_blocks = (dir_bytes + B - 1) // B
        per_bm = B // 4
        n_bm_blocks = max(1, (n_dir_blocks + per_bm - 1) // per_bm)
        first_stream_block = 2 + n_bm_blocks
        first_dir_block = first_stream_block + total_stream_blocks
        num_blocks = first_dir_block + n_dir_blocks

        file = bytearray(num_blocks * B)

        directory = bytearray(struct.pack("<I", num_streams))
        block_lists = []
        next_block = first_stream_block
        for s, n_blocks in zip(self.streams, stream_blocks):
            directory += struct.pack("<I", len(s))
            blocks = list(range(next_block, next_block + n_blocks))
            block_lists.append(blocks)
            next_block += n_blocks
        for blocks in block_lists:
            for blk in blocks:
                directory += struct.pack("<I", blk)

        for s, blocks in zip(self.streams, block_lists):
            for i, blk in enumerate(blocks):
                chunk = s[i * B : (i + 1) * B]
                file[blk * B : blk * B + len(chunk)] = chunk

        dir_blocks = list(range(first_dir_block, first_dir_block + n_dir_blocks))
        for i, blk in enumerate(dir_blocks):
            chunk = bytes(directory[i * B : (i + 1) * B])
            file[blk * B : blk * B + len(chunk)] = chunk

        for i in range(n_bm_blocks):
            entries = dir_blocks[i * per_bm : (i + 1) * per_bm]
            packed = b"".join(struct.pack("<I", b) for b in entries)
            file[(2 + i) * B : (2 + i) * B + len(packed)] = packed

        superblock = bytearray(B)
        superblock[: len(MSF_MAGIC)] = MSF_MAGIC
        struct.pack_into(
            "<IIIIII", superblock, 0x20, B, 1, num_blocks, len(directory), 0, 2
        )
        file[:B] = superblock
        return bytes(file)
