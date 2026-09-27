from __future__ import annotations

import struct
import uuid as uuid_mod
from dataclasses import dataclass


class PeError(Exception):
    pass


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
DEBUG_TYPE_CODEVIEW = 2


@dataclass
class Section:
    name: str
    vsize: int
    va: int
    raw_size: int
    raw_ptr: int
    characteristics: int


@dataclass
class PEImage:
    data: bytes
    sections: list[Section]
    section_table_off: int = 0
    debug_cv: tuple[uuid_mod.UUID, int] | None = None

    @classmethod
    def parse(cls, data: bytes) -> "PEImage":
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PeError("not a PE file (missing MZ signature)")
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise PeError("not a PE file (missing PE signature)")
        machine, num_sections = struct.unpack_from("<HH", data, e_lfanew + 4)
        size_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        opt_off = e_lfanew + 24
        (opt_magic,) = struct.unpack_from("<H", data, opt_off)
        if opt_magic == 0x20B:
            num_rva_off, dd_off = opt_off + 108, opt_off + 112
        elif opt_magic == 0x10B:
            num_rva_off, dd_off = opt_off + 92, opt_off + 96
        else:
            raise PeError(f"unsupported optional header magic 0x{opt_magic:X}")
        (num_rvas,) = struct.unpack_from("<I", data, num_rva_off)

        section_table = e_lfanew + 4 + 20 + size_opt
        sections = []
        for i in range(num_sections):
            off = section_table + 40 * i
            raw_name = data[off : off + 8]
            name = raw_name.rstrip(b"\x00").decode("ascii", "replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            sections.append(Section(name, vsize, va, raw_size, raw_ptr, chars))

        img = cls(data, sections, section_table)
        if num_rvas > IMAGE_DIRECTORY_ENTRY_DEBUG:
            img.debug_cv = img._parse_debug_cv(dd_off + 8 * IMAGE_DIRECTORY_ENTRY_DEBUG)
        return img

    def _parse_debug_cv(self, dd_entry_off: int) -> tuple[uuid_mod.UUID, int] | None:
        dd_rva, dd_size = struct.unpack_from("<II", self.data, dd_entry_off)
        if dd_rva == 0 or dd_size == 0:
            return None
        off = self.rva_to_offset(dd_rva)
        if off is None:
            return None
        for i in range(dd_size // 28):
            entry = off + 28 * i
            (_chars, _ts, _maj, _min, dtype, dsize, addr_raw, ptr_raw) = struct.unpack_from(
                "<IIHHIIII", self.data, entry
            )
            if dtype != DEBUG_TYPE_CODEVIEW:
                continue
            cv_off = ptr_raw if ptr_raw else self.rva_to_offset(addr_raw)
            if cv_off is None:
                continue
            if self.data[cv_off : cv_off + 4] != b"RSDS":
                continue
            guid = uuid_mod.UUID(bytes_le=self.data[cv_off + 4 : cv_off + 20])
            (age,) = struct.unpack_from("<I", self.data, cv_off + 20)
            return guid, age
        return None

    def rva_to_offset(self, rva: int) -> int | None:
        for sec in self.sections:
            if sec.va <= rva < sec.va + sec.vsize:
                delta = rva - sec.va
                if delta < sec.raw_size:
                    return sec.raw_ptr + delta
                return None
        return None

    def exec_scan_regions(self) -> list[tuple[int, bytes]]:
        return [
            (sec.va, self.data[sec.raw_ptr : sec.raw_ptr + sec.raw_size])
            for sec in self.sections
            if sec.characteristics & IMAGE_SCN_MEM_EXECUTE and sec.raw_size > 0
        ]

    def all_scan_regions(self) -> list[tuple[int, bytes]]:
        return [
            (sec.va, self.data[sec.raw_ptr : sec.raw_ptr + sec.raw_size])
            for sec in self.sections
            if sec.raw_size > 0
        ]

    def section_headers_blob(self) -> bytes:
        return self.data[
            self.section_table_off : self.section_table_off + 40 * len(self.sections)
        ]


def rva_to_section(image: PEImage, rva: int) -> tuple[int, int] | None:
    for i, sec in enumerate(image.sections):
        if sec.va <= rva < sec.va + max(sec.vsize, sec.raw_size):
            return i + 1, rva - sec.va
    return None
