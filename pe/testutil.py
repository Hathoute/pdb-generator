import struct

import pe


def build_pe(sections, debug_cv=None):
    pe_sig_off = 0x80
    coff_off = pe_sig_off + 4
    opt_off = coff_off + 20
    section_table_off = opt_off + 0xF0

    debug_raw_len = 0
    if debug_cv is not None:
        cv_data = (
            b"RSDS"
            + debug_cv["guid"].bytes_le
            + struct.pack("<I", debug_cv["age"])
            + b"dummy.pdb\x00"
        )
        debug_raw_len = 28 + len(cv_data)

    va = 0x1000
    placed = []
    for sec in sections:
        placed.append((sec["name"], sec["raw"], sec["exec"], va))
        va = (va + max(sec["vsize"], len(sec["raw"])) + 0xFFF) & ~0xFFF

    debug_va = 0
    if debug_cv is not None:
        debug_va = va
        placed.append((".debug", None, False, debug_va))

    raw_off = (section_table_off + 40 * len(placed) + 0xFFF) & ~0xFFF
    with_raw = []
    for name, raw, exec_flag, sec_va in placed:
        raw_len = debug_raw_len if raw is None else len(raw)
        with_raw.append((name, raw, exec_flag, sec_va, raw_off))
        raw_off += raw_len

    headers = bytearray(section_table_off)
    struct.pack_into("<H", headers, 0, 0x5A4D)
    struct.pack_into("<I", headers, 0x3C, pe_sig_off)

    coff = struct.pack("<HHIIIHH", 0x8664, len(placed), 0, 0, 0, 0xF0, 0x2022)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 108, 16)
    if debug_cv is not None:
        struct.pack_into("<II", opt, 112 + 6 * 8, debug_va, 28)

    image = bytearray(raw_off)
    image[: len(headers)] = headers
    image[pe_sig_off : pe_sig_off + 4] = b"PE\x00\x00"
    image[coff_off : coff_off + 20] = coff
    image[opt_off : opt_off + 0xF0] = opt

    for i, (name, raw, exec_flag, sec_va, sec_raw_off) in enumerate(with_raw):
        hdr = bytearray(40)
        encoded = name.encode()[:8]
        hdr[: len(encoded)] = encoded
        raw_len = debug_raw_len if raw is None else len(raw)
        vsize_field = debug_raw_len if raw is None else max(sec["vsize"], raw_len)
        struct.pack_into("<IIII", hdr, 8, vsize_field, sec_va, raw_len, sec_raw_off)
        chars = (0x60000020 if exec_flag else 0x40000040) | 0x40
        struct.pack_into("<I", hdr, 36, chars)
        st = section_table_off + 40 * i
        image[st : st + 40] = hdr
        if raw is not None:
            image[sec_raw_off : sec_raw_off + len(raw)] = raw

    if debug_cv is not None:
        _, _, _, dbg_va, dbg_raw_off = with_raw[-1]
        dbg_dir = struct.pack(
            "<IIHHIIII",
            0, 0, 0, 0, 2, len(cv_data), dbg_va + 28, dbg_raw_off + 28,
        )
        image[dbg_raw_off : dbg_raw_off + 28] = dbg_dir
        image[dbg_raw_off + 28 : dbg_raw_off + 28 + len(cv_data)] = cv_data

    return bytes(image)


def make_image(entries_pattern_pairs=(), sections_spec=None, debug_cv=None):
    if sections_spec is None:
        sections_spec = [
            {
                "name": ".text",
                "vsize": 0x100,
                "raw": b"\x00" * 0x100,
                "exec": True,
            },
            {
                "name": ".rdata",
                "vsize": 0x100,
                "raw": b"\x00" * 0x100,
                "exec": False,
            },
        ]
        for off, blob in entries_pattern_pairs:
            sections_spec[0]["raw"] = (
                sections_spec[0]["raw"][:off]
                + blob
                + sections_spec[0]["raw"][off + len(blob) :]
            )
    return pe.PEImage.parse(build_pe(sections_spec, debug_cv))
