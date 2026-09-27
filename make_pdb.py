from __future__ import annotations

import argparse
import jsonc
import os
import pe
import pdb as pdb_pkg
import resolver
import signatures
import sys
import time
import uuid as uuid_mod
from typing import Iterable


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a PDB with function names resolved by byte-pattern signatures."
    )
    parser.add_argument("--dll", default="server.dll", help="target PE file")
    parser.add_argument("--sig", default="signatures.jsonc", help="JSONC signatures file")
    parser.add_argument("--out", default=None, help="output PDB path")
    args = parser.parse_args(argv)

    dll_path = args.dll
    target_library = os.path.basename(dll_path)
    out_path = args.out if args.out else os.path.splitext(dll_path)[0] + ".pdb"

    try:
        sigs = signatures.load_signatures(args.sig)
    except (OSError, jsonc.JsoncError, signatures.SignatureFileError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        with open(dll_path, "rb") as f:
            image = pe.PEImage.parse(f.read())
    except (OSError, pe.PeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    res = resolver.resolve_signatures(sigs, image, target_library)
    for name, lib in res.skipped:
        print(f"warning: skipped {name} (library {lib} != {target_library})")

    if res.errors:
        print(
            f"error: {len(res.errors)} signature problem(s); PDB not written:",
            file=sys.stderr,
        )
        for e in res.errors:
            print(f"  [{e.kind}] {e.name}: {e.detail}", file=sys.stderr)
        return 2

    if image.debug_cv:
        guid, age = image.debug_cv
    else:
        guid, age = uuid_mod.uuid4(), 1

    pdb_symbols = []
    for name, rva, kind in res.symbols:
        seg_off = pe.rva_to_section(image, rva)
        if seg_off is None:
            print(
                f"error: RVA 0x{rva:X} for {name!r} lies outside all sections",
                file=sys.stderr,
            )
            return 1
        segment, offset = seg_off
        flags = pdb_pkg.PUBSYM_FUNCTION if kind == "function" else pdb_pkg.PUBSYM_DATA
        pdb_symbols.append((name, segment, offset, flags))

    blob = pdb_pkg.build_pdb(
        [
            pdb_pkg.SectionEntry(sec.characteristics, sec.vsize)
            for sec in image.sections
        ],
        image.section_headers_blob(),
        pdb_symbols,
        guid,
        age,
        int(time.time()),
    )

    try:
        with open(out_path, "wb") as f:
            f.write(blob)
    except OSError as e:
        print(f"error: cannot write {out_path}: {e}", file=sys.stderr)
        return 1

    n_functions = sum(1 for _n, _r, k in res.symbols if k == "function")
    n_labels = len(res.symbols) - n_functions
    print(f"wrote {n_functions} functions and {n_labels} labels to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
