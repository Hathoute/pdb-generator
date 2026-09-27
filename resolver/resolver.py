from __future__ import annotations

from dataclasses import dataclass

import pe
import signatures


class SignatureError(Exception):
    def __init__(self, name: str, kind: str, detail: str):
        self.name = name
        self.kind = kind
        self.detail = detail
        super().__init__(f"{name}: {kind} ({detail})")


@dataclass
class Resolution:
    symbols: list[tuple[str, int]]
    errors: list[SignatureError]
    skipped: list[tuple[str, str]]


def resolve_signatures(
    sigs: dict, image: pe.PEImage, target_library: str
) -> Resolution:
    regions = image.exec_scan_regions()
    symbols: list[tuple[str, int]] = []
    errors: list[SignatureError] = []
    skipped: list[tuple[str, str]] = []

    for name, entry in sigs.items():
        lib = entry.get("library", target_library)
        if lib != target_library:
            skipped.append((name, lib))
            continue
        try:
            pat = signatures.compile_pattern(entry["windows"])
        except signatures.PatternError as e:
            errors.append(SignatureError(name, "bad_pattern", str(e)))
            continue
        matches: list[int] = []
        for rva, blob in regions:
            matches.extend(rva + m for m in signatures.find_matches(blob, pat))
        if not matches:
            errors.append(
                SignatureError(name, "not_found", "no match in executable sections")
            )
        elif len(matches) > 1:
            where = ", ".join(f"0x{m:X}" for m in matches)
            errors.append(
                SignatureError(name, "ambiguous", f"{len(matches)} matches: {where}")
            )
        else:
            symbols.append((name, matches[0]))

    by_rva: dict[int, list[str]] = {}
    for name, rva in symbols:
        by_rva.setdefault(rva, []).append(name)
    for rva, names in by_rva.items():
        if len(names) > 1:
            for name in names:
                others = ", ".join(n for n in names if n != name)
                errors.append(
                    SignatureError(
                        name, "clash", f"RVA 0x{rva:X} also matched by {others}"
                    )
                )

    symbols.sort(key=lambda item: item[1])
    return Resolution(symbols, errors, skipped)
