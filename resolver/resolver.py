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
    symbols: list[tuple[str, int, str]]
    errors: list[SignatureError]
    skipped: list[tuple[str, str]]


def _resolve_group(
    group: dict,
    regions: list[tuple[int, bytes]],
    target_library: str,
    where: str,
    kind: str,
    symbols: list[tuple[str, int, str]],
    errors: list[SignatureError],
    skipped: list[tuple[str, str]],
) -> None:
    for name, entry in group.items():
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
            errors.append(SignatureError(name, "not_found", f"no match in {where}"))
        elif len(matches) > 1:
            locs = ", ".join(f"0x{m:X}" for m in matches)
            errors.append(
                SignatureError(name, "ambiguous", f"{len(matches)} matches: {locs}")
            )
        else:
            symbols.append((name, matches[0], kind))


def resolve_signatures(
    sigs: signatures.SignatureFile, image: pe.PEImage, target_library: str
) -> Resolution:
    symbols: list[tuple[str, int, str]] = []
    errors: list[SignatureError] = []
    skipped: list[tuple[str, str]] = []

    _resolve_group(
        sigs.functions,
        image.exec_scan_regions(),
        target_library,
        "executable sections",
        "function",
        symbols,
        errors,
        skipped,
    )
    _resolve_group(
        sigs.labels,
        image.all_scan_regions(),
        target_library,
        "all sections",
        "label",
        symbols,
        errors,
        skipped,
    )

    dropped: set[str] = set()

    by_rva: dict[int, set[str]] = {}
    for name, rva, _kind in symbols:
        by_rva.setdefault(rva, set()).add(name)
    for rva, names in by_rva.items():
        if len(names) > 1:
            dropped.update(names)
            for name in names:
                others = ", ".join(sorted(n for n in names if n != name))
                errors.append(
                    SignatureError(
                        name, "clash", f"RVA 0x{rva:X} also matched by {others}"
                    )
                )

    by_name: dict[str, str] = {}
    for name, _rva, kind in symbols:
        if name not in dropped:
            if name in by_name:
                dropped.add(name)
                errors.append(
                    SignatureError(
                        name,
                        "clash",
                        f"name used in both functions and labels groups "
                        f"(first as {by_name[name]})",
                    )
                )
            else:
                by_name[name] = kind

    kept = [(n, r, k) for n, r, k in symbols if n not in dropped]
    kept.sort(key=lambda item: item[1])
    return Resolution(kept, errors, skipped)
