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


def _resolve_rip_labels(
    group: dict,
    regions: list[tuple[int, bytes]],
    target_library: str,
    image: pe.PEImage,
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
        rip_offset = entry["rip_offset"]
        if rip_offset < 0 or rip_offset + 4 > pat.size:
            errors.append(
                SignatureError(
                    name,
                    "bad_pattern",
                    f"rip_offset {rip_offset} out of range for pattern of "
                    f"{pat.size} bytes",
                )
            )
            continue
        matches: list[tuple[int, bytes, int]] = []
        for rva, blob in regions:
            for m in signatures.find_matches(blob, pat):
                matches.append((rva, blob, m))
        if not matches:
            errors.append(
                SignatureError(name, "not_found", "no anchor match in executable sections")
            )
        elif len(matches) > 1:
            locs = ", ".join(f"0x{rva + m:X}" for rva, _b, m in matches)
            errors.append(
                SignatureError(name, "ambiguous", f"{len(matches)} matches: {locs}")
            )
        else:
            rva, blob, m = matches[0]
            disp = int.from_bytes(
                blob[m + rip_offset : m + rip_offset + 4], "little", signed=True
            )
            label_rva = rva + m + rip_offset + 4 + disp
            if pe.rva_to_section(image, label_rva) is None:
                errors.append(
                    SignatureError(
                        name,
                        "bad_ref",
                        f"anchor at 0x{rva + m:X} decodes to RVA 0x{label_rva:X}, "
                        f"outside all sections",
                    )
                )
            else:
                symbols.append((name, label_rva, "label"))


def resolve_signatures(
    sigs: signatures.SignatureFile, image: pe.PEImage, target_library: str
) -> Resolution:
    symbols: list[tuple[str, int, str]] = []
    errors: list[SignatureError] = []
    skipped: list[tuple[str, str]] = []

    exec_regions = image.exec_scan_regions()

    _resolve_group(
        sigs.functions,
        exec_regions,
        target_library,
        "executable sections",
        "function",
        symbols,
        errors,
        skipped,
    )

    pattern_labels = {
        n: e for n, e in sigs.labels.items() if e.get("mode") == "pattern"
    }
    rip_labels = {n: e for n, e in sigs.labels.items() if e.get("mode") == "rip"}

    _resolve_group(
        pattern_labels,
        image.all_scan_regions(),
        target_library,
        "all sections",
        "label",
        symbols,
        errors,
        skipped,
    )
    _resolve_rip_labels(
        rip_labels, exec_regions, target_library, image, symbols, errors, skipped
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
