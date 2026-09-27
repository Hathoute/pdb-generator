from __future__ import annotations

from dataclasses import dataclass


class PatternError(Exception):
    pass


@dataclass(frozen=True)
class Pattern:
    data: bytes
    mask: bytes

    @property
    def size(self) -> int:
        return len(self.data)


def compile_pattern(sig: str) -> Pattern:
    tokens = sig.split()
    if not tokens:
        raise PatternError("empty pattern")
    data = bytearray()
    mask = bytearray()
    for tok in tokens:
        if tok in ("?", "??"):
            data.append(0)
            mask.append(0)
            continue
        if len(tok) != 2:
            raise PatternError(f"invalid token {tok!r} (expected 2 hex digits or ?/??)")
        try:
            value = int(tok, 16)
        except ValueError:
            raise PatternError(f"invalid hex byte {tok!r}") from None
        data.append(value)
        mask.append(0xFF)
    if not any(mask):
        raise PatternError("pattern has no concrete bytes")
    return Pattern(bytes(data), bytes(mask))


def find_matches(data: bytes, pat: Pattern) -> list[int]:
    anchor_start = 0
    anchor_len = 0
    run_start = None
    for i, m in enumerate(pat.mask):
        if m:
            if run_start is None:
                run_start = i
        else:
            if run_start is not None and i - run_start > anchor_len:
                anchor_start, anchor_len = run_start, i - run_start
            run_start = None
    if run_start is not None and pat.size - run_start > anchor_len:
        anchor_start, anchor_len = run_start, pat.size - run_start
    anchor = pat.data[anchor_start : anchor_start + anchor_len]

    matches = []
    pos = 0
    while True:
        hit = data.find(anchor, pos)
        if hit == -1:
            break
        pos = hit + 1
        start = hit - anchor_start
        if start < 0 or start + pat.size > len(data):
            continue
        chunk = data[start : start + pat.size]
        ok = True
        for j in range(pat.size):
            if pat.mask[j] and chunk[j] != pat.data[j]:
                ok = False
                break
        if ok:
            matches.append(start)
    return matches
