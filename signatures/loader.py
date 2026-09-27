from __future__ import annotations

import jsonc


class SignatureFileError(Exception):
    pass


def load_signatures(path: str) -> dict:
    data = jsonc.load(path)
    sigs = data.get("signatures")
    if not isinstance(sigs, dict):
        raise SignatureFileError(
            f"{path}: expected top-level object with a 'signatures' object"
        )
    for name, entry in sigs.items():
        if not isinstance(entry, dict) or "windows" not in entry:
            raise SignatureFileError(
                f"{path}: signature {name!r} must be an object with a 'windows' pattern"
            )
    return sigs
