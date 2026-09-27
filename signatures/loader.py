from __future__ import annotations

import jsonc
from dataclasses import dataclass


class SignatureFileError(Exception):
    pass


@dataclass
class SignatureFile:
    functions: dict
    labels: dict


def _load_group(path: str, root: dict, key: str) -> dict:
    group = root[key]
    if not isinstance(group, dict):
        raise SignatureFileError(f"{path}: '{key}' must be an object")
    for name, entry in group.items():
        if not isinstance(entry, dict) or "windows" not in entry:
            raise SignatureFileError(
                f"{path}: {key[:-1]} {name!r} must be an object with a 'windows' pattern"
            )
    return group


def load_signatures(path: str) -> SignatureFile:
    data = jsonc.load(path)
    if not isinstance(data, dict):
        raise SignatureFileError(
            f"{path}: expected top-level object with 'functions' and 'labels' objects"
        )
    missing = [key for key in ("functions", "labels") if key not in data]
    if missing:
        raise SignatureFileError(
            f"{path}: expected top-level object with 'functions' and 'labels' objects; "
            f"missing {', '.join(repr(k) for k in missing)}"
        )
    return SignatureFile(
        functions=_load_group(path, data, "functions"),
        labels=_load_group(path, data, "labels"),
    )
