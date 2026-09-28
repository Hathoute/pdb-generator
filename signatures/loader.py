from __future__ import annotations

import jsonc
from dataclasses import dataclass


class SignatureFileError(Exception):
    pass


LABEL_MODES = ("pattern", "rip")


@dataclass
class SignatureFile:
    functions: dict
    labels: dict


def _load_group(path: str, root: dict, key: str) -> dict:
    group = root[key]
    if not isinstance(group, dict):
        raise SignatureFileError(f"{path}: '{key}' must be an object")
    kind = key[:-1]
    for name, entry in group.items():
        if not isinstance(entry, dict) or "windows" not in entry:
            raise SignatureFileError(
                f"{path}: {kind} {name!r} must be an object with a 'windows' pattern"
            )
        if key == "functions":
            if "mode" in entry:
                raise SignatureFileError(
                    f"{path}: function {name!r} must not set 'mode' "
                    f"(labels only)"
                )
            continue
        mode = entry.get("mode")
        if mode not in LABEL_MODES:
            raise SignatureFileError(
                f"{path}: label {name!r} must set 'mode' to 'pattern' or 'rip'"
            )
        if mode == "rip":
            if "rip_offset" not in entry:
                raise SignatureFileError(
                    f"{path}: label {name!r} with mode 'rip' requires 'rip_offset'"
                )
        elif "rip_offset" in entry:
            raise SignatureFileError(
                f"{path}: label {name!r} with mode 'pattern' must not set 'rip_offset'"
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
