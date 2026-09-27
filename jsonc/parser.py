from __future__ import annotations

import json


class JsoncError(Exception):
    pass


def strip_jsonc_comments(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            out.append(" ")
            continue
        out.append(c)
        i += 1
    return "".join(out)


def loads(text: str) -> dict:
    try:
        return json.loads(strip_jsonc_comments(text))
    except json.JSONDecodeError as e:
        raise JsoncError(str(e)) from e


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        return loads(text)
    except JsoncError as e:
        raise JsoncError(f"failed to parse {path} as JSONC: {e}") from e
