"""Strict JSON, as the scenarios repository reads every JSON document of a release and asks
its consumers to: UTF-8, no key twice in an object, no NaN nor infinite number, no integer
beyond the range a double holds exactly, no unpaired surrogate, at most 64 levels deep.
"""

import json
import math
from typing import Any

MAX_DEPTH = 64
_SAFE_INTEGER = 2**53 - 1


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"not strict JSON: a key twice in an object ({key!r})")
        document[key] = value
    return document


def _constant(name: str) -> Any:
    raise ValueError(f"not strict JSON: {name} is not a number")


def _integer(text: str) -> int:
    value = int(text)
    if abs(value) > _SAFE_INTEGER:
        raise ValueError("not strict JSON: an integer beyond ±(2^53 − 1)")
    return value


def _float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("not strict JSON: not a finite number")
    return value


def _check(document: Any) -> None:
    """Refuse a document deeper than ``MAX_DEPTH``, or holding an unpaired surrogate, walked
    without recursion."""
    stack: list[tuple[Any, int]] = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        if isinstance(value, str):
            if any("\ud800" <= character <= "\udfff" for character in value):
                raise ValueError("not strict JSON: an unpaired surrogate")
        elif isinstance(value, (dict, list)):
            if depth > MAX_DEPTH:
                raise ValueError(f"not strict JSON: deeper than {MAX_DEPTH} levels")
            children = value.items() if isinstance(value, dict) else enumerate(value)
            for key, child in children:
                stack.append((key, depth))
                stack.append((child, depth + 1))


def read_strict_json(data: bytes, *, limit: int) -> Any:
    """The document ``data`` holds, read as strict JSON; ``ValueError`` with why otherwise,
    and before reading when ``data`` is over ``limit`` bytes."""
    if len(data) > limit:
        raise ValueError(f"over {limit} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("not UTF-8") from error
    try:
        document = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_int=_integer,
            parse_float=_float,
        )
    except RecursionError as error:
        raise ValueError(f"not strict JSON: deeper than {MAX_DEPTH} levels") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"not JSON: {error}") from error
    _check(document)
    return document
