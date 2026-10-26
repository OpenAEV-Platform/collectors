"""Strict JSON reading: the reading the scenarios repository asks of its consumers."""

import pytest

from scenarios.strict_json import read_strict_json


def test_a_plain_document_is_read() -> None:
    assert read_strict_json(b'{"a": [1, 2.5, "x", true, null]}', limit=100) == {
        "a": [1, 2.5, "x", True, None]
    }


@pytest.mark.parametrize(
    ("data", "why"),
    [
        (b'{"a": 1, "a": 2}', "a key twice"),
        (b'{"a": NaN}', "not a number"),
        (b'{"a": Infinity}', "not a number"),
        (b'{"a": 1e400}', "not a finite number"),
        (b'{"a": 9007199254740992}', "beyond"),
        (b'{"a": -9007199254740992}', "beyond"),
        (b'{"a": "\\ud800"}', "unpaired surrogate"),
        (b'{"a": "\\udc00x"}', "unpaired surrogate"),
        (b"\xff", "not UTF-8"),
        (b"{", "not JSON"),
        (b"[" * 65 + b"]" * 65, "deeper than 64"),
    ],
)
def test_what_strict_json_refuses(data: bytes, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        read_strict_json(data, limit=10_000)


def test_the_largest_safe_integer_and_64_levels_are_read() -> None:
    assert read_strict_json(b"[9007199254740991, -9007199254740991]", limit=100) == [
        9007199254740991,
        -9007199254740991,
    ]
    assert read_strict_json(b"[" * 64 + b"]" * 64, limit=1000) is not None


def test_a_paired_surrogate_is_a_character() -> None:
    assert read_strict_json(b'"\\ud83d\\ude00"', limit=100) == "\U0001f600"


def test_a_document_over_the_limit_is_refused_before_it_is_read() -> None:
    with pytest.raises(ValueError, match="over 10 bytes"):
        read_strict_json(b'{"a": "0123456789"}', limit=10)


def test_a_very_deep_document_is_refused_not_crashed() -> None:
    with pytest.raises(ValueError, match="deeper than 64"):
        read_strict_json(b"[" * 100_000 + b"]" * 100_000, limit=1_000_000)
