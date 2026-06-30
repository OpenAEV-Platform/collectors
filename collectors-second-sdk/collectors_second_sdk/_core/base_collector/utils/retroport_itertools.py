"""Retro-compatible itertools utilities for Python 3.11 support."""

from itertools import islice
from typing import Any, Iterator


def batched(iterable: Any, n: int) -> Iterator[tuple]:
    """Batch data into tuples of length n. The last batch may be shorter.

    Backport of itertools.batched from Python 3.12.
    """
    if n < 1:
        raise ValueError("n must be at least one")
    it = iter(iterable)
    while batch := tuple(islice(it, n)):
        yield batch
