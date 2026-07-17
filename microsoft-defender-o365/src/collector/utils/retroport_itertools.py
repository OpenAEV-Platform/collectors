import itertools
import sys
from typing import Iterable, Sequence, TypeVar

T = TypeVar("T")


def _batched(iterable: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    """
    pseudo-itertools.batched for python 3.11
    based on https://docs.python.org/3/library/itertools.html#itertools.batched
    """
    if size < 1:
        raise ValueError("size must be at least one")
    iterator = iter(iterable)
    while batch := tuple(itertools.islice(iterator, size)):
        yield batch


def batched(iterable: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    """providing support for itertools.batched in 3.11"""
    if not (sys.version_info.major >= 3 and sys.version_info.minor >= 12):
        return _batched(iterable, size)

    return itertools.batched(iterable, size)
