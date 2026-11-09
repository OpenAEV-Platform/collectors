"""Collector runtime data contracts: the dev options of a collector."""

from dataclasses import dataclass

from xtm_oaev_sdk import DevOptions

__all__ = ["CollectorDevOptions"]


@dataclass(frozen=True)
class CollectorDevOptions(DevOptions):
    """Dev options of a collector: the common ones plus the collector's own.

    ``expectations`` names the pending expectations to answer, a JSON list as the
    platform serves them (``-`` for stdin), and ``once`` runs a single cycle.
    """

    expectations: str | None = None
    once: bool = False
