"""Collector daemon runtime (API client injected, see ``xtm_oaev_sdk.BaseClient``)."""

from collectors_sdk._core.daemons import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
    CollectorDaemon,
)

__all__ = ["CollectorDaemon", "DEFAULT_PERIOD_SECONDS", "DEFAULT_PLATFORM_TAG_COLOR"]
