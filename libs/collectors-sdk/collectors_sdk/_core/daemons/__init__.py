"""Collector daemon runtime."""

from .collector_daemon import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
    CollectorDaemon,
)

__all__ = ["CollectorDaemon", "DEFAULT_PERIOD_SECONDS", "DEFAULT_PLATFORM_TAG_COLOR"]
