"""Collector daemon data contracts: scheduling and platform defaults."""

__all__ = ["DEFAULT_PERIOD_SECONDS", "DEFAULT_PLATFORM_TAG_COLOR"]

DEFAULT_PERIOD_SECONDS = 60

# Neutral grey used for tags auto-created alongside the security platform,
# consistent with the tag colors already used across collectors.
DEFAULT_PLATFORM_TAG_COLOR = "#6b7280"
