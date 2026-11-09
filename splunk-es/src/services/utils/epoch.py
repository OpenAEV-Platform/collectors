"""Convert OpenAEV timestamps to the epoch values Splunk expects."""

import math
import re
from datetime import datetime


def _epoch_seconds(value: str | None) -> float | None:
    """Parse an ISO-8601 timestamp or an epoch string to epoch seconds.

    Splunk's ``earliest``/``latest`` search modifiers accept epoch or the
    ``%m/%d/%Y:%H:%M:%S`` format only - they do NOT parse ISO-8601 strings
    with a ``Z`` suffix or sub-second precision beyond microseconds (as sent
    in OpenAEV expectation signatures). Passing those verbatim silently
    breaks the time bounds and the search returns 0 results.

    Returns:
        Epoch seconds, or None if empty / already relative / unparseable
        (the caller then falls back to a relative window).

    """
    text = str(value or "").strip()
    if not text or text[0] in "+-":
        return None
    if text.isdigit():
        return float(text)
    # datetime.fromisoformat reads at most 6 fraction digits (no nanoseconds).
    text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def to_epoch(value: str | None) -> int | None:
    """Convert a timestamp to epoch seconds for Splunk, rounding down."""
    seconds = _epoch_seconds(value)
    return None if seconds is None else math.floor(seconds)


def to_epoch_ceil(value: str | None) -> int | None:
    """Convert a timestamp to epoch seconds, rounding up.

    For the end of a window: ``10:00:00.9`` ends at ``10:00:01``, never cutting
    the last fraction of a second.
    """
    seconds = _epoch_seconds(value)
    return None if seconds is None else math.ceil(seconds)
