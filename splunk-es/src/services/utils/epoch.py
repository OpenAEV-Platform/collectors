"""Convert OpenAEV timestamps to the epoch values Splunk expects."""

import re
from datetime import datetime


def to_epoch(value: str | None) -> int | None:
    """Convert an ISO-8601 timestamp to a Unix epoch integer for Splunk.

    Splunk's ``earliest``/``latest`` search modifiers accept epoch or the
    ``%m/%d/%Y:%H:%M:%S`` format only - they do NOT parse ISO-8601 strings
    with a ``Z`` suffix or sub-second precision beyond microseconds (as sent
    in OpenAEV expectation signatures). Passing those verbatim silently
    breaks the time bounds and the search returns 0 results.

    Args:
        value: ISO-8601 timestamp (optionally with ``Z`` / nanoseconds), an
            epoch string, or None.

    Returns:
        Epoch seconds as int, or None if empty / already relative /
        unparseable (the caller then falls back to a relative window).

    """
    if not value:
        return None
    s = str(value).strip()
    if not s or s.startswith("-") or s.startswith("+"):
        return None
    if s.isdigit():
        return int(s)
    # Normalise 'Z' to a numeric offset and trim fractional seconds to the
    # 6 digits datetime.fromisoformat supports (drops nanoseconds).
    s = s.replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        return int(datetime.fromisoformat(s).timestamp())
    except ValueError:
        return None


def to_epoch_ceil(value: str | None) -> int | None:
    """Convert a timestamp to epoch seconds, rounding a fraction up.

    ``to_epoch`` drops the fraction of a second. For the end of a window that
    would cut its last fraction (``10:00:00.9`` would end at ``10:00:00``), so
    the end is rounded up instead.

    Args:
        value: ISO-8601 timestamp, an epoch string, or None.

    Returns:
        Epoch seconds rounded up, or None like ``to_epoch``.

    """
    epoch = to_epoch(value)
    if epoch is None:
        return None
    fraction = re.search(r"\.(\d+)", str(value))
    if fraction and int(fraction.group(1)) > 0:
        return epoch + 1
    return epoch
