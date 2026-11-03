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
