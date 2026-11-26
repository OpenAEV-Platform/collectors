"""Read the ISO-8601 dates sent by OpenAEV and SentinelOne."""

import re
from datetime import datetime, timezone


def read_iso_date(value: str) -> tuple[datetime, str] | None:
    """Read an ISO-8601 date in UTC, with its fraction of a second kept apart.

    The fraction is kept as text: ``datetime.fromisoformat`` reads at most 6
    digits, while OpenAEV can send 9 (nanoseconds). Each caller decides how
    precise it needs to be.

    Args:
        value: The date, e.g. ``2026-11-24T08:00:00.123456789Z``. A date
            without a time zone is read as UTC.

    Returns:
        The date in UTC without its fraction, and the fraction digits (empty
        when there are none). None if the date cannot be read.

    """
    text = value.replace("Z", "+00:00")
    fraction = re.search(r"\.(\d+)", text)
    if fraction:
        text = text[: fraction.start()] + text[fraction.end() :]
    try:
        date = datetime.fromisoformat(text)
    except ValueError:
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc), fraction.group(1) if fraction else ""
