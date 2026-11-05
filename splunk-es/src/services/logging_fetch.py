"""Splunk ES Logging search results.

The Logging search can end in five ways, and the Logging pass reacts
differently to each: match the events, try again on a later cycle, back off,
or stop Logging until the collector restarts. Each outcome is its own type so
that an error can never be mistaken for "no event found".
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .models import LoggingEvent

LOG_PREFIX = "[SplunkESLoggingFetch]"


@dataclass(frozen=True)
class LoggingRows:
    """The search returned events.

    Attributes:
        events: The events that could be read.
        skipped: Number of rows dropped because they were malformed.

    """

    events: list[LoggingEvent]
    skipped: int = 0


@dataclass(frozen=True)
class LoggingEmpty:
    """The search ran and found no event (HTTP 200, no results)."""


@dataclass(frozen=True)
class LoggingAuthError:
    """Splunk refused the credentials or the permission (HTTP 401 or 403).

    Retrying cannot succeed: the Logging pass stops until the collector
    restarts.
    """

    status_code: int
    message: str = field(default="")


@dataclass(frozen=True)
class LoggingApiError:
    """The search failed for a reason that may go away (5xx, timeout, network)."""

    message: str
    status_code: int | None = None


@dataclass(frozen=True)
class LoggingMalformed:
    """Splunk answered, but not with the expected JSON shape."""

    message: str


@dataclass(frozen=True)
class LoggingIndexCheck:
    """Which configured Logging indexes Splunk can search.

    Attributes:
        found: Indexes that exist and the role can read (a wildcard is found
            when it matches at least one index).
        missing: Indexes that do not exist or that the role cannot read.
            Searches on them silently return no event.

    """

    found: list[str]
    missing: list[str]


LoggingIndexCheckResult = (
    LoggingIndexCheck | LoggingAuthError | LoggingApiError | LoggingMalformed
)


LoggingFetchResult = (
    LoggingRows | LoggingEmpty | LoggingAuthError | LoggingApiError | LoggingMalformed
)


def parse_logging_rows(results: list[Any]) -> tuple[list[LoggingEvent], int]:
    """Turn the rows of a Logging search into events.

    A row needs a ``_time`` (ISO date, as Splunk returns it), an ``index``
    and a ``_raw`` text. A row without them is skipped and counted, so one bad row does not
    hide the others.

    Args:
        results: The ``results`` list of the Splunk JSON answer.

    Returns:
        The events, and the number of skipped rows.

    """
    logger = logging.getLogger(__name__)
    events: list[LoggingEvent] = []
    skipped = 0
    for position, row in enumerate(results):
        event = _parse_row(row)
        if event is None:
            skipped += 1
            logger.debug(f"{LOG_PREFIX} Skipped malformed Logging row {position}")
        else:
            events.append(event)
    return events, skipped


def _parse_row(row: Any) -> LoggingEvent | None:
    """Build one event from a search row, or None when the row is malformed."""
    if not isinstance(row, dict):
        return None
    try:
        event_epoch = datetime.fromisoformat(row.get("_time")).timestamp()  # type: ignore[arg-type]
    except TypeError, ValueError:
        return None
    index = row.get("index")
    raw = row.get("_raw")
    if not isinstance(index, str) or not index:
        return None
    if not isinstance(raw, str) or not raw:
        return None
    return LoggingEvent(
        event_epoch=event_epoch,
        index=index,
        host=_optional_text(row.get("host")),
        sourcetype=_optional_text(row.get("sourcetype")),
        raw=raw,
    )


def _optional_text(value: Any) -> str | None:
    """Keep a text field, or its first value when Splunk returns a list."""
    if isinstance(value, list):
        value = value[0] if value else None
    return value if isinstance(value, str) and value else None
