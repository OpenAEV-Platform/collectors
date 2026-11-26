"""SentinelOne Logging search results.

The Logging search can end in five ways, and the Logging pass reacts
differently to each: match the events, try again on a later cycle, or stop
Logging until the collector restarts. Each outcome is its own type, so that an
error can never be mistaken for "no event found".
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from .exception import SentinelOneAPIError, SentinelOneNetworkError
from .fetcher_deep_visibility import FetcherDeepVisibility
from .fetcher_sdl import FetcherSDL
from .logging_query import LoggingQuery
from .utils.dates import read_iso_date

LOG_PREFIX = "[SentinelOneLoggingFetch]"
AUTH_ERROR_STATUS_CODES = (401, 403)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LoggingEvent:
    """One raw event returned by the Logging search.

    Attributes:
        event_time: When the event happened, in UTC.
        event_type: Kind of event, e.g. ``Process Creation`` or ``IP Connect``.
        endpoint_name: Name of the machine that recorded the event.
        event_id: SentinelOne id of the event.
        tgt_process_name: Process that was created or acted on.
        src_process_name: Process that did the action.
        src_parent_process_name: Parent of the process that did the action.
        src_ip: Source IP of a network event.
        dst_ip: Destination IP of a network event.

    """

    event_time: datetime
    event_type: str | None = None
    endpoint_name: str | None = None
    event_id: str | None = None
    tgt_process_name: str | None = None
    src_process_name: str | None = None
    src_parent_process_name: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None


@dataclass(frozen=True)
class LoggingRows:
    """The search returned events.

    Attributes:
        events: The events that could be read.
        skipped: Number of rows dropped because they could not be read.

    """

    events: list[LoggingEvent]
    skipped: int = 0


@dataclass(frozen=True)
class LoggingEmpty:
    """The search ran and found no event."""


@dataclass(frozen=True)
class LoggingAuthError:
    """SentinelOne refused the token or the permission (HTTP 401 or 403).

    Retrying cannot succeed: the Logging pass stops until the collector
    restarts.
    """

    status_code: int
    message: str = ""


@dataclass(frozen=True)
class LoggingApiError:
    """The search failed for a reason that may go away.

    Rate limit (429), server error, timeout or network error. ``status_code``
    is None when SentinelOne gave no HTTP answer.
    """

    message: str
    status_code: int | None = None


@dataclass(frozen=True)
class LoggingMalformed:
    """SentinelOne returned rows, but none of them could be read.

    This usually means a field name or a date format is not the expected one,
    so it is reported as an error instead of "no event found".
    """

    message: str


LoggingFetchResult = (
    LoggingRows | LoggingEmpty | LoggingAuthError | LoggingApiError | LoggingMalformed
)


def fetch_logging_events(
    fetcher: FetcherSDL | FetcherDeepVisibility,
    query: LoggingQuery,
    deadline: datetime | None = None,
) -> LoggingFetchResult:
    """Run the Logging search of one expectation and read its events.

    A row needs a readable event time. A row without it is skipped and
    counted, so one bad row does not hide the others. When no row at all can
    be read, the result is ``LoggingMalformed``.

    Args:
        fetcher: The event search of the console: ``FetcherSDL`` on SaaS,
            ``FetcherDeepVisibility`` on self-hosted. It must match the S1QL
            version of ``query.filter``.
        query: The search built by ``build_logging_query``.
        deadline: When the search must stop. A search cut by it is an API
            error, like a timeout. None for no deadline.

    Returns:
        The events, ``LoggingEmpty`` when none was found,
        ``LoggingMalformed`` when no returned row could be read, or the error.

    """
    try:
        rows = fetcher.fetch_rows(
            query.filter, query.start, query.end, deadline=deadline
        )
    except SentinelOneAPIError as e:
        if e.status_code in AUTH_ERROR_STATUS_CODES:
            return LoggingAuthError(status_code=e.status_code, message=str(e))
        return LoggingApiError(message=str(e), status_code=e.status_code)
    except SentinelOneNetworkError as e:
        return LoggingApiError(message=str(e))

    if not rows:
        return LoggingEmpty()
    events = [
        event
        for event in (_parse_row(row, fetcher.LOGGING_FIELDS) for row in rows)
        if event is not None
    ]
    if not events:
        return LoggingMalformed(message=f"None of the {len(rows)} rows could be read")
    skipped = len(rows) - len(events)
    if skipped:
        logger.debug(f"{LOG_PREFIX} Skipped {skipped} unreadable Logging rows")
    return LoggingRows(events=events, skipped=skipped)


def _parse_row(row: Any, fields: dict[str, str]) -> LoggingEvent | None:
    """Build one event from a row, or None when the row has no readable time.

    Args:
        row: The event fields by name, as returned by ``fetch_rows``.
        fields: The fetcher's ``LOGGING_FIELDS``: where each event value is.

    Returns:
        The event, or None.

    """
    if not isinstance(row, dict):
        return None
    event_time = _parse_event_time(row.get(fields["event_time"]))
    if event_time is None:
        return None
    return LoggingEvent(
        event_time=event_time,
        **{
            attribute: _text(row.get(name))
            for attribute, name in fields.items()
            if attribute != "event_time"
        },
    )


def _text(value: Any) -> str | None:
    """Keep a value as text, or None when it is empty."""
    text = "" if value is None else str(value).strip()
    return text or None


def _parse_event_time(value: Any) -> datetime | None:
    """Read an event time as a UTC datetime.

    SDL sends milliseconds since 1970 (a number, or a number in a string).
    Deep Visibility sends an ISO-8601 date.

    Args:
        value: The event time as found in the row.

    Returns:
        The time in UTC, to the microsecond, or None if it cannot be read.

    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    try:
        # Decimal reads the number exactly, with no float rounding.
        milliseconds = Decimal(text)
    except InvalidOperation:
        date = read_iso_date(text)
        if date is None:
            return None
        whole_seconds, fraction = date
        # A datetime holds microseconds: digits after the sixth are dropped.
        return whole_seconds + timedelta(microseconds=int(fraction[:6].ljust(6, "0")))
    try:
        return EPOCH + timedelta(microseconds=int(milliseconds * 1000))
    # ValueError and OverflowError cover NaN, infinity and out-of-range times.
    except OverflowError, ValueError:
        return None
