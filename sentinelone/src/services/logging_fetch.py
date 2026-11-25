"""SentinelOne Logging search results.

The Logging search can end in four ways, and the Logging pass reacts
differently to each: match the events, try again on a later cycle, or stop
Logging until the collector restarts. Each outcome is its own type, so that an
error can never be mistaken for "no event found".
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .exception import SentinelOneAPIError, SentinelOneNetworkError
from .fetcher_deep_visibility import FetcherDeepVisibility
from .fetcher_sdl import FetcherSDL
from .logging_query import LoggingQuery

LOG_PREFIX = "[SentinelOneLoggingFetch]"
AUTH_ERROR_STATUS_CODES = (401, 403)

# Where each value is in an SDL row (S1QL 2.0 field names).
SDL_FIELDS = {
    "time": ("event.time",),
    "type": ("event.type",),
    "endpoint": ("endpoint.name",),
    "id": ("event.id",),
    "tgt_process": ("tgt.process.name",),
    "src_process": ("src.process.name",),
    "src_parent_process": ("src.process.parent.name",),
    "src_ip": ("src.ip.address",),
    "dst_ip": ("dst.ip.address",),
}
# Where each value is in a Deep Visibility event. Only processName and
# parentProcessName are used by Detection today: the other names are not
# checked on a self-hosted console yet, so the likely spellings are all tried.
DV_FIELDS = {
    "time": ("eventTime", "createdAt"),
    "type": ("eventType",),
    "endpoint": ("agentName", "agentComputerName", "endpointName"),
    "id": ("id", "eventId"),
    "tgt_process": ("tgtProcName", "targetProcessName"),
    "src_process": ("processName", "srcProcName"),
    "src_parent_process": ("parentProcessName", "srcProcParentName"),
    "src_ip": ("srcIp", "srcIP"),
    "dst_ip": ("dstIp", "dstIP"),
}


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
    message: str = field(default="")


@dataclass(frozen=True)
class LoggingApiError:
    """The search failed for a reason that may go away.

    Rate limit (429), server error, timeout or network error. ``status_code``
    is None when SentinelOne gave no HTTP answer.
    """

    message: str
    status_code: int | None = None


LoggingFetchResult = LoggingRows | LoggingEmpty | LoggingAuthError | LoggingApiError


def fetch_logging_events(
    fetcher: FetcherSDL | FetcherDeepVisibility, query: LoggingQuery
) -> LoggingFetchResult:
    """Run the Logging search of one expectation and read its events.

    Args:
        fetcher: The event search of the console: ``FetcherSDL`` on SaaS,
            ``FetcherDeepVisibility`` on self-hosted. It must match the S1QL
            version of ``query.filter``.
        query: The search built by ``build_logging_query``.

    Returns:
        The events, ``LoggingEmpty`` when none was found, or the error.

    """
    logger = logging.getLogger(__name__)
    try:
        rows = fetcher.fetch_rows(query.filter, query.start, query.end)
    except SentinelOneAPIError as e:
        if e.status_code in AUTH_ERROR_STATUS_CODES:
            return LoggingAuthError(status_code=e.status_code, message=str(e))
        return LoggingApiError(message=str(e), status_code=e.status_code)
    except SentinelOneNetworkError as e:
        return LoggingApiError(message=str(e))

    if not rows:
        return LoggingEmpty()
    fields = DV_FIELDS if isinstance(fetcher, FetcherDeepVisibility) else SDL_FIELDS
    events, skipped = parse_logging_rows(rows, fields)
    if skipped:
        logger.debug(f"{LOG_PREFIX} Skipped {skipped} unreadable Logging rows")
    return LoggingRows(events=events, skipped=skipped)


def parse_logging_rows(
    rows: list[Any], fields: dict[str, tuple[str, ...]]
) -> tuple[list[LoggingEvent], int]:
    """Turn the rows of a Logging search into events.

    A row needs a readable event time. A row without it is skipped and
    counted, so one bad row does not hide the others.

    Args:
        rows: The raw rows. An SDL row holds its fields under ``values``.
        fields: ``SDL_FIELDS`` or ``DV_FIELDS``.

    Returns:
        The events, and the number of skipped rows.

    """
    events: list[LoggingEvent] = []
    skipped = 0
    for row in rows:
        event = _parse_row(row, fields)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped


def _parse_row(row: Any, fields: dict[str, tuple[str, ...]]) -> LoggingEvent | None:
    """Build one event from a row, or None when the row cannot be read."""
    if not isinstance(row, dict):
        return None
    values = row.get("values") if isinstance(row.get("values"), dict) else row
    event_time = _parse_event_time(_first(values, fields["time"]))
    if event_time is None:
        return None
    return LoggingEvent(
        event_time=event_time,
        event_type=_text(_first(values, fields["type"])),
        endpoint_name=_text(_first(values, fields["endpoint"])),
        event_id=_text(_first(values, fields["id"])),
        tgt_process_name=_text(_first(values, fields["tgt_process"])),
        src_process_name=_text(_first(values, fields["src_process"])),
        src_parent_process_name=_text(_first(values, fields["src_parent_process"])),
        src_ip=_text(_first(values, fields["src_ip"])),
        dst_ip=_text(_first(values, fields["dst_ip"])),
    )


def _first(values: dict, names: tuple[str, ...]) -> Any:
    """Return the value of the first of these fields that is set."""
    for name in names:
        value = values.get(name)
        if value not in (None, ""):
            return value
    return None


def _text(value: Any) -> str | None:
    """Keep a value as text, or None when it is empty."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_event_time(value: Any) -> datetime | None:
    """Read an event time as a UTC datetime.

    SDL sends milliseconds since 1970 (a number, or a number in a string).
    Deep Visibility sends an ISO-8601 date.

    Args:
        value: The event time as found in the row.

    Returns:
        The time in UTC, or None if it cannot be read.

    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _from_milliseconds(value)
    text = str(value).strip()
    try:
        return _from_milliseconds(float(text))
    except ValueError:
        pass
    # datetime.fromisoformat reads at most 6 fraction digits (no nanoseconds).
    text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00"))
    try:
        date = datetime.fromisoformat(text)
    except ValueError:
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc)


def _from_milliseconds(milliseconds: float) -> datetime | None:
    """Turn milliseconds since 1970 into a UTC datetime."""
    try:
        return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)
    except OverflowError, OSError, ValueError:
        return None
