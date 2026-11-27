"""SentinelOne Logging search filter.

This module holds the raw-event search built for one LOGGING expectation, or
the reason why no search can be built for it. ``build_logging_query`` builds
it from the expectation's signatures. The fetcher runs the filter inside the
window, and the matcher uses the marker and the IPs to pick the event.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Iterable, Mapping

from pyoaev.signatures.types import SignatureTypes

from .fetcher_sdl import S1QL_BASE_FILTER
from .utils.dates import read_iso_date
from .utils.s1ql import dv_list, dv_string, s1ql_list, s1ql_string

# Fields that can hold the implant's name: the process itself, the process that
# started an event (e.g. a child or a network connection), or its parent.
SDL_MARKER_FIELDS = ("tgt.process.name", "src.process.name", "src.process.parent.name")
SDL_IP_FIELDS = ("src.ip.address", "dst.ip.address")
# The same fields in Deep Visibility (S1QL 1.0). Not checked on a self-hosted
# console yet: the collector only used tgtFileSha1 before.
DV_MARKER_FIELDS = ("TgtProcName", "SrcProcName", "SrcProcParentName")
DV_IP_FIELDS = ("SrcIP", "DstIP")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class LoggingQuery:
    """Raw-event search for one LOGGING expectation.

    Attributes:
        filter: The S1QL filter: 2.0 for SDL (SaaS), 1.0 for Deep Visibility
            (self-hosted). The time window is not in it: the fetcher sends it
            next to the filter.
        markers: Parent process name signature values. Empty when the
            expectation has no marker.
        source_ips: Source IPv4 and IPv6 signature values.
        target_ips: Target IPv4 and IPv6 signature values.
        start: Start of the search, UTC: the inject start rounded down to the
            second, as SentinelOne searches whole seconds.
        end: End of the search, UTC: the inject end rounded up to the second.
        inject_start: Exact start of the inject, UTC, to the microsecond. The
            matcher only accepts events from here, not from ``start``.
        inject_end: Exact end of the inject, UTC, to the microsecond.

    """

    filter: str
    markers: list[str]
    source_ips: list[str]
    target_ips: list[str]
    start: datetime
    end: datetime
    inject_start: datetime
    inject_end: datetime


@dataclass(frozen=True)
class Unqueryable:
    """No Logging search can be built for an expectation.

    Attributes:
        reason: Why the expectation cannot be searched (e.g. no end date,
            no marker and no IP).

    """

    reason: str


def build_logging_query(
    signatures: Iterable[Mapping[str, str]], self_hosted: bool
) -> LoggingQuery | Unqueryable:
    """Build the raw-event search of one LOGGING expectation.

    The search looks for events whose process names contain the marker OR
    whose source or destination IP is one of the expectation's IPs. Each IP is
    looked for in both IP fields: the matcher then tells a source IP match from
    a target IP match by the signature the IP came from.

    Args:
        signatures: The expectation's signatures, as ``{"type", "value"}``
            mappings.
        self_hosted: True to build an S1QL 1.0 filter for Deep Visibility,
            False to build an S1QL 2.0 filter for SDL.

    Returns:
        The search, or ``Unqueryable`` when the expectation has no end date,
        no valid window, or neither a marker nor an IP.

    """
    by_type: dict[str, list[str]] = {}
    for signature in signatures:
        value = str(signature.get("value") or "").strip()
        if value:
            by_type.setdefault(str(signature.get("type")), []).append(value)

    end_dates = by_type.get(SignatureTypes.SIG_TYPE_END_DATE.value, [])
    if not end_dates:
        return Unqueryable("no end_date")
    start_dates = by_type.get(SignatureTypes.SIG_TYPE_START_DATE.value, [])
    if not start_dates:
        return Unqueryable("no start_date")
    start = _parse_instant(start_dates[0])
    end = _parse_instant(end_dates[0])
    if start is None or end is None:
        return Unqueryable("start_date or end_date is not a valid date")
    # Compare the exact instants: rounding first could hide a reversed window
    # that fits inside one second.
    if start > end:
        return Unqueryable("start_date is after end_date")

    markers = _unique(
        by_type.get(SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME.value, [])
    )
    source_ips = _unique(
        by_type.get(SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS.value, [])
        + by_type.get(SignatureTypes.SIG_TYPE_SOURCE_IPV6_ADDRESS.value, [])
    )
    target_ips = _unique(
        by_type.get(SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS.value, [])
        + by_type.get(SignatureTypes.SIG_TYPE_TARGET_IPV6_ADDRESS.value, [])
    )
    if not markers and not source_ips and not target_ips:
        # Never search without a signal: it would match every event.
        return Unqueryable("no marker and no IP")

    ips = _unique([*source_ips, *target_ips])
    if self_hosted:
        search_filter = _dv_filter(markers, ips)
    else:
        search_filter = _sdl_filter(markers, ips)
    return LoggingQuery(
        filter=search_filter,
        markers=markers,
        source_ips=source_ips,
        target_ips=target_ips,
        # Round the search outwards: it can only grow by under a second, never
        # lose the end of the inject.
        start=_to_second(start, round_up=False),
        end=_to_second(end, round_up=True),
        # The exact window, kept apart so that the extra part of the search
        # is never taken as evidence.
        inject_start=_to_microsecond(start),
        inject_end=_to_microsecond(end),
    )


def _sdl_filter(markers: list[str], ips: list[str]) -> str:
    """Write the S1QL 2.0 filter, limited to SentinelOne agent events."""
    conditions = [
        f"{field} contains:anycase {s1ql_string(marker)}"
        for marker in markers
        for field in SDL_MARKER_FIELDS
    ]
    if ips:
        conditions += [f"{field} in ({s1ql_list(ips)})" for field in SDL_IP_FIELDS]
    return f"{S1QL_BASE_FILTER} ({' or '.join(conditions)})"


def _dv_filter(markers: list[str], ips: list[str]) -> str:
    """Write the S1QL 1.0 filter. Deep Visibility holds agent events only."""
    conditions = [
        f"{field} ContainsCIS {dv_string(marker)}"
        for marker in markers
        for field in DV_MARKER_FIELDS
    ]
    if ips:
        conditions += [f"{field} In ({dv_list(ips)})" for field in DV_IP_FIELDS]
    return " OR ".join(conditions)


def _parse_instant(value: str) -> Decimal | None:
    """Read an ISO-8601 signature date as exact Unix seconds.

    Args:
        value: The date, e.g. ``2026-11-24T08:00:00.123456789Z``. A date
            without a time zone is read as UTC.

    Returns:
        The seconds since 1970-01-01 UTC, fraction included, or None if the
        date cannot be read.

    """
    date = read_iso_date(value)
    if date is None:
        return None
    whole_seconds, fraction = date
    # Decimal keeps every fraction digit, so two close dates are never seen as
    # equal.
    return Decimal(int(whole_seconds.timestamp())) + Decimal(f"0.{fraction or 0}")


def _to_second(instant: Decimal, round_up: bool) -> datetime:
    """Round an instant to the second, as a UTC datetime.

    Args:
        instant: Exact Unix seconds, as read by ``_parse_instant``.
        round_up: True to round up (window end), False to round down (window
            start).

    Returns:
        The rounded instant in UTC.

    """
    seconds = math.ceil(instant) if round_up else math.floor(instant)
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _to_microsecond(instant: Decimal) -> datetime:
    """Turn an exact instant into a UTC datetime, to the microsecond.

    A datetime holds microseconds, so the digits after them are dropped. Event
    times are cut the same way, so an event inside the window stays inside.

    Args:
        instant: Exact Unix seconds, as read by ``_parse_instant``.

    Returns:
        The instant in UTC.

    """
    return EPOCH + timedelta(microseconds=math.floor(instant * 1_000_000))


def _unique(values: Iterable[str]) -> list[str]:
    """Drop duplicates, keeping the first occurrence order."""
    return list(dict.fromkeys(values))
