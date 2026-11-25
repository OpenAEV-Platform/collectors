"""SentinelOne Logging matcher.

This module decides whether the events returned by the Logging search record
an inject: one event inside the inject window whose process names contain the
inject marker, or whose source or destination IP is one of the inject IPs, is
enough.
"""

import ipaddress
import logging
from dataclasses import dataclass
from typing import Sequence

from pyoaev.apis.inject_expectation_trace import (  # type: ignore[import-untyped]
    TraceMatchType,
)

from .logging_fetch import LoggingEvent
from .logging_query import LoggingQuery

LOG_PREFIX = "[SentinelOneLoggingMatcher]"

# Strongest signal first: the marker identifies the inject itself, while an
# IP only identifies a host, which also logs its own unrelated traffic.
MATCH_TYPE_PRIORITY: tuple[TraceMatchType, ...] = (
    TraceMatchType.MARKER,
    TraceMatchType.SOURCE_IP,
    TraceMatchType.TARGET_IP,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Match:
    """An event of the inject window records the inject.

    Attributes:
        match_type: Strongest signal found in the event.
        event: The chosen event.

    """

    match_type: TraceMatchType
    event: LoggingEvent


@dataclass(frozen=True)
class NoMatch:
    """No event of the inject window contains any signal of the search."""


LoggingMatchResult = Match | NoMatch


def match_logging_events(
    query: LoggingQuery, events: Sequence[LoggingEvent]
) -> LoggingMatchResult:
    """Find the event that best records the inject.

    SentinelOne already filtered the events, but the check is done again here:
    to know which signal matched, and to keep only events inside the exact
    window and with an exact IP.

    When several events match, the strongest signal wins (marker, then source
    IP, then target IP), even over an earlier event. Among events with the
    same signal, the earliest one is chosen.

    Args:
        query: The Logging search of the expectation.
        events: Events returned by the Logging search.

    Returns:
        ``Match`` with the strongest signal and its event, or ``NoMatch`` when
        no event of the window contains a signal.

    """
    markers = [marker.casefold() for marker in query.markers]
    source_ips = _parse_ips(query.source_ips)
    target_ips = _parse_ips(query.target_ips)

    best: Match | None = None
    outside_window = 0
    for event in events:
        if not query.start <= event.event_time <= query.end:
            outside_window += 1
            continue
        match_type = _strongest_signal(event, markers, source_ips, target_ips)
        if match_type is None:
            continue
        candidate = Match(match_type=match_type, event=event)
        if best is None or _rank(candidate) < _rank(best):
            best = candidate

    logger.debug(
        f"{LOG_PREFIX} Checked {len(events)} events "
        f"({outside_window} outside the window): "
        f"{best.match_type.value if best else 'no match'}"
    )
    return best or NoMatch()


def _strongest_signal(
    event: LoggingEvent,
    markers: list[str],
    source_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
    target_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> TraceMatchType | None:
    """Return the strongest signal found in one event.

    Args:
        event: The event to check.
        markers: The lowercase markers.
        source_ips: The source IPs of the expectation.
        target_ips: The target IPs of the expectation.

    Returns:
        The strongest match type found, or None.

    """
    process_names = [
        name.casefold()
        for name in (
            event.tgt_process_name,
            event.src_process_name,
            event.src_parent_process_name,
        )
        if name
    ]
    if any(marker in name for marker in markers for name in process_names):
        return TraceMatchType.MARKER

    # An IP can be on either side of a connection, like in the search filter.
    event_ips = _parse_ips([event.src_ip, event.dst_ip])
    if event_ips & source_ips:
        return TraceMatchType.SOURCE_IP
    if event_ips & target_ips:
        return TraceMatchType.TARGET_IP
    return None


def _parse_ips(
    values: Sequence[str | None],
) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Read IP addresses, dropping empty and invalid values.

    Comparing parsed addresses, not text, makes two spellings of the same
    IPv6 address equal (e.g. ``2001:DB8::1`` and ``2001:db8:0::1``).

    Args:
        values: IP addresses as text.

    Returns:
        The valid addresses.

    """
    ips = set()
    for value in values:
        try:
            ips.add(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            continue
    return ips


def _rank(match: Match) -> tuple[int, float]:
    """Order matches: strongest signal first, then earliest event.

    Args:
        match: A candidate match.

    Returns:
        Sort key, lower is better.

    """
    return (
        MATCH_TYPE_PRIORITY.index(match.match_type),
        match.event.event_time.timestamp(),
    )
