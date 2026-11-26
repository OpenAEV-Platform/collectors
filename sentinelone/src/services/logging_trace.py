"""SentinelOne Logging trace builder.

This module turns a Logging match into the expectation trace sent to
OpenAEV. The trace says which signal matched, when the event happened, on
which machine, and how to open the Logging search in the SentinelOne console.
It never carries raw event content.
"""

import logging
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

from ..collector.models import ExpectationTrace
from .exception import SentinelOneDataConversionError
from .logging_matcher import Match
from .logging_query import LoggingQuery

LOG_PREFIX = "[SentinelOneLoggingTrace]"

# Console page of Event Search (SDL). Deep Visibility consoles have no such
# page, so their traces link to the console root.
EVENT_SEARCH_PATH = "/events/search"


def build_logging_trace(
    match: Match,
    query: LoggingQuery,
    expectation_id: str,
    collector_id: str,
    base_url: str,
    self_hosted: bool,
) -> ExpectationTrace:
    """Build the trace of a matched LOGGING expectation.

    Args:
        match: The matched signal and event.
        query: The Logging search that returned the event.
        expectation_id: ID of the LOGGING expectation.
        collector_id: ID of the collector.
        base_url: SentinelOne console URL.
        self_hosted: True on a Deep Visibility (self-hosted) console.

    Returns:
        The trace: event type and machine, link to the search, event time in
        UTC and match type.

    Raises:
        SentinelOneDataConversionError: If the trace cannot be built (e.g.
            empty ID or console URL).

    """
    event = match.event
    try:
        trace = ExpectationTrace(
            inject_expectation_trace_expectation=expectation_id,
            inject_expectation_trace_source_id=collector_id,
            inject_expectation_trace_alert_name=(
                f"SentinelOne event: {event.event_type or 'unknown type'} "
                f"on {event.endpoint_name or 'unknown machine'}"
            ),
            inject_expectation_trace_alert_link=_search_link(
                base_url, query, self_hosted
            ),
            inject_expectation_trace_date=_utc_date(event.event_time),
            inject_expectation_trace_match_type=match.match_type,
        )
    # ValueError covers the model checks (e.g. an empty ID or link).
    except ValueError as e:
        raise SentinelOneDataConversionError(
            f"Error creating Logging trace for expectation {expectation_id}: {e}"
        ) from e

    logging.getLogger(__name__).debug(
        f"{LOG_PREFIX} Created Logging trace for expectation {expectation_id}: "
        f"{match.match_type.value} at {trace.inject_expectation_trace_date}"
    )
    return trace


def _search_link(base_url: str, query: LoggingQuery, self_hosted: bool) -> str:
    """Build the console link that opens the Logging search.

    Args:
        base_url: SentinelOne console URL.
        query: The Logging search.
        self_hosted: True on a Deep Visibility (self-hosted) console.

    Returns:
        The Event Search link with the filter and the inject window, or the
        console root on a self-hosted console. Empty when there is no URL.

    """
    console = (base_url or "").strip().rstrip("/")
    if not console or self_hosted:
        return console
    params = {
        "_categoryId": "eventSearch",
        # Event times are in milliseconds, like the window here.
        "startTime": int(query.start.timestamp() * 1000),
        "endTime": int(query.end.timestamp() * 1000),
        "gettingStarted": "false",
        "filter": query.filter,
    }
    return f"{console}{EVENT_SEARCH_PATH}?{urlencode(params, quote_via=quote)}"


def _utc_date(event_time: datetime) -> str:
    """Format an event time for the platform.

    Args:
        event_time: Event time.

    Returns:
        The time in UTC, ISO-8601 with a ``Z`` suffix, to the second (the
        platform stores the trace date without fractions).

    """
    return event_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
