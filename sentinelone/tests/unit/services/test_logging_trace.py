"""Tests for the Logging trace builder and the trace payload."""

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
from pyoaev.apis.inject_expectation_trace import TraceMatchType
from src.services.exception import SentinelOneDataConversionError
from src.services.logging_fetch import LoggingEvent
from src.services.logging_matcher import Match
from src.services.logging_query import LoggingQuery
from src.services.logging_trace import build_logging_trace

START = datetime(2026, 11, 24, 8, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 24, 9, 0, 1, tzinfo=timezone.utc)
FILTER = "dataSource.name='SentinelOne' (src.process.name contains:anycase 'oaev')"
CONSOLE = "https://usea1-partners.sentinelone.net/"


def _query() -> LoggingQuery:
    """Build a Logging query with a fixed window."""
    return LoggingQuery(
        filter=FILTER, markers=[], source_ips=[], target_ips=[], start=START, end=END
    )


def _match(**fields) -> Match:
    """Build a marker match on an event at 08:30:15.900."""
    event = LoggingEvent(
        event_time=datetime(2026, 11, 24, 8, 30, 15, 900000, tzinfo=timezone.utc),
        **fields,
    )
    return Match(TraceMatchType.MARKER, event)


def _build(match: Match, base_url: str = CONSOLE, self_hosted: bool = False):
    """Build the trace of a match with fixed IDs."""
    return build_logging_trace(
        match, _query(), "expectation-1", "collector-1", base_url, self_hosted
    )


def test_trace_names_the_event_and_keeps_the_match_type():
    """The trace says what happened, where, when, and which signal matched."""
    # Act
    trace = _build(_match(event_type="Process Creation", endpoint_name="meereen"))

    # Assert
    assert trace.inject_expectation_trace_alert_name == (  # noqa: S101
        "SentinelOne event: Process Creation on meereen"
    )
    assert trace.inject_expectation_trace_date == "2026-11-24T08:30:15Z"  # noqa: S101
    assert trace.inject_expectation_trace_match_type == (  # noqa: S101
        TraceMatchType.MARKER
    )
    assert trace.inject_expectation_trace_expectation == "expectation-1"  # noqa: S101
    assert trace.inject_expectation_trace_source_id == "collector-1"  # noqa: S101


def test_trace_name_without_type_or_machine():
    """Missing event fields still give a readable name."""
    trace = _build(_match())

    assert trace.inject_expectation_trace_alert_name == (  # noqa: S101
        "SentinelOne event: unknown type on unknown machine"
    )


def test_sdl_link_opens_event_search_on_the_inject_window():
    """The link carries the Logging filter and the window in milliseconds."""
    # Act
    link = _build(_match()).inject_expectation_trace_alert_link

    # Assert
    parts = urlsplit(link)
    params = parse_qs(parts.query)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == (  # noqa: S101
        "https://usea1-partners.sentinelone.net/events/search"
    )
    assert params["_categoryId"] == ["eventSearch"]  # noqa: S101
    assert params["filter"] == [FILTER]  # noqa: S101
    assert params["startTime"] == [str(int(START.timestamp() * 1000))]  # noqa: S101
    assert params["endTime"] == [str(int(END.timestamp() * 1000))]  # noqa: S101
    assert " " not in link  # noqa: S101


def test_self_hosted_link_is_the_console_root():
    """Deep Visibility consoles have no Event Search page."""
    link = _build(_match(), self_hosted=True).inject_expectation_trace_alert_link

    assert link == "https://usea1-partners.sentinelone.net"  # noqa: S101


def test_missing_console_url_is_a_conversion_error():
    """A trace needs a link: an empty console URL cannot give one."""
    with pytest.raises(SentinelOneDataConversionError):
        _build(_match(), base_url="")


def test_payload_sends_the_match_type_value_only_when_set():
    """Logging traces send "marker"; other traces keep their payload."""
    # Arrange
    logging_trace = _build(_match())
    other_trace = logging_trace.model_copy(
        update={"inject_expectation_trace_match_type": None}
    )

    # Act
    logging_payload = logging_trace.to_api_dict()
    other_payload = other_trace.to_api_dict()

    # Assert
    assert logging_payload["inject_expectation_trace_match_type"] == (  # noqa: S101
        "marker"
    )
    assert "inject_expectation_trace_match_type" not in other_payload  # noqa: S101
