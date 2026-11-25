"""Tests for the Logging matcher: window, signals and ranking."""

from datetime import datetime, timedelta, timezone

from pyoaev.apis.inject_expectation_trace import TraceMatchType
from src.services.logging_fetch import LoggingEvent
from src.services.logging_matcher import Match, NoMatch, match_logging_events
from src.services.logging_query import LoggingQuery

START = datetime(2026, 11, 24, 8, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 24, 9, 0, 0, tzinfo=timezone.utc)
MARKER = "oaev-implant-1-agent-2"
SOURCE_IP = "10.66.30.12"
TARGET_IP = "2001:db8::5"


def _query(markers=(MARKER,), source_ips=(SOURCE_IP,), target_ips=(TARGET_IP,)):
    """Build a Logging query with a fixed window."""
    return LoggingQuery(
        filter="the-filter",
        markers=list(markers),
        source_ips=list(source_ips),
        target_ips=list(target_ips),
        start=START,
        end=END,
    )


def _event(minutes: int = 10, **fields) -> LoggingEvent:
    """Build an event a number of minutes after the window start."""
    return LoggingEvent(event_time=START + timedelta(minutes=minutes), **fields)


def test_marker_in_any_process_name_matches_in_any_case():
    """The implant can be the created process, the acting one or its parent."""
    for field in ("tgt_process_name", "src_process_name", "src_parent_process_name"):
        # Arrange
        event = _event(**{field: f"{MARKER.upper()}.exe"})

        # Act
        result = match_logging_events(_query(), [event])

        # Assert
        assert result == Match(TraceMatchType.MARKER, event)  # noqa: S101


def test_source_ip_on_either_side_of_the_connection_matches():
    """An IP is looked for in the source and the destination fields."""
    outgoing = _event(src_ip=SOURCE_IP, dst_ip="168.63.129.16")
    incoming = _event(src_ip="10.66.40.50", dst_ip=SOURCE_IP)

    assert match_logging_events(_query(), [outgoing]).match_type == (  # noqa: S101
        TraceMatchType.SOURCE_IP
    )
    assert match_logging_events(_query(), [incoming]).match_type == (  # noqa: S101
        TraceMatchType.SOURCE_IP
    )


def test_target_ip_is_compared_as_an_address_not_as_text():
    """Two spellings of the same IPv6 address are equal."""
    # Arrange
    event = _event(dst_ip="2001:DB8:0:0::5")

    # Act
    result = match_logging_events(_query(), [event])

    # Assert
    assert result == Match(TraceMatchType.TARGET_IP, event)  # noqa: S101


def test_a_longer_ip_does_not_match():
    """10.66.30.12 is not found in 10.66.30.120."""
    # Act
    result = match_logging_events(_query(), [_event(src_ip="10.66.30.120")])

    # Assert
    assert result == NoMatch()  # noqa: S101


def test_events_outside_the_window_are_ignored():
    """The window ends are inside it, one second out is not."""
    # Arrange
    before = LoggingEvent(event_time=START - timedelta(seconds=1), src_ip=SOURCE_IP)
    after = LoggingEvent(event_time=END + timedelta(seconds=1), src_ip=SOURCE_IP)
    on_end = LoggingEvent(event_time=END, src_ip=SOURCE_IP)

    # Act
    result = match_logging_events(_query(), [before, after, on_end])

    # Assert
    assert result == Match(TraceMatchType.SOURCE_IP, on_end)  # noqa: S101


def test_the_marker_wins_over_an_earlier_ip_match():
    """The strongest signal wins, even over an earlier event."""
    # Arrange
    ip_event = _event(minutes=1, src_ip=SOURCE_IP)
    marker_event = _event(minutes=30, src_process_name=f"{MARKER}.exe")
    target_event = _event(minutes=0, dst_ip=TARGET_IP)

    # Act
    result = match_logging_events(_query(), [target_event, ip_event, marker_event])

    # Assert
    assert result == Match(TraceMatchType.MARKER, marker_event)  # noqa: S101


def test_the_earliest_event_wins_for_the_same_signal():
    """Among events with the same signal, the earliest one is chosen."""
    # Arrange
    later = _event(minutes=20, tgt_process_name=MARKER)
    earlier = _event(minutes=5, tgt_process_name=MARKER)

    # Act
    result = match_logging_events(_query(), [later, earlier])

    # Assert
    assert result == Match(TraceMatchType.MARKER, earlier)  # noqa: S101


def test_events_without_any_signal_give_no_match():
    """Unrelated events and invalid IPs never match."""
    # Arrange
    events = [
        _event(src_process_name="WaAppAgent.exe", src_ip="not-an-ip"),
        _event(),
    ]

    # Act
    result = match_logging_events(_query(), events)

    # Assert
    assert result == NoMatch()  # noqa: S101


def test_no_events_give_no_match():
    """An empty list is no match."""
    assert match_logging_events(_query(), []) == NoMatch()  # noqa: S101
