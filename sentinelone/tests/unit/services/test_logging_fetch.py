"""Tests for the Logging event search: fetchers and typed results."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
from src.services.exception import SentinelOneAPIError, SentinelOneNetworkError
from src.services.fetcher_deep_visibility import FetcherDeepVisibility
from src.services.fetcher_sdl import FetcherSDL
from src.services.logging_fetch import (
    LoggingApiError,
    LoggingAuthError,
    LoggingEmpty,
    LoggingEvent,
    LoggingMalformed,
    LoggingRows,
    fetch_logging_events,
)
from src.services.logging_query import LoggingQuery

START = datetime(2026, 11, 24, 8, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 24, 9, 0, 0, tzinfo=timezone.utc)
MARKER = "oaev-implant-1-agent-2.exe"


def _query(search_filter: str = "the-filter") -> LoggingQuery:
    """Build a Logging query with a fixed window."""
    return LoggingQuery(
        filter=search_filter,
        markers=[MARKER],
        source_ips=[],
        target_ips=[],
        start=START,
        end=END,
    )


def _fetcher(kind: type, rows=None, error: Exception | None = None) -> Mock:
    """Build a fake fetcher of this kind returning rows or raising an error."""
    fetcher = Mock(spec=kind)
    fetcher.LOGGING_FIELDS = kind.LOGGING_FIELDS
    if error is not None:
        fetcher.fetch_rows.side_effect = error
    else:
        fetcher.fetch_rows.return_value = rows or []
    return fetcher


def _response(status_code: int, body=None) -> Mock:
    """Build a fake HTTP response."""
    response = Mock()
    response.status_code = status_code
    response.headers = {}
    response.json.return_value = body if body is not None else {}
    response.text = str(body)
    return response


def _client() -> Mock:
    """Build a fake SentinelOne client with a fake HTTP session."""
    client = Mock()
    client.base_url = "https://s1.example.com"
    client.api_key = "fake-api-key"
    client.time_window = timedelta(hours=1)
    client.session = Mock()
    return client


# -- Typed results --


def test_sdl_rows_become_events():
    """SDL rows use dotted names, with the time in milliseconds."""
    # Arrange
    rows = [
        {
            "event.time": 1795507200500,
            "event.type": "Process Creation",
            "endpoint.name": "meereen",
            "event.id": "e1",
            "tgt.process.name": MARKER,
            "src.process.name": "agent.exe",
            "src.process.parent.name": "services.exe",
            "src.ip.address": "10.66.30.12",
            "dst.ip.address": "10.66.40.50",
        }
    ]
    fetcher = _fetcher(FetcherSDL, rows)

    # Act
    result = fetch_logging_events(fetcher, _query())

    # Assert
    assert result == LoggingRows(  # noqa: S101
        events=[
            LoggingEvent(
                event_time=datetime(2026, 11, 24, 8, 0, 0, 500000, tzinfo=timezone.utc),
                event_type="Process Creation",
                endpoint_name="meereen",
                event_id="e1",
                tgt_process_name=MARKER,
                src_process_name="agent.exe",
                src_parent_process_name="services.exe",
                src_ip="10.66.30.12",
                dst_ip="10.66.40.50",
            )
        ]
    )
    fetcher.fetch_rows.assert_called_once_with("the-filter", START, END)


def test_deep_visibility_events_are_read_with_their_own_names():
    """Deep Visibility events use camelCase names and an ISO date."""
    # Arrange
    rows = [
        {
            "createdAt": "2026-11-24T08:30:00.123456789Z",
            "eventType": "IP Connect",
            "agentName": "meereen",
            "id": "e2",
            "processName": MARKER,
            "parentProcessName": "agent.exe",
            "srcIp": "10.66.30.12",
            "dstIp": "10.66.40.50",
        }
    ]

    # Act
    result = fetch_logging_events(_fetcher(FetcherDeepVisibility, rows), _query())

    # Assert
    (event,) = result.events
    assert event.event_time == datetime(  # noqa: S101
        2026, 11, 24, 8, 30, 0, 123456, tzinfo=timezone.utc
    )
    assert event.event_type == "IP Connect"  # noqa: S101
    assert event.endpoint_name == "meereen"  # noqa: S101
    assert event.src_process_name == MARKER  # noqa: S101
    assert event.src_parent_process_name == "agent.exe"  # noqa: S101
    assert (event.src_ip, event.dst_ip) == ("10.66.30.12", "10.66.40.50")  # noqa: S101


def test_rows_without_a_readable_time_are_skipped_and_counted():
    """One bad row does not hide the others."""
    # Arrange
    rows = [
        {"event.time": "1795507200000", "event.type": "File Creation"},
        {"event.type": "no time"},
        {"event.time": "soon"},
        None,
    ]

    # Act
    result = fetch_logging_events(_fetcher(FetcherSDL, rows), _query())

    # Assert
    assert [event.event_type for event in result.events] == [  # noqa: S101
        "File Creation"
    ]
    assert result.skipped == 3  # noqa: S101


@pytest.mark.parametrize(
    ("event_time", "microsecond"),
    [(1795371220662, 662000), ("1795371220662", 662000), ("1795371220662.5", 662500)],
)
def test_millisecond_times_are_read_exactly(event_time, microsecond):
    """Milliseconds are read with no float rounding, as a number or a string."""
    # Act
    result = fetch_logging_events(
        _fetcher(FetcherSDL, [{"event.time": event_time}]), _query()
    )

    # Assert
    (event,) = result.events
    assert event.event_time == datetime(  # noqa: S101
        2026, 11, 22, 18, 13, 40, microsecond, tzinfo=timezone.utc
    )


def test_only_unreadable_rows_are_malformed():
    """Rows came back but none could be read: an error, not "no event"."""
    # Act
    result = fetch_logging_events(
        _fetcher(FetcherSDL, [{"event.type": "no time"}, None]), _query()
    )

    # Assert
    assert result == LoggingMalformed(  # noqa: S101
        message="None of the 2 rows could be read"
    )


def test_no_row_is_empty():
    """The search ran and found nothing."""
    # Act
    result = fetch_logging_events(_fetcher(FetcherSDL, []), _query())

    # Assert
    assert result == LoggingEmpty()  # noqa: S101


@pytest.mark.parametrize("status_code", [401, 403])
def test_refused_token_is_an_auth_error(status_code):
    """A refused token or permission stops Logging: retrying cannot help."""
    # Arrange
    error = SentinelOneAPIError("refused", status_code=status_code)

    # Act
    result = fetch_logging_events(_fetcher(FetcherSDL, error=error), _query())

    # Assert
    assert result == LoggingAuthError(  # noqa: S101
        status_code=status_code, message="refused"
    )


@pytest.mark.parametrize("status_code", [429, 500, None])
def test_other_api_errors_keep_their_status(status_code):
    """A rate limit, a server error or no status may go away: try again later."""
    # Arrange
    error = SentinelOneAPIError("failed", status_code=status_code)

    # Act
    result = fetch_logging_events(_fetcher(FetcherSDL, error=error), _query())

    # Assert
    assert result == LoggingApiError(  # noqa: S101
        message="failed", status_code=status_code
    )


def test_network_error_is_an_api_error_without_status():
    """No HTTP answer: an error to retry, never "no event"."""
    # Act
    result = fetch_logging_events(
        _fetcher(FetcherDeepVisibility, error=SentinelOneNetworkError("down")),
        _query(),
    )

    # Assert
    assert result == LoggingApiError(message="down", status_code=None)  # noqa: S101


# -- SDL fetcher --


def test_sdl_fetch_rows_sends_the_logging_filter_and_window():
    """The Logging filter and window are sent as given, rows come back flat."""
    # Arrange
    client = _client()
    row = {"cursor": "c1", "values": {"event.time": 1}}
    client.session.post.return_value = _response(200, {"id": "q1"})
    client.session.get.return_value = _response(
        200,
        {
            "stepsCompleted": 1,
            "stepsTotal": 1,
            "data": {"estimatedMatchCount": 1, "matches": [row]},
        },
    )

    # Act
    rows = FetcherSDL(client).fetch_rows("my filter", START, END)

    # Assert
    assert rows == [row["values"]]  # noqa: S101
    body = client.session.post.call_args.kwargs["json"]
    assert body["log"]["filter"] == "my filter"  # noqa: S101
    assert body["startTime"] == "2026-11-24T08:00:00Z"  # noqa: S101
    assert body["endTime"] == "2026-11-24T09:00:00Z"  # noqa: S101


@pytest.mark.parametrize("status_code", [400, 401, 403, 500])
def test_sdl_launch_error_carries_its_status(status_code):
    """The HTTP status is kept on the error, not only in its message."""
    # Arrange
    client = _client()
    client.session.post.return_value = _response(status_code, {"message": "no"})

    # Act / Assert
    with pytest.raises(SentinelOneAPIError) as error:
        FetcherSDL(client).fetch_rows("f", START, END)
    assert error.value.status_code == status_code  # noqa: S101


def test_sdl_exhausted_rate_limit_carries_429():
    """After the existing retries, the rate limit error says 429."""
    # Arrange
    client = _client()
    client.session.post.return_value = _response(429)

    # Act / Assert
    with patch("time.sleep"), pytest.raises(SentinelOneAPIError) as error:
        FetcherSDL(client).fetch_rows("f", START, END)
    assert error.value.status_code == 429  # noqa: S101


def test_sdl_expired_query_carries_404():
    """An expired query keeps its 404."""
    # Arrange
    client = _client()
    client.session.post.return_value = _response(200, {"id": "q1"})
    client.session.get.return_value = _response(404, {"message": "gone"})

    # Act / Assert
    with pytest.raises(SentinelOneAPIError) as error:
        FetcherSDL(client).fetch_rows("f", START, END)
    assert error.value.status_code == 404  # noqa: S101


# -- Deep Visibility fetcher --


def test_deep_visibility_fetch_rows_runs_the_logging_query():
    """The query is started, waited for, then its events are read."""
    # Arrange
    client = _client()
    event = {"createdAt": "2026-11-24T08:30:00Z"}
    client.session.post.return_value = _response(200, {"data": {"queryId": "q1"}})
    client.session.get.side_effect = [
        _response(200, {"data": {"responseState": "FINISHED", "progressStatus": 100}}),
        _response(200, {"data": [event]}),
    ]

    # Act
    rows = FetcherDeepVisibility(client).fetch_rows('SrcIP In ("1")', START, END)

    # Assert
    assert rows == [event]  # noqa: S101
    body = client.session.post.call_args.kwargs["json"]
    assert body == {  # noqa: S101
        "query": 'SrcIP In ("1")',
        "fromDate": "2026-11-24T08:00:00Z",
        "toDate": "2026-11-24T09:00:00Z",
    }


@pytest.mark.parametrize("step", ["init", "status", "events"])
def test_deep_visibility_errors_carry_their_status(step):
    """Each Deep Visibility call keeps the HTTP status on its error."""
    # Arrange
    client = _client()
    refused = _response(403, {"errors": [{"code": 4030010, "title": "Forbidden"}]})
    client.session.post.return_value = (
        refused if step == "init" else _response(200, {"data": {"queryId": "q1"}})
    )
    finished = _response(
        200, {"data": {"responseState": "FINISHED", "progressStatus": 100}}
    )
    client.session.get.side_effect = (
        [refused] if step == "status" else [finished, refused]
    )

    # Act / Assert
    with pytest.raises(SentinelOneAPIError) as error:
        FetcherDeepVisibility(client).fetch_rows("q", START, END)
    assert error.value.status_code == 403  # noqa: S101


def test_deep_visibility_init_without_query_id_is_an_error():
    """A 200 answer without a query id cannot be followed."""
    # Arrange
    client = _client()
    client.session.post.return_value = _response(200, {"data": {}})

    # Act / Assert
    with pytest.raises(SentinelOneAPIError, match="missing queryId"):
        FetcherDeepVisibility(client).fetch_rows("q", START, END)
