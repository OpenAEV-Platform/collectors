"""Tests for the Splunk ES Logging fetch."""

from unittest.mock import Mock, patch

import pytest
from requests.exceptions import ConnectionError, Timeout
from src.services.client_api import SplunkESClientAPI
from src.services.logging_fetch import (
    LoggingApiError,
    LoggingAuthError,
    LoggingEmpty,
    LoggingMalformed,
    LoggingRows,
)
from src.services.logging_query import LoggingQuery
from src.services.models import LoggingEvent
from tests.services.fixtures.factories import create_test_config

QUERY = LoggingQuery(
    spl='search index IN (sysmon) earliest=1 latest=3 ("10.0.0.1")',
    marker_values=[],
    source_ips=["10.0.0.1"],
    target_ips=[],
    earliest=1,
    latest=2,
)

SYSMON_ROW = {
    "oaev_event_epoch": "1793714702.000",
    "index": "sysmon",
    "host": "WIN-LAB01",
    "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "_raw": "<Event>... ParentImage C:\\oaev-implant-x.exe ...</Event>",
}


def _response(status_code: int = 200, json_data=None, text: str = "") -> Mock:
    """Build a mocked HTTP response."""
    response = Mock()
    response.status_code = status_code
    response.text = text
    if isinstance(json_data, Exception):
        response.json.side_effect = json_data
    else:
        response.json.return_value = json_data
    return response


@pytest.fixture
def client() -> SplunkESClientAPI:
    """Build a client with a row cap of 25."""
    config = create_test_config()
    config.splunk_es.logging_max_rows = 25
    return SplunkESClientAPI(config=config)


@patch("time.sleep")
@patch("requests.Session.post")
def test_rows_become_events(mock_post, mock_sleep, client):
    """Rows are returned as events, with one search and no sleep."""
    # Arrange
    mock_post.return_value = _response(json_data={"results": [SYSMON_ROW]})

    # Act
    result = client.fetch_logging_events(QUERY)

    # Assert
    assert result == LoggingRows(  # noqa: S101
        events=[
            LoggingEvent(
                event_epoch=1793714702.0,
                index="sysmon",
                host="WIN-LAB01",
                sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                raw=SYSMON_ROW["_raw"],
            )
        ]
    )
    mock_post.assert_called_once()
    mock_sleep.assert_not_called()


@patch("requests.Session.post")
def test_request_uses_the_query_and_the_row_cap(mock_post, client):
    """The search is sent as is, oneshot, in JSON, capped at the row limit."""
    # Arrange
    mock_post.return_value = _response(json_data={"results": []})

    # Act
    client.fetch_logging_events(QUERY)

    # Assert
    url = mock_post.call_args.args[0]
    params = mock_post.call_args.kwargs["data"]
    assert url.endswith("/services/search/jobs")  # noqa: S101
    assert params == {  # noqa: S101
        "search": QUERY.spl,
        "exec_mode": "oneshot",
        "output_mode": "json",
        "count": "25",
    }


@patch("requests.Session.post")
def test_no_results_is_empty(mock_post, client):
    """A search without results is Empty."""
    # Arrange
    mock_post.return_value = _response(json_data={"results": []})

    # Act / Assert
    assert client.fetch_logging_events(QUERY) == LoggingEmpty()  # noqa: S101


@pytest.mark.parametrize("status_code", [401, 403])
@patch("requests.Session.post")
def test_auth_errors(mock_post, client, status_code):
    """401 and 403 are an AuthError, never Empty."""
    # Arrange
    mock_post.return_value = _response(status_code, text="Unauthorized")

    # Act
    result = client.fetch_logging_events(QUERY)

    # Assert
    assert isinstance(result, LoggingAuthError)  # noqa: S101
    assert result.status_code == status_code  # noqa: S101


@pytest.mark.parametrize("status_code", [400, 500, 503])
@patch("requests.Session.post")
def test_other_http_errors(mock_post, client, status_code):
    """Other HTTP errors are an ApiError with a short message."""
    # Arrange
    mock_post.return_value = _response(status_code, text="x" * 1000)

    # Act
    result = client.fetch_logging_events(QUERY)

    # Assert
    assert isinstance(result, LoggingApiError)  # noqa: S101
    assert result.status_code == status_code  # noqa: S101
    assert len(result.message) <= 203  # noqa: S101


@pytest.mark.parametrize(
    "error",
    [Timeout("timed out"), ConnectionError("refused")],
    ids=["timeout", "network"],
)
@patch("requests.Session.post")
def test_request_failures_are_api_errors(mock_post, client, error):
    """A timeout or a network error is an ApiError, not an exception."""
    # Arrange
    mock_post.side_effect = error

    # Act
    result = client.fetch_logging_events(QUERY)

    # Assert
    assert isinstance(result, LoggingApiError)  # noqa: S101
    assert result.status_code is None  # noqa: S101


@pytest.mark.parametrize(
    "json_data",
    [
        ValueError("Expecting value"),
        ["not", "a", "dict"],
        {"messages": []},
        {"results": "nope"},
        {"results": [{"index": "sysmon"}, "garbage"]},
    ],
    ids=["not-json", "list", "no-results", "results-not-list", "no-readable-row"],
)
@patch("requests.Session.post")
def test_malformed_answers(mock_post, client, json_data):
    """An answer that is not the expected JSON is Malformed, never Empty."""
    # Arrange
    mock_post.return_value = _response(json_data=json_data)

    # Act / Assert
    assert isinstance(  # noqa: S101
        client.fetch_logging_events(QUERY), LoggingMalformed
    )


@patch("requests.Session.post")
def test_malformed_rows_are_skipped_and_counted(mock_post, client):
    """Bad rows are skipped, the good ones are kept."""
    # Arrange
    rows = [
        SYSMON_ROW,
        {**SYSMON_ROW, "oaev_event_epoch": "not a number"},
        {**SYSMON_ROW, "oaev_event_epoch": "nan"},
        {**SYSMON_ROW, "_raw": ""},
        {**SYSMON_ROW, "index": None},
        "garbage",
    ]
    mock_post.return_value = _response(json_data={"results": rows})

    # Act
    result = client.fetch_logging_events(QUERY)

    # Assert
    assert isinstance(result, LoggingRows)  # noqa: S101
    assert len(result.events) == 1  # noqa: S101
    assert result.skipped == 5  # noqa: S101


@patch("requests.Session.post")
def test_optional_fields_and_multivalue_host(mock_post, client):
    """Keep host and sourcetype optional; a multivalue host keeps its first value."""
    # Arrange
    row = {
        "oaev_event_epoch": "12.5",
        "index": "network",
        "host": ["fw01", "fw02"],
        "_raw": "Built outbound TCP connection",
    }
    mock_post.return_value = _response(json_data={"results": [row]})

    # Act
    result = client.fetch_logging_events(QUERY)

    # Assert
    assert result == LoggingRows(  # noqa: S101
        events=[
            LoggingEvent(
                event_epoch=12.5,
                index="network",
                host="fw01",
                sourcetype=None,
                raw="Built outbound TCP connection",
            )
        ]
    )


@patch("requests.Session.post")
def test_detection_query_request_is_unchanged(mock_post, client):
    """The Detection search still sends an uncapped oneshot search."""
    # Arrange
    mock_post.return_value = _response(json_data={"results": []})
    criteria = Mock(
        source_ips=["10.0.0.1"],
        target_ips=["10.0.0.2"],
        hostnames=[],
        start_date=None,
        end_date=None,
    )

    # Act
    client._execute_splunk_query(criteria)

    # Assert
    params = mock_post.call_args.kwargs["data"]
    assert params["search"].startswith("search index=_notable ")  # noqa: S101
    assert params["exec_mode"] == "oneshot"  # noqa: S101
    assert params["output_mode"] == "json"  # noqa: S101
    assert params["count"] == "0"  # noqa: S101
    assert mock_post.call_args.kwargs["timeout"] == 30  # noqa: S101
