"""Essential tests for the SentinelOne SDL v2 deep-search fetcher - Gherkin GWT Format."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import ConnectionError as RequestsConnectionError
from src.services.exception import (
    SentinelOneAPIError,
    SentinelOneNetworkError,
    SentinelOneValidationError,
)
from src.services.expectation_service import SentinelOneExpectationService
from src.services.fetcher_deep_visibility import FetcherDeepVisibility
from src.services.fetcher_sdl import FetcherSDL
from tests.services.fixtures.factories import create_test_config

# --------
# Fixtures
# --------


@pytest.fixture(autouse=True)
def mock_logging() -> logging.Logger:
    """Shadow the services conftest ``mock_logging`` fixture for this module.

    The conftest autouse fixture replaces every named logger with a shared
    ``Mock``; log calls on that mock never reach the real logging hierarchy,
    so the ``caplog`` fixture cannot observe them. The 429 retry scenario
    must emit its warning through the real loggers for ``caplog`` to
    capture it, so this module-level fixture shadows the conftest one and
    restores real logging for this module only.

    Yields:
        The real root logger.

    """
    yield logging.getLogger()


# --------
# Given Helpers
# --------


def _given_mock_client_api(is_self_hosted: bool) -> Mock:
    """Create a mock client API exposing the SDL fetcher's contract surface.

    Args:
        is_self_hosted: Value of the client's is_self_hosted flag.

    Returns:
        Mock client API with base_url, time_window, and session set.

    """
    client = Mock()
    client.base_url = "https://s1.example.com"
    client.time_window = timedelta(hours=1)
    client.is_self_hosted = is_self_hosted
    return client


def _given_sdl_fetcher(is_self_hosted: bool = False) -> tuple[FetcherSDL, Mock]:
    """Create an SDL fetcher wired to a fresh mock session.

    Args:
        is_self_hosted: Value of the client's is_self_hosted flag.

    Returns:
        Tuple of (FetcherSDL instance, mock session).

    """
    session = Mock()
    client = _given_mock_client_api(is_self_hosted)
    client.session = session
    return FetcherSDL(client), session


def _given_valid_sha1() -> str:
    """Create a valid SHA1 hash for tests.

    Returns:
        Valid SHA1 string.

    """
    return "a1b2c3d4e5f6789012345678901234567890abcd"


def _given_valid_sha1_list() -> list[str]:
    """Create a list of valid SHA1 hashes for tests.

    Returns:
        List of three valid SHA1 strings.

    """
    return [
        "a1b2c3d4e5f6789012345678901234567890abcd",
        "b2c3d4e5f6789012345678901234567890abcdef",
        "c3d4e5f6789012345678901234567890abcdef01",
    ]


def _given_valid_time_range() -> tuple[datetime, datetime]:
    """Create a fixed UTC time range for tests.

    Returns:
        Tuple of (start, end) tz-aware datetimes.

    """
    start = datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc)
    return start, end


def _given_row(
    cursor: str,
    sha1: str,
    event_id: str,
    parent_name: str,
    process_name: str,
    event_type: str,
    event_time_ms: int,
    hostname: str = "kingslanding",
) -> dict[str, Any]:
    """Create one SDL v2 match row in the verified row shape.

    Args:
        cursor: Row cursor (G/... in production).
        sha1: tgt.file.sha1 value.
        event_id: event.id value.
        parent_name: src.process.parent.name value.
        process_name: src.process.name value.
        event_type: event.type value.
        event_time_ms: event.time in milliseconds.
        hostname: endpoint.name value.

    Returns:
        Raw SDL match row dictionary.

    """
    return {
        "cursor": cursor,
        "serverInfo": {},
        "sessionId": "",
        "severity": 3,
        "threadId": "",
        "timestamp": event_time_ms * 1_000_000,
        "values": {
            "tgt.file.sha1": sha1,
            "tgt.file.sha256": "f" * 64,
            "tgt.file.id": "7F8BC31AF4A291CB",
            "tgt.file.name": "implant.exe",
            "tgt.file.path": "C:\\ProgramData\\implant.exe",
            "src.process.name": process_name,
            "src.process.cmdline": f"C:\\Windows\\System32\\{process_name}",
            "src.process.image.path": "C:\\Windows\\System32\\",
            "src.process.parent.name": parent_name,
            "src.process.parent.cmdline": "C:\\Windows\\explorer.exe",
            "src.process.parent.image.path": "C:\\Windows\\",
            "endpoint.name": hostname,
            "event.type": event_type,
            "event.time": event_time_ms,
            "event.id": event_id,
            "account.name": "svc-alerts",
        },
    }


def _given_launch_response(query_id: str, forward_tag: str = "G/fwd-tag-1") -> Mock:
    """Create a 200 SDL query-launch response.

    The forward tag header is deliberately mixed-case: the fetcher must
    match it case-insensitively and echo it back in canonical case.

    Args:
        query_id: Query id to return in the body.
        forward_tag: Forward tag header value.

    Returns:
        Mock response with status, headers, and json body.

    """
    response = Mock()
    response.status_code = 200
    response.headers = {"X-Dataset-Query-Forward-Tag": forward_tag}
    response.json.return_value = {
        "id": query_id,
        "stepsCompleted": 2,
        "stepsTotal": 2,
        "totalSteps": 2,
        "data": {"estimatedMatchCount": 0.0, "matches": []},
    }
    return response


def _given_poll_response(
    query_id: str,
    rows: list[dict[str, Any]],
    estimated_match_count: float,
    steps_completed: int,
    steps_total: int = 2,
) -> Mock:
    """Create a 200 SDL query-poll response.

    Args:
        query_id: Query id echoed in the body.
        rows: Match rows in the data block.
        estimated_match_count: estimatedMatchCount in the data block.
        steps_completed: stepsCompleted value.
        steps_total: stepsTotal value.

    Returns:
        Mock response with status and json body.

    """
    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "id": query_id,
        "stepsCompleted": steps_completed,
        "stepsTotal": steps_total,
        "totalSteps": steps_total,
        "data": {
            "estimatedMatchCount": estimated_match_count,
            "matches": rows,
        },
    }
    return response


def _given_mock_session_get(account_type_present: bool) -> Mock:
    """Create a replacement for requests.Session.get with an account listing.

    Args:
        account_type_present: Whether one account exposes an accountType
            field (SaaS) or none do (self-hosted).

    Returns:
        Mock callable returning the listing response.

    """
    if account_type_present:
        accounts = [{"id": "acc-1", "name": "SaaS Tenant", "accountType": "Trial"}]
    else:
        accounts = [{"id": "acc-1", "name": "Legacy Tenant"}]
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"data": accounts}
    return Mock(return_value=response)


# --------
# Scenarios
# --------


# Scenario: A single SHA1 filter uses only verified S1QL 2.0 fields
def test_single_sha1_filter_uses_verified_s1ql_2_fields():
    """Scenario: A single SHA1 filter uses only verified S1QL 2.0 fields."""
    # Given: An SDL fetcher
    fetcher, _ = _given_sdl_fetcher()
    # Given: A valid SHA1
    sha1 = _given_valid_sha1()

    # When: The S1QL filter is built for the single SHA1
    filter_expr = fetcher._build_s1ql_filter([sha1])

    # Then: The filter is tenant-wide and uses verified 2.0 field names only
    base = "dataSource.name='SentinelOne' dataSource.category='security'"
    assert filter_expr == f"{base} tgt.file.sha1='{sha1}'"  # noqa: S101
    assert "endpoint.name" not in filter_expr  # noqa: S101
    assert "agent.hostname" not in filter_expr  # noqa: S101


# Scenario: A batch filter OR-joins every SHA1 without a host filter
def test_batch_sha1_filter_or_joins_all_sha1s():
    """Scenario: A batch filter OR-joins every SHA1 without a host filter."""
    # Given: An SDL fetcher
    fetcher, _ = _given_sdl_fetcher()
    # Given: A list of valid SHA1s
    sha1s = _given_valid_sha1_list()

    # When: The S1QL filter is built for the batch
    filter_expr = fetcher._build_s1ql_filter(sha1s)

    # Then: Every SHA1 is OR-joined inside the tenant-wide base clauses
    base = "dataSource.name='SentinelOne' dataSource.category='security'"
    or_expr = " or ".join(f"tgt.file.sha1='{s}'" for s in sha1s)
    assert filter_expr == f"{base} ({or_expr})"  # noqa: S101
    assert "endpoint.name" not in filter_expr  # noqa: S101


# Scenario: S1QL string values are defensively escaped
def test_s1ql_string_values_are_escaped():
    """Scenario: S1QL string values are defensively escaped."""
    # Given: An SDL fetcher
    fetcher, _ = _given_sdl_fetcher()

    # When: A value containing a quote and a backslash is escaped
    escaped = fetcher._escape_s1ql_string("a'b\\c")

    # Then: Backslashes are escaped before quotes
    assert escaped == "a\\'b\\\\c"  # noqa: S101


# Scenario: The launch body matches the verified SDL v2 contract
def test_launch_body_matches_sdl_v2_contract():
    """Scenario: The launch body matches the verified SDL v2 contract."""
    # Given: An SDL fetcher
    fetcher, _ = _given_sdl_fetcher()
    # Given: A valid time range
    start, end = _given_valid_time_range()

    # When: A first-page launch body is built (no cursor)
    body = fetcher._build_launch_body("f = 'x'", start, end, None)

    # Then: The body uses only contract-valid fields
    assert body["queryType"] == "LOG"  # noqa: S101
    assert body["tenant"] is True  # noqa: S101
    assert body["startTime"] == "2026-08-01T00:00:00Z"  # noqa: S101
    assert body["endTime"] == "2026-08-31T23:59:59Z"  # noqa: S101
    assert body["queryPriority"] == "HIGH"  # noqa: S101
    assert body["log"] == {"filter": "f = 'x'", "limit": 100}  # noqa: S101
    assert "cursor" not in body["log"]  # noqa: S101
    assert "offset" not in body["log"]  # noqa: S101
    assert "lastCursor" not in body["log"]  # noqa: S101

    # When: A resumption launch body is built with a cursor
    resumed = fetcher._build_launch_body("f = 'x'", start, end, "G/xyz")

    # Then: The cursor is carried in the log block
    assert resumed["log"]["cursor"] == "G/xyz"  # noqa: S101


# Scenario: A SaaS fetch posts only to SDL v2 endpoints
def test_saas_fetch_posts_only_to_sdl_endpoints():
    """Scenario: A SaaS fetch posts only to SDL v2 endpoints."""
    # Given: A SaaS SDL fetcher
    fetcher, session = _given_sdl_fetcher(is_self_hosted=False)
    # Given: A valid SHA1
    sha1 = _given_valid_sha1()
    # Given: One matching row on the first page
    rows = [
        _given_row(
            "c-1",
            sha1,
            "e-1",
            "explorer.exe",
            "implant.exe",
            "process_creation",
            1577836800000,
        )
    ]
    session.post.return_value = _given_launch_response("q-1")
    session.get.return_value = _given_poll_response("q-1", rows, 1.0, 2, 2)

    # When: I fetch events for the SHA1
    events = fetcher.fetch_events_for_sha1(sha1)

    # Then: The launch goes to /sdl/v2/api/queries, never to /dv/
    assert len(events) == 1  # noqa: S101
    assert session.post.call_count == 1  # noqa: S101
    launch_url = session.post.call_args.args[0]
    assert launch_url == "https://s1.example.com/sdl/v2/api/queries"  # noqa: S101
    launch_body = session.post.call_args.kwargs["json"]
    assert f"tgt.file.sha1='{sha1}'" in launch_body["log"]["filter"]  # noqa: S101
    poll_url = session.get.call_args.args[0]
    assert poll_url == "https://s1.example.com/sdl/v2/api/queries/q-1"  # noqa: S101
    all_urls = [c.args[0] for c in session.post.call_args_list] + [
        c.args[0] for c in session.get.call_args_list
    ]
    assert all("/dv/" not in url for url in all_urls)  # noqa: S101


# Scenario: The service selects the SDL fetcher for a SaaS instance
def test_service_selects_sdl_fetcher_for_saas():
    """Scenario: The service selects the SDL fetcher for a SaaS instance."""
    # Given: A SaaS account listing (one account exposes accountType)
    mock_get = _given_mock_session_get(account_type_present=True)

    # When: The expectation service is initialized with the probe mocked
    with patch("requests.Session.get", new=mock_get):
        service = SentinelOneExpectationService(config=create_test_config())

    # Then: The deep-search backend is the SDL v2 fetcher
    backend = service.deep_visibility_fetcher
    assert isinstance(backend, FetcherSDL)  # noqa: S101
    assert not isinstance(backend, FetcherDeepVisibility)  # noqa: S101


# Scenario: The service keeps the DV fetcher for a self-hosted instance
def test_service_selects_dv_fetcher_for_self_hosted():
    """Scenario: The service keeps the DV fetcher for a self-hosted instance."""
    # Given: A self-hosted account listing (no accountType anywhere)
    mock_get = _given_mock_session_get(account_type_present=False)

    # When: The expectation service is initialized with the probe mocked
    with patch("requests.Session.get", new=mock_get):
        service = SentinelOneExpectationService(config=create_test_config())

    # Then: The deep-search backend is the legacy DV fetcher
    backend = service.deep_visibility_fetcher
    assert isinstance(backend, FetcherDeepVisibility)  # noqa: S101
    assert not isinstance(backend, FetcherSDL)  # noqa: S101


# Scenario: Polling completes and echoes the forward tag on every poll
def test_polling_completes_and_echoes_forward_tag():
    """Scenario: Polling completes and echoes the forward tag on every poll."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: A valid SHA1
    sha1 = _given_valid_sha1()
    # Given: A launch response carrying a mixed-case forward tag
    session.post.return_value = _given_launch_response(
        "q-42", forward_tag="G/fwd-tag-77"
    )
    # Given: An incomplete first poll and a complete second poll
    rows = [
        _given_row(
            "c-1",
            sha1,
            "e-1",
            "explorer.exe",
            "implant.exe",
            "process_creation",
            1577836800000,
        )
    ]
    incomplete = _given_poll_response("q-42", [], 1.0, steps_completed=1)
    complete = _given_poll_response("q-42", rows, 1.0, steps_completed=2)
    session.get.side_effect = [incomplete, complete]

    # When: I fetch with sleeps disabled
    with patch("time.sleep"):
        events = fetcher.fetch_events_for_sha1(sha1)

    # Then: The query completed after two polls
    assert len(events) == 1  # noqa: S101
    assert session.get.call_count == 2  # noqa: S101
    # And: The forward tag is echoed in canonical case on every poll
    first = session.get.call_args_list[0]
    second = session.get.call_args_list[1]
    expected_headers = {"x-dataset-query-forward-tag": "G/fwd-tag-77"}
    assert first.kwargs["headers"] == expected_headers  # noqa: S101
    assert second.kwargs["headers"] == expected_headers  # noqa: S101
    # And: lastStepSeen tracks the last observed stepsCompleted
    assert first.kwargs["params"] == {"lastStepSeen": 0}  # noqa: S101
    assert second.kwargs["params"] == {"lastStepSeen": 1}  # noqa: S101


# Scenario: Pagination resumes with cursors and deduplicates inclusive overlaps
def test_pagination_resumes_with_cursor_and_dedupes():
    """Scenario: Pagination resumes with cursors and deduplicates overlaps."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: Six rows for the target SHA1
    sha1 = _given_valid_sha1()
    rows = [
        _given_row(
            f"cursor-{i}",
            sha1,
            f"evt-{i}",
            "explorer.exe",
            "implant.exe",
            "process_creation",
            1577836800000 + i,
        )
        for i in range(6)
    ]
    # Given: Five pages; each resumed page repeats its first row (inclusive)
    pages = [
        (rows[0:2], 6.0),
        (rows[1:3], 5.0),
        (rows[2:4], 4.0),
        (rows[3:5], 3.0),
        (rows[4:6], 2.0),
    ]
    session.post.side_effect = [
        _given_launch_response(f"q-{i + 1}") for i in range(len(pages))
    ]
    session.get.side_effect = [
        _given_poll_response(f"q-{i + 1}", page_rows, est, 2, 2)
        for i, (page_rows, est) in enumerate(pages)
    ]

    # When: I fetch all pages
    events = fetcher.fetch_events_for_sha1(sha1)

    # Then: Paging stopped once the first page's estimate was reached
    assert session.post.call_count == 5  # noqa: S101
    assert session.get.call_count == 5  # noqa: S101
    # And: Inclusive-resumption overlaps were deduplicated by cursor
    assert len(events) == 6  # noqa: S101
    assert [e["fileSha1"] for e in events] == [sha1] * 6  # noqa: S101
    # And: Resumption passed the previous page's last row cursor
    first_body = session.post.call_args_list[0].kwargs["json"]
    last_body = session.post.call_args_list[4].kwargs["json"]
    assert "cursor" not in first_body["log"]  # noqa: S101
    assert last_body["log"]["cursor"] == "cursor-4"  # noqa: S101


# Scenario: A row maps to the Deep-Visibility-shaped event contract
def test_row_maps_to_deep_visibility_event_contract():
    """Scenario: A row maps to the Deep-Visibility-shaped event contract."""
    # Given: An SDL fetcher
    fetcher, _ = _given_sdl_fetcher()
    # Given: A row with the verified field vocabulary
    row = _given_row(
        "c-1",
        _given_valid_sha1(),
        "evt-9",
        "explorer.exe",
        "implant.exe",
        "process_creation",
        1577836800500,
    )

    # When: The row is mapped to an event
    event = fetcher._map_row_to_event(row)

    # Then: Every contract key is populated from the row values
    assert event["fileSha1"] == _given_valid_sha1()  # noqa: S101
    assert event["fileSha256"] == "f" * 64  # noqa: S101
    assert event["fileId"] == "7F8BC31AF4A291CB"  # noqa: S101
    assert event["parentProcessName"] == "explorer.exe"  # noqa: S101
    assert event["processName"] == "implant.exe"  # noqa: S101
    assert event["processCmdline"] == "C:\\Windows\\System32\\implant.exe"  # noqa: S101
    assert event["parentProcessCmdline"] == "C:\\Windows\\explorer.exe"  # noqa: S101
    assert event["hostname"] == "kingslanding"  # noqa: S101
    assert event["eventType"] == "process_creation"  # noqa: S101
    assert event["eventTime"] == "2020-01-01T00:00:00.500000Z"  # noqa: S101
    assert event["eventId"] == "evt-9"  # noqa: S101
    # And: The raw values block is preserved
    assert event["raw"] is row["values"]  # noqa: S101


# Scenario: Row mapping tolerates missing fields
def test_row_mapping_tolerates_missing_fields():
    """Scenario: Row mapping tolerates missing fields."""
    # Given: An SDL fetcher
    fetcher, _ = _given_sdl_fetcher()

    # When: A row with an empty values block is mapped
    event = fetcher._map_row_to_event({"cursor": "c-x", "values": {}})

    # Then: Every field degrades to None instead of raising
    assert event["fileSha1"] is None  # noqa: S101
    assert event["parentProcessName"] is None  # noqa: S101
    assert event["eventTime"] is None  # noqa: S101
    assert event["raw"] == {}  # noqa: S101

    # When: A row with no values block at all is mapped
    bare = fetcher._map_row_to_event({})

    # Then: It also degrades to all-None fields
    assert bare["fileSha1"] is None  # noqa: S101
    assert bare["raw"] == {}  # noqa: S101


# Scenario: Batch results group events per requested SHA1
def test_batch_groups_events_per_requested_sha1():
    """Scenario: Batch results group events per requested SHA1."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: Three requested SHA1s
    sha1s = _given_valid_sha1_list()
    first, second, third = sha1s
    # Given: Rows for two requested SHA1s and one unrequested SHA1
    unrequested = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
    rows = [
        _given_row("c-1", first, "e-1", "p1", "q1", "t1", 1577836800000),
        _given_row("c-2", first, "e-2", "p1", "q2", "t1", 1577836801000),
        _given_row("c-3", second, "e-3", "p2", "q3", "t2", 1577836802000),
        _given_row("c-4", unrequested, "e-4", "p3", "q4", "t3", 1577836803000),
    ]
    session.post.return_value = _given_launch_response("q-batch")
    session.get.return_value = _given_poll_response("q-batch", rows, 4.0, 2, 2)

    # When: I fetch the batch
    result = fetcher.fetch_events_for_batch_sha1(sha1s)

    # Then: Every requested SHA1 is a key, including the no-match one
    assert set(result.keys()) == set(sha1s)  # noqa: S101
    assert len(result[first]) == 2  # noqa: S101
    assert len(result[second]) == 1  # noqa: S101
    assert result[third] == []  # noqa: S101
    # And: The unrequested row was dropped
    assert sum(len(v) for v in result.values()) == 3  # noqa: S101


# Scenario: Single-SHA1 fetch post-filters non-matching rows
def test_single_sha1_fetch_postfilters_non_matching_rows():
    """Scenario: Single-SHA1 fetch post-filters non-matching rows."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: The target SHA1 and a different one
    target = _given_valid_sha1()
    other = "b2c3d4e5f6789012345678901234567890abcdef"
    # Given: A page containing both
    rows = [
        _given_row("c-1", target, "e-1", "p", "q", "t", 1577836800000),
        _given_row("c-2", other, "e-2", "p", "q", "t", 1577836801000),
        _given_row("c-3", target, "e-3", "p", "q", "t", 1577836802000),
    ]
    session.post.return_value = _given_launch_response("q-pf")
    session.get.return_value = _given_poll_response("q-pf", rows, 3.0, 2, 2)

    # When: I fetch events for the target SHA1
    events = fetcher.fetch_events_for_sha1(target)

    # Then: Only rows matching the target SHA1 survive
    assert len(events) == 2  # noqa: S101
    assert all(e["fileSha1"] == target for e in events)  # noqa: S101


# Scenario: A 400 invalid_argument launch error surfaces with its details
def test_launch_400_invalid_argument_raises_api_error():
    """Scenario: A 400 invalid_argument launch error surfaces with details."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: A 400 response in the verified SDL error shape
    response = Mock()
    response.status_code = 400
    response.json.return_value = {
        "code": "invalid_argument",
        "message": "Invalid JSON",
        "details": [{"field": "log.offset", "message": "Cannot deserialize JSON"}],
    }
    response.text = str(response.json.return_value)
    session.post.return_value = response

    # When: I launch a fetch
    with pytest.raises(SentinelOneAPIError) as excinfo:
        fetcher.fetch_events_for_sha1(_given_valid_sha1())

    # Then: The error carries the status and the structured details
    message = str(excinfo.value)
    assert "SDL query launch" in message  # noqa: S101
    assert "status 400" in message  # noqa: S101
    assert "code=invalid_argument" in message  # noqa: S101
    assert "message=Invalid JSON" in message  # noqa: S101
    assert "log.offset: Cannot deserialize JSON" in message  # noqa: S101


# Scenario: A 404 poll means the query expired
def test_poll_404_expired_raises_api_error():
    """Scenario: A 404 poll means the query expired."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: A successful launch followed by a 404 poll
    session.post.return_value = _given_launch_response("q-exp")
    not_found = Mock()
    not_found.status_code = 404
    not_found.json.return_value = {"message": "query not found"}
    not_found.text = "query not found"
    session.get.return_value = not_found

    # When: I fetch events
    with pytest.raises(SentinelOneAPIError) as excinfo:
        fetcher.fetch_events_for_sha1(_given_valid_sha1())

    # Then: The error reports the query as expired
    assert "expired (HTTP 404)" in str(excinfo.value)  # noqa: S101


# Scenario: A 429 is retried with backoff, then succeeds
def test_429_retries_with_backoff_then_succeeds(caplog: Any):
    """Scenario: A 429 is retried with backoff, then succeeds."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: The first launch is rate limited, the retry succeeds
    rate_limited = Mock()
    rate_limited.status_code = 429
    session.post.side_effect = [rate_limited, _given_launch_response("q-rl")]
    session.get.return_value = _given_poll_response("q-rl", [], 0.0, 2, 2)

    # When: I fetch with sleeps disabled
    with patch("time.sleep") as mock_sleep:
        events = fetcher.fetch_events_for_sha1(_given_valid_sha1())

    # Then: The retry succeeded after one 5-second backoff
    assert events == []  # noqa: S101
    assert session.post.call_count == 2  # noqa: S101
    mock_sleep.assert_called_once_with(5)
    # And: The rate limit was logged as a warning
    assert any(  # noqa: S101
        "retry 1/4 in 5s" in record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
    )


# Scenario: Exhausted 429 retries raise an API error
def test_429_retries_exhausted_raises_api_error():
    """Scenario: Exhausted 429 retries raise an API error."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: Every launch is rate limited
    rate_limited = Mock()
    rate_limited.status_code = 429
    session.post.return_value = rate_limited

    # When: I fetch with sleeps disabled
    with patch("time.sleep"):
        with pytest.raises(SentinelOneAPIError) as excinfo:
            fetcher.fetch_events_for_sha1(_given_valid_sha1())

    # Then: The error reports the exhausted retries
    assert "rate limited" in str(excinfo.value)  # noqa: S101
    assert "4 retries" in str(excinfo.value)  # noqa: S101
    # And: The bounded retry budget was respected (initial + 4 retries)
    assert session.post.call_count == 5  # noqa: S101


# Scenario: A network error raises SentinelOneNetworkError
def test_network_error_raises_network_error():
    """Scenario: A network error raises SentinelOneNetworkError."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()
    # Given: The launch connection fails
    session.post.side_effect = RequestsConnectionError("connection refused")

    # When: I fetch events
    with pytest.raises(SentinelOneNetworkError) as excinfo:
        fetcher.fetch_events_for_sha1(_given_valid_sha1())

    # Then: The failure is reported as a network error
    assert "Network error" in str(excinfo.value)  # noqa: S101


# Scenario: Invalid SHA1 input fails before any request is made
def test_invalid_sha1_raises_validation_error():
    """Scenario: Invalid SHA1 input fails before any request is made."""
    # Given: An SDL fetcher
    fetcher, session = _given_sdl_fetcher()

    # When: I fetch with an empty SHA1
    with pytest.raises(SentinelOneValidationError):
        fetcher.fetch_events_for_sha1("")

    # When: I fetch with a non-string SHA1
    with pytest.raises(SentinelOneValidationError):
        fetcher.fetch_events_for_sha1(12345)

    # When: I batch-fetch with an empty list
    with pytest.raises(SentinelOneValidationError):
        fetcher.fetch_events_for_batch_sha1([])

    # Then: No request was ever made
    session.post.assert_not_called()
    session.get.assert_not_called()


# Scenario: Absent times default to the configured time window
def test_default_window_used_when_times_absent():
    """Scenario: Absent times default to the configured time window."""
    # Given: An SDL fetcher with a one-hour client time window
    fetcher, session = _given_sdl_fetcher()
    # Given: An empty matching response
    session.post.return_value = _given_launch_response("q-dw")
    session.get.return_value = _given_poll_response("q-dw", [], 0.0, 2, 2)

    # When: I fetch without explicit times
    fetcher.fetch_events_for_sha1(_given_valid_sha1())

    # Then: The launch body spans exactly the configured window
    body = session.post.call_args.kwargs["json"]
    assert body["startTime"].endswith("Z")  # noqa: S101
    assert body["endTime"].endswith("Z")  # noqa: S101
    start = datetime.fromisoformat(body["startTime"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(body["endTime"].replace("Z", "+00:00"))
    assert end - start == timedelta(hours=1)  # noqa: S101
