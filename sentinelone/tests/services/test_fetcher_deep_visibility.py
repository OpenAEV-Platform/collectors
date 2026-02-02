"""Essential tests for SentinelOne Deep Visibility Fetcher service - Gherkin GWT Format."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
from src.services.exception import SentinelOneValidationError
from src.services.fetcher_deep_visibility import FetcherDeepVisibility
from tests.gwt_shared import given_initialized_client_api

# --------
# Scenarios
# --------


# Scenario: Initialize deep visibility fetcher with valid client API
def test_initialize_deep_visibility_fetcher_with_valid_client_api():
    """Scenario: Initialize deep visibility fetcher with valid client API."""
    # Given: A valid client API is available
    client_api = _given_valid_client_api()

    # When: I initialize the deep visibility fetcher
    fetcher = _when_initialize_deep_visibility_fetcher(client_api)

    # Then: The deep visibility fetcher should be initialized successfully
    _then_deep_visibility_fetcher_initialized_successfully(fetcher, client_api)


# Scenario: Fetch events for single SHA1 successfully
def test_fetch_events_for_single_sha1_successfully():
    """Scenario: Fetch events for single SHA1 successfully."""
    # Given: A valid deep visibility fetcher
    fetcher = _given_valid_deep_visibility_fetcher()
    # Given: A valid SHA1 hash
    sha1 = _given_valid_sha1()
    # Given: A valid time range
    start_time, end_time = _given_valid_time_range()

    # When: I fetch events for the SHA1 (with mocked API)
    with _mock_deep_visibility_success_response(fetcher, sha1):
        events = _when_fetch_events_for_sha1(fetcher, sha1, start_time, end_time)

    # Then: Events should be returned successfully
    _then_events_returned_successfully_for_single_sha1(events, sha1)


# Scenario: Fetch events for batch SHA1s successfully
def test_fetch_events_for_batch_sha1s_successfully():
    """Scenario: Fetch events for batch SHA1s successfully."""
    # Given: A valid deep visibility fetcher
    fetcher = _given_valid_deep_visibility_fetcher()
    # Given: A list of valid SHA1 hashes
    sha1_list = _given_valid_sha1_list()
    # Given: A valid time range
    start_time, end_time = _given_valid_time_range()

    # When: I fetch events for the SHA1 batch (with mocked API)
    with _mock_deep_visibility_batch_success_response(fetcher, sha1_list):
        events_dict = _when_fetch_events_for_batch_sha1(
            fetcher, sha1_list, start_time, end_time
        )

    # Then: Events should be returned successfully for all SHA1s
    _then_events_returned_successfully_for_batch_sha1s(events_dict, sha1_list)


# Scenario: Handle invalid SHA1 input
def test_handle_invalid_sha1_input():
    """Scenario: Handle invalid SHA1 input."""
    # Given: A valid deep visibility fetcher
    fetcher = _given_valid_deep_visibility_fetcher()
    # Given: Invalid SHA1 inputs
    invalid_sha1_cases = [None, "", 123, [], {}]

    for invalid_sha1 in invalid_sha1_cases:
        # When: I attempt to fetch events with invalid SHA1
        # Then: A validation error should be raised
        _when_fetch_events_for_sha1_then_validation_error_raised(fetcher, invalid_sha1)


# Scenario: Handle invalid SHA1 list input
def test_handle_invalid_sha1_list_input():
    """Scenario: Handle invalid SHA1 list input."""
    # Given: A valid deep visibility fetcher
    fetcher = _given_valid_deep_visibility_fetcher()

    # When: I attempt to fetch events with None SHA1 list
    # Then: A validation error should be raised
    with pytest.raises(SentinelOneValidationError):
        fetcher.fetch_events_for_batch_sha1(None)

    # When: I attempt to fetch events with empty SHA1 list
    # Then: A validation error should be raised
    with pytest.raises(SentinelOneValidationError):
        fetcher.fetch_events_for_batch_sha1([])


# Scenario: Handle API connection error during single SHA1 fetch
def test_handle_api_connection_error_single_sha1():
    """Scenario: Handle API connection error during single SHA1 fetch."""
    # Given: A valid deep visibility fetcher
    fetcher = _given_valid_deep_visibility_fetcher()
    # Given: A valid SHA1 hash
    sha1 = _given_valid_sha1()

    # When: I attempt to fetch events with connection error
    with _mock_connection_error(fetcher):
        _when_fetch_events_for_sha1_then_api_error_raised(fetcher, sha1)


# Scenario: Filter events correctly by SHA1 in single fetch
def test_filter_events_correctly_by_sha1_single_fetch():
    """Scenario: Filter events correctly by SHA1 in single fetch."""
    # Given: A valid deep visibility fetcher
    fetcher = _given_valid_deep_visibility_fetcher()
    # Given: A target SHA1 hash
    target_sha1 = _given_valid_sha1()

    # When: I fetch events and API returns mixed SHA1 events
    with _mock_mixed_sha1_events_response(fetcher, target_sha1):
        events = _when_fetch_events_for_sha1(fetcher, target_sha1)

    # Then: Only events matching the target SHA1 should be returned
    _then_only_target_sha1_events_returned(events, target_sha1)


# --------
# Given Methods
# --------


# Given: A valid client API is available
def _given_valid_client_api():
    """Create a valid client API for testing.

    Returns:
        Valid client API instance.

    """
    return given_initialized_client_api()


# Given: A valid deep visibility fetcher
def _given_valid_deep_visibility_fetcher():
    """Create a valid deep visibility fetcher for testing.

    Returns:
        Initialized FetcherDeepVisibility instance.

    """
    client_api = given_initialized_client_api()
    return FetcherDeepVisibility(client_api)


# Given: A valid SHA1 hash
def _given_valid_sha1():
    """Create a valid SHA1 hash for testing.

    Returns:
        Valid SHA1 string.

    """
    return "a1b2c3d4e5f6789012345678901234567890abcd"


# Given: A list of valid SHA1 hashes
def _given_valid_sha1_list():
    """Create a list of valid SHA1 hashes for testing.

    Returns:
        List of valid SHA1 strings.

    """
    return [
        "a1b2c3d4e5f6789012345678901234567890abcd",
        "b2c3d4e5f6789012345678901234567890abcdef",
        "c3d4e5f6789012345678901234567890abcdef01",
    ]


# Given: A valid time range
def _given_valid_time_range():
    """Create a valid time range for testing.

    Returns:
        Tuple of (start_time, end_time) datetime objects.

    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)
    return start_time, end_time


# --------
# Mock Context Managers
# --------


def _mock_deep_visibility_success_response(fetcher, sha1):
    """Mock Deep Visibility API to return successful response for single SHA1."""
    mock_query_response = Mock()
    mock_query_response.data = Mock()
    mock_query_response.data.query_id = "test_query_id"

    mock_events = [
        {
            "fileSha1": sha1,
            "processName": "test_process.exe",
            "timestamp": "2023-01-01T12:00:00Z",
            "eventType": "Process Creation",
        },
        {
            "fileSha1": "different_sha1",
            "processName": "other_process.exe",
            "timestamp": "2023-01-01T12:01:00Z",
            "eventType": "Process Creation",
        },
    ]

    return patch.multiple(
        fetcher,
        _init_dv_query=Mock(return_value=mock_query_response),
        _execute_query=Mock(return_value=mock_events),
    )


def _mock_deep_visibility_batch_success_response(fetcher, sha1_list):
    """Mock Deep Visibility API to return successful response for batch SHA1s."""
    mock_query_response = Mock()
    mock_query_response.data = Mock()
    mock_query_response.data.query_id = "test_batch_query_id"

    mock_events = []
    for i, sha1 in enumerate(sha1_list):
        mock_events.append(
            {
                "fileSha1": sha1,
                "processName": f"test_process_{i}.exe",
                "timestamp": f"2023-01-01T12:0{i}:00Z",
                "eventType": "Process Creation",
            }
        )

    return patch.multiple(
        fetcher,
        _init_dv_query=Mock(return_value=mock_query_response),
        _execute_query=Mock(return_value=mock_events),
    )


def _mock_connection_error(fetcher):
    """Mock connection error during API call."""
    from requests.exceptions import ConnectionError

    return patch.object(
        fetcher,
        "_init_dv_query",
        side_effect=ConnectionError("Connection failed"),
    )


def _mock_mixed_sha1_events_response(fetcher, target_sha1):
    """Mock API to return events with mixed SHA1s."""
    mock_query_response = Mock()
    mock_query_response.data = Mock()
    mock_query_response.data.query_id = "mixed_query_id"

    mock_events = [
        {"fileSha1": target_sha1, "processName": "target_process.exe"},
        {"fileSha1": "other_sha1_1", "processName": "other_process1.exe"},
        {"fileSha1": target_sha1, "processName": "target_process2.exe"},
        {"fileSha1": "other_sha1_2", "processName": "other_process2.exe"},
    ]

    return patch.multiple(
        fetcher,
        _init_dv_query=Mock(return_value=mock_query_response),
        _execute_query=Mock(return_value=mock_events),
    )


# --------
# When Methods
# --------


# When: I initialize the deep visibility fetcher
def _when_initialize_deep_visibility_fetcher(client_api):
    """Initialize deep visibility fetcher with given client API.

    Args:
        client_api: Client API instance to use.

    Returns:
        Initialized FetcherDeepVisibility instance.

    """
    return FetcherDeepVisibility(client_api)


# When: I fetch events for SHA1
def _when_fetch_events_for_sha1(fetcher, sha1, start_time=None, end_time=None):
    """Fetch events for given SHA1.

    Args:
        fetcher: The deep visibility fetcher instance.
        sha1: SHA1 hash to fetch events for.
        start_time: Start time for search (optional).
        end_time: End time for search (optional).

    Returns:
        List of fetched events.

    """
    return fetcher.fetch_events_for_sha1(sha1, start_time, end_time)


# When: I fetch events for batch SHA1s
def _when_fetch_events_for_batch_sha1(
    fetcher, sha1_list, start_time=None, end_time=None
):
    """Fetch events for given SHA1 list.

    Args:
        fetcher: The deep visibility fetcher instance.
        sha1_list: List of SHA1 hashes to fetch events for.
        start_time: Start time for search (optional).
        end_time: End time for search (optional).

    Returns:
        Dictionary mapping SHA1 to events.

    """
    return fetcher.fetch_events_for_batch_sha1(sha1_list, start_time, end_time)


# When: I attempt to fetch events for SHA1 and expect validation error
def _when_fetch_events_for_sha1_then_validation_error_raised(fetcher, invalid_sha1):
    """Attempt to fetch events for invalid SHA1 and expect validation error.

    Args:
        fetcher: The deep visibility fetcher instance.
        invalid_sha1: Invalid SHA1 to test.

    """
    with pytest.raises(SentinelOneValidationError):
        fetcher.fetch_events_for_sha1(invalid_sha1)


# When: I attempt to fetch events for SHA1 and expect API error
def _when_fetch_events_for_sha1_then_api_error_raised(fetcher, sha1):
    """Attempt to fetch events and expect API error.

    Args:
        fetcher: The deep visibility fetcher instance.
        sha1: SHA1 hash to fetch events for.

    """
    from src.services.exception import SentinelOneAPIError

    with pytest.raises(SentinelOneAPIError):
        fetcher.fetch_events_for_sha1(sha1)


# --------
# Then Methods
# --------


# Then: The deep visibility fetcher should be initialized successfully
def _then_deep_visibility_fetcher_initialized_successfully(fetcher, client_api):
    """Verify deep visibility fetcher was initialized successfully.

    Args:
        fetcher: The fetcher instance to verify.
        client_api: The client API used for initialization.

    """
    assert fetcher is not None  # noqa: S101
    assert fetcher.client_api == client_api  # noqa: S101
    assert fetcher.logger is not None  # noqa: S101


# Then: Events should be returned successfully for single SHA1
def _then_events_returned_successfully_for_single_sha1(events, sha1):
    """Verify events were returned successfully for single SHA1.

    Args:
        events: The fetched events to verify.
        sha1: The SHA1 that was searched for.

    """
    assert isinstance(events, list)  # noqa: S101
    assert len(events) > 0  # noqa: S101

    for event in events:
        assert event.get("fileSha1") == sha1  # noqa: S101
        assert isinstance(event, dict)  # noqa: S101


# Then: Events should be returned successfully for batch SHA1s
def _then_events_returned_successfully_for_batch_sha1s(events_dict, sha1_list):
    """Verify events were returned successfully for batch SHA1s.

    Args:
        events_dict: Dictionary of SHA1 to events.
        sha1_list: The SHA1 list that was searched for.

    """
    assert isinstance(events_dict, dict)  # noqa: S101
    assert len(events_dict) == len(sha1_list)  # noqa: S101

    for sha1 in sha1_list:
        assert sha1 in events_dict  # noqa: S101
        assert isinstance(events_dict[sha1], list)  # noqa: S101


# Then: Only events matching the target SHA1 should be returned
def _then_only_target_sha1_events_returned(events, target_sha1):
    """Verify only events matching target SHA1 are returned.

    Args:
        events: The fetched events to verify.
        target_sha1: The target SHA1 that should match.

    """
    assert isinstance(events, list)  # noqa: S101
    assert len(events) > 0  # noqa: S101

    for event in events:
        assert event.get("fileSha1") == target_sha1  # noqa: S101
