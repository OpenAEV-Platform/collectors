"""Essential tests for SentinelOne Threat Events Fetcher service - Gherkin GWT Format."""

import pytest
from src.services.exception import SentinelOneValidationError
from src.services.fetcher_threat_events import FetcherThreatEvents
from tests.gwt_shared import (given_initialized_client_api,
                              given_threat_with_complete_data)

# --------
# Scenarios
# --------


# Scenario: Initialize threat events fetcher with valid client API
def test_initialize_threat_events_fetcher_with_valid_client_api():
    """Scenario: Initialize threat events fetcher with valid client API."""
    # Given: A valid client API is available
    client_api = _given_valid_client_api()

    # When: I initialize the threat events fetcher
    fetcher = _when_initialize_threat_events_fetcher(client_api)

    # Then: The threat events fetcher should be initialized successfully
    _then_threat_events_fetcher_initialized_successfully(fetcher, client_api)


# Scenario: Initialize with invalid client API raises error
def test_initialize_with_invalid_client_api():
    """Scenario: Initialize with invalid client API raises error."""
    # Given: An invalid client API (None)
    invalid_client_api = _given_invalid_client_api()

    # When: I attempt to initialize the threat events fetcher
    # Then: A validation error should be raised
    _when_initialize_threat_events_fetcher_then_validation_error_raised(
        invalid_client_api
    )


# Scenario: Fetch events for threat successfully
def test_fetch_events_for_threat_successfully():
    """Scenario: Fetch events for threat successfully."""
    # Given: A valid threat events fetcher
    fetcher = _given_valid_threat_events_fetcher()
    # Given: A threat to fetch events for
    threat = _given_threat_for_event_fetching()

    # When: I fetch events for the threat (with mocked API)
    from unittest.mock import Mock, patch

    mock_response = Mock()
    mock_response.json.return_value = {
        "data": [
            {
                "id": "event_1",
                "processName": "test.exe",
                "createdAt": "2024-01-01T12:00:00Z",
            }
        ]
    }
    mock_response.raise_for_status.return_value = None

    with patch.object(fetcher.client_api.session, "get", return_value=mock_response):
        events = _when_fetch_events_for_threat(fetcher, threat)

    # Then: Events should be returned successfully
    _then_events_returned_successfully(events)


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


# Given: An invalid client API (None)
def _given_invalid_client_api():
    """Create an invalid client API.

    Returns:
        None (invalid client API).

    """
    return None


# Given: A valid threat events fetcher
def _given_valid_threat_events_fetcher():
    """Create a valid threat events fetcher for testing.

    Returns:
        Initialized FetcherThreatEvents instance.

    """
    client_api = given_initialized_client_api()
    return FetcherThreatEvents(client_api)


# Given: A threat to fetch events for
def _given_threat_for_event_fetching():
    """Create a threat for event fetching testing.

    Returns:
        Threat object for testing.

    """
    return given_threat_with_complete_data()


# Given: Mock API returns event data
def _given_mock_api_returns_event_data(fetcher):
    """Set up mock API to return event data.

    Args:
        fetcher: The threat events fetcher instance to mock.

    """
    pass


# --------
# When Methods
# --------


# When: I initialize the threat events fetcher
def _when_initialize_threat_events_fetcher(client_api):
    """Initialize threat events fetcher with given client API.

    Args:
        client_api: Client API instance to use.

    Returns:
        Initialized FetcherThreatEvents instance.

    """
    return FetcherThreatEvents(client_api)


# When: I attempt to initialize with invalid client API and expect validation error
def _when_initialize_threat_events_fetcher_then_validation_error_raised(
    invalid_client_api,
):
    """Attempt to initialize with invalid client API and expect validation error.

    Args:
        invalid_client_api: Invalid client API to test.

    """
    with pytest.raises(SentinelOneValidationError):
        FetcherThreatEvents(invalid_client_api)


# When: I fetch events for the threat
def _when_fetch_events_for_threat(fetcher, threat):
    """Fetch events for given threat.

    Args:
        fetcher: The threat events fetcher instance.
        threat: Threat to fetch events for.

    Returns:
        List of fetched events.

    """
    return fetcher.fetch_events_for_threat(threat)


# --------
# Then Methods
# --------


# Then: The threat events fetcher should be initialized successfully
def _then_threat_events_fetcher_initialized_successfully(fetcher, client_api):
    """Verify threat events fetcher was initialized successfully.

    Args:
        fetcher: The fetcher instance to verify.
        client_api: The client API used for initialization.

    """
    assert fetcher is not None  # noqa: S101
    assert fetcher.client_api == client_api  # noqa: S101
    assert fetcher.logger is not None  # noqa: S101


# Then: Events should be returned successfully
def _then_events_returned_successfully(events):
    """Verify events were returned successfully.

    Args:
        events: The fetched events to verify.

    """
    assert isinstance(events, list)  # noqa: S101
    assert len(events) > 0  # noqa: S101

    # Basic verification that we got events back
    assert all(isinstance(event, dict) for event in events)  # noqa: S101
