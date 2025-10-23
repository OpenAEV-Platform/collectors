"""Essential tests for SentinelOne Threat Fetcher service - Gherkin GWT Format."""

import pytest
from src.services.fetcher_threat import FetcherThreat
from src.services.exception import SentinelOneValidationError, SentinelOneNetworkError
from tests.gwt_shared import (
    given_initialized_client_api,
)


# --------
# Scenarios
# --------


# Scenario: Initialize threat fetcher with valid client API
def test_initialize_threat_fetcher_with_valid_client_api():
    """Scenario: Initialize threat fetcher with valid client API."""
    # Given: A valid client API is available
    client_api = _given_valid_client_api()

    # When: I initialize the threat fetcher
    fetcher = _when_initialize_threat_fetcher(client_api)

    # Then: The threat fetcher should be initialized successfully
    _then_threat_fetcher_initialized_successfully(fetcher, client_api)


# Scenario: Initialize with invalid client API raises error
def test_initialize_with_invalid_client_api():
    """Scenario: Initialize with invalid client API raises error."""
    # Given: An invalid client API (None)
    invalid_client_api = _given_invalid_client_api()

    # When: I attempt to initialize the threat fetcher
    # Then: A validation error should be raised
    _when_initialize_threat_fetcher_then_validation_error_raised(invalid_client_api)


# Scenario: Fetch threats for time window successfully
def test_fetch_threats_for_time_window_successfully():
    """Scenario: Fetch threats for time window successfully."""
    # Given: A valid threat fetcher
    fetcher = _given_valid_threat_fetcher()
    # Given: A valid time window
    time_window = _given_valid_time_window()
    # When: I fetch threats for the time window (with mocked API)
    from unittest.mock import Mock, patch

    mock_response = Mock()
    mock_response.json.return_value = {
        "data": [
            {
                "threatInfo": {
                    "threatId": "test_threat_1",
                    "computerName": "test-host.example.com",
                    "mitigationStatus": "not_mitigated",
                }
            }
        ]
    }
    mock_response.raise_for_status.return_value = None

    with patch.object(fetcher.client_api.session, "get", return_value=mock_response):
        threats = _when_fetch_threats_for_time_window(fetcher, time_window)

    # Then: Threats should be returned successfully
    _then_threats_returned_successfully(threats)


# Scenario: Handle API connection error
def test_handle_api_connection_error():
    """Scenario: Handle API connection error."""
    # Given: A valid threat fetcher
    fetcher = _given_valid_threat_fetcher()
    # Given: A valid time window
    time_window = _given_valid_time_window()

    # When: I attempt to fetch threats with connection error
    from requests.exceptions import ConnectionError
    from unittest.mock import patch

    with patch.object(
        fetcher.client_api.session,
        "get",
        side_effect=ConnectionError("Connection failed"),
    ):
        _when_fetch_threats_then_network_error_raised(fetcher, time_window)


# Scenario: Handle invalid time window
def test_handle_invalid_time_window():
    """Scenario: Handle invalid time window."""
    # Given: A valid threat fetcher
    fetcher = _given_valid_threat_fetcher()
    # Given: An invalid time window
    invalid_time_window = _given_invalid_time_window()

    # When: I attempt to fetch threats with invalid time window
    # Then: A validation error should be raised
    _when_fetch_threats_then_validation_error_raised(fetcher, invalid_time_window)


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


# Given: A valid threat fetcher
def _given_valid_threat_fetcher():
    """Create a valid threat fetcher for testing.

    Returns:
        Initialized SentinelOneThreatFetcher instance.

    """
    client_api = given_initialized_client_api()
    return FetcherThreat(client_api)


# Given: A valid time window
def _given_valid_time_window():
    """Create a valid time window for testing.

    Returns:
        Valid timedelta object.

    """
    from datetime import timedelta

    return timedelta(hours=24)


# Given: An invalid time window
def _given_invalid_time_window():
    """Create an invalid time window.

    Returns:
        Invalid time window (None).

    """
    return None


# Given: Mock API returns threat data
def _given_mock_api_returns_threat_data(fetcher):
    """Set up mock API to return threat data.

    Args:
        fetcher: The threat fetcher instance to mock.

    """
    from unittest.mock import Mock, patch

    mock_response = Mock()
    mock_response.json.return_value = {
        "data": [
            {
                "threatInfo": {
                    "threatId": "test_threat_1",
                    "computerName": "test-host.example.com",
                    "mitigationStatus": "not_mitigated",
                }
            }
        ]
    }
    mock_response.raise_for_status.return_value = None

    with patch.object(fetcher.client_api.session, "get", return_value=mock_response):
        pass


# Given: API connection will fail
def _given_api_connection_will_fail(fetcher):
    """Set up API connection to fail.

    Args:
        fetcher: The threat fetcher instance to mock.

    """
    from requests.exceptions import ConnectionError
    from unittest.mock import patch

    with patch.object(
        fetcher.client_api.session,
        "get",
        side_effect=ConnectionError("Connection failed"),
    ):
        pass


# --------
# When Methods
# --------


# When: I initialize the threat fetcher
def _when_initialize_threat_fetcher(client_api):
    """Initialize threat fetcher with given client API.

    Args:
        client_api: Client API instance to use.

    Returns:
        Initialized SentinelOneThreatFetcher instance.

    """
    return FetcherThreat(client_api)


# When: I attempt to initialize with invalid client API and expect validation error
def _when_initialize_threat_fetcher_then_validation_error_raised(invalid_client_api):
    """Attempt to initialize with invalid client API and expect validation error.

    Args:
        invalid_client_api: Invalid client API to test.

    """
    with pytest.raises(SentinelOneValidationError):
        FetcherThreat(invalid_client_api)


# When: I fetch threats for the time window
def _when_fetch_threats_for_time_window(fetcher, time_window):
    """Fetch threats for given time window.

    Args:
        fetcher: The threat fetcher instance.
        time_window: Time window to fetch threats for.

    Returns:
        List of fetched threats.

    """
    from datetime import datetime, timezone

    end_time = datetime.now(timezone.utc)
    start_time = end_time - time_window
    return fetcher.fetch_threats_for_time_window(start_time, end_time)


# When: I attempt to fetch threats and expect network error
def _when_fetch_threats_then_network_error_raised(fetcher, time_window):
    """Attempt to fetch threats and expect network error.

    Args:
        fetcher: The threat fetcher instance.
        time_window: Time window to fetch threats for.

    """
    from datetime import datetime, timezone

    end_time = datetime.now(timezone.utc)
    start_time = end_time - time_window
    with pytest.raises(SentinelOneNetworkError):
        fetcher.fetch_threats_for_time_window(start_time, end_time)


# When: I attempt to fetch threats and expect validation error
def _when_fetch_threats_then_validation_error_raised(fetcher, invalid_time_window):
    """Attempt to fetch threats and expect validation error.

    Args:
        fetcher: The threat fetcher instance.
        invalid_time_window: Invalid time window to test.

    """
    from datetime import datetime, timezone

    if invalid_time_window is not None:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - invalid_time_window
        with pytest.raises(SentinelOneValidationError):
            fetcher.fetch_threats_for_time_window(start_time, end_time)
    else:
        with pytest.raises(SentinelOneValidationError):
            fetcher.fetch_threats_for_time_window(None, None)


# --------
# Then Methods
# --------


# Then: The threat fetcher should be initialized successfully
def _then_threat_fetcher_initialized_successfully(fetcher, client_api):
    """Verify threat fetcher was initialized successfully.

    Args:
        fetcher: The threat fetcher instance to verify.
        client_api: The client API used for initialization.

    """
    assert fetcher is not None  # noqa: S101
    assert fetcher.client_api == client_api  # noqa: S101
    assert fetcher.logger is not None  # noqa: S101


# Then: Threats should be returned successfully
def _then_threats_returned_successfully(threats):
    """Verify threats were returned successfully.

    Args:
        threats: The fetched threats to verify.

    """
    assert isinstance(threats, list)  # noqa: S101
    assert len(threats) > 0  # noqa: S101

    # Basic verification that we got threats back
    from src.services.model_threat import SentinelOneThreat

    assert all(isinstance(threat, SentinelOneThreat) for threat in threats)  # noqa: S101
