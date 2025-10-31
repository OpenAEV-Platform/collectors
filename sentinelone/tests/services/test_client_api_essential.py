"""Essential tests for SentinelOne Client API service."""

from unittest.mock import Mock

import pytest
from requests import Session
from src.services.client_api import SentinelOneClientAPI
from src.services.exception import SentinelOneAPIError
from tests.services.fixtures.factories import (
    TestDataFactory,
    create_test_config,
    create_test_dv_events,
    create_test_threats,
)


class TestSentinelOneClientAPIEssential:
    """Essential test cases for SentinelOneClientAPI.

    Tests the core functionality of the SentinelOne client API including
    initialization, session creation, and signature fetching operations.
    """

    def test_init_with_valid_config(self):
        """Test that SentinelOneClientAPI initializes correctly with valid config.

        Verifies that the client properly initializes with configuration values,
        creates session with authentication, and sets up fetcher components.
        """
        config = create_test_config()

        client = SentinelOneClientAPI(config=config)

        assert client.config == config  # noqa: S101
        assert client.base_url == str(config.sentinelone.base_url).rstrip(  # noqa: S101
            "/"
        )
        assert (  # noqa: S101
            client.api_key == config.sentinelone.api_key.get_secret_value()
        )
        assert isinstance(client.session, Session)  # noqa: S101
        assert client.dv_fetcher is not None  # noqa: S101
        assert client.threat_fetcher is not None  # noqa: S101

    def test_create_session_with_api_key(self):
        """Test session creation with API key.

        Verifies that the HTTP session is properly configured with
        authentication headers and content type settings.
        """
        config = create_test_config()

        client = SentinelOneClientAPI(config=config)

        expected_auth = f"ApiToken {config.sentinelone.api_key.get_secret_value()}"
        assert client.session.headers["Authorization"] == expected_auth  # noqa: S101
        assert (  # noqa: S101
            client.session.headers["Content-Type"] == "application/json"
        )

    def test_fetch_signatures_detection_success(self):
        """Test successful signature fetching for detection expectation.

        Verifies that detection expectations fetch both Deep Visibility events
        and related threat data for unified analysis.
        """
        config = create_test_config()
        client = SentinelOneClientAPI(config=config)

        mock_dv_events = create_test_dv_events(count=2)
        mock_threats = create_test_threats(count=1)
        client.dv_fetcher.fetch_with_retry = Mock(return_value=mock_dv_events)
        client.threat_fetcher.fetch_with_retry = Mock(return_value=mock_threats)

        search_signatures = TestDataFactory.create_expectation_signatures()

        result = client.fetch_signatures(search_signatures, "detection")

        assert len(result) == 3  # 2 DV events + 1 threat  # noqa: S101
        client.dv_fetcher.fetch_with_retry.assert_called_once()  # noqa: S101
        client.threat_fetcher.fetch_with_retry.assert_called_once()  # noqa: S101

    def test_fetch_signatures_prevention_success(self):
        """Test successful signature fetching for prevention expectation.

        Verifies that prevention expectations fetch both Deep Visibility events
        and related threat data, combining them in the result.
        """
        config = create_test_config()
        client = SentinelOneClientAPI(config=config)

        mock_dv_events = create_test_dv_events(count=2)
        mock_threats = create_test_threats(count=1)
        client.dv_fetcher.fetch_with_retry = Mock(return_value=mock_dv_events)
        client.threat_fetcher.fetch_with_retry = Mock(return_value=mock_threats)

        search_signatures = TestDataFactory.create_expectation_signatures()

        result = client.fetch_signatures(search_signatures, "prevention")

        assert len(result) == 3  # 2 DV events + 1 threat  # noqa: S101
        client.dv_fetcher.fetch_with_retry.assert_called_once()
        client.threat_fetcher.fetch_with_retry.assert_called_once()

    def test_fetch_signatures_no_data_returns_empty(self):
        """Test behavior when no data is found.

        Verifies that when no Deep Visibility events are found,
        the method returns empty list and skips threat fetching.
        """
        config = create_test_config()
        client = SentinelOneClientAPI(config=config)

        client.dv_fetcher.fetch_with_retry = Mock(return_value=[])
        client.threat_fetcher.fetch_with_retry = Mock(return_value=[])

        search_signatures = TestDataFactory.create_expectation_signatures()

        result = client.fetch_signatures(search_signatures, "prevention")

        assert result == []  # noqa: S101
        client.dv_fetcher.fetch_with_retry.assert_called_once()
        client.threat_fetcher.fetch_with_retry.assert_not_called()

    def test_fetch_signatures_exception_handling(self):
        """Test exception handling in fetch_signatures.

        Verifies that API errors are properly caught and wrapped
        in SentinelOneAPIError with descriptive error messages.
        """
        config = create_test_config()
        client = SentinelOneClientAPI(config=config)

        client.dv_fetcher.fetch_with_retry = Mock(side_effect=Exception("API Error"))

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(SentinelOneAPIError) as exc_info:
            client.fetch_signatures(search_signatures, "detection")

        assert "Unexpected error fetching signatures: API Error" in str(  # noqa: S101
            exc_info.value
        )
