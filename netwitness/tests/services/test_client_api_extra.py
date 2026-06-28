"""Additional branch-coverage tests for NetWitnessClientAPI."""

from unittest.mock import Mock, patch

import pytest
import requests
from src.services.client_api import NetWitnessClientAPI
from src.services.exception import NetWitnessAPIError, NetWitnessValidationError
from tests.services.fixtures.factories import TestDataFactory, create_test_config

SIGNATURES = [{"type": "source_ipv4_address", "value": "1.2.3.4"}]


def _ok_response() -> Mock:
    """Mock a successful SDK query response."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = TestDataFactory.create_api_response_data()
    return response


class TestNetWitnessClientAPIExtra:
    """Branch-coverage tests for NetWitnessClientAPI."""

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.get")
    def test_network_error_wrapped(self, mock_get, mock_sleep):
        """Connection errors are retried then wrapped in NetWitnessAPIError."""
        client = NetWitnessClientAPI(config=create_test_config())
        mock_get.side_effect = requests.exceptions.ConnectionError("net down")

        with pytest.raises(NetWitnessAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.get")
    def test_server_error_status(self, mock_get, mock_sleep):
        """A 500 response is retried then wrapped in NetWitnessAPIError."""
        client = NetWitnessClientAPI(config=create_test_config())
        response = Mock()
        response.status_code = 500
        response.text = "server error"
        mock_get.return_value = response

        with pytest.raises(NetWitnessAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    def test_fetch_with_retry_empty_signatures(self):
        """Empty signatures raise a validation error."""
        client = NetWitnessClientAPI(config=create_test_config())
        with pytest.raises(NetWitnessValidationError):
            client.fetch_with_retry([], "detection")

    def test_fetch_with_retry_invalid_type(self):
        """Non-detection expectation types raise a validation error."""
        client = NetWitnessClientAPI(config=create_test_config())
        with pytest.raises(NetWitnessValidationError):
            client.fetch_with_retry(SIGNATURES, "prevention")

    @patch("requests.Session.get")
    def test_fetch_with_retry_success(self, mock_get):
        """A successful query yields parsed alerts."""
        client = NetWitnessClientAPI(config=create_test_config())
        mock_get.return_value = _ok_response()

        result = client.fetch_with_retry(SIGNATURES, "detection")

        assert len(result) == 2  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.get")
    def test_fetch_with_retry_empty_returns_empty(self, mock_get, mock_sleep):
        """No result fields after all retries returns an empty list."""
        client = NetWitnessClientAPI(config=create_test_config())
        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"results": {"fields": []}}
        mock_get.return_value = empty

        result = client.fetch_with_retry(SIGNATURES, "detection")

        assert result == []  # noqa: S101
