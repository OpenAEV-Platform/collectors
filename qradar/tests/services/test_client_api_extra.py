"""Additional branch-coverage tests for QRadarClientAPI."""

from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
import requests
from src.services.client_api import QRadarClientAPI
from src.services.exception import QRadarAPIError, QRadarValidationError
from tests.services.fixtures.factories import TestDataFactory, create_test_config

SIGNATURES = [{"type": "source_ipv4_address", "value": "1.2.3.4"}]


def _create_response() -> Mock:
    """Mock Ariel search creation response."""
    response = Mock()
    response.status_code = 201
    response.json.return_value = {"search_id": "abc123"}
    return response


def _status_response(status: str = "COMPLETED") -> Mock:
    """Mock Ariel search status response."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"status": status}
    return response


def _results_response() -> Mock:
    """Mock Ariel search results response."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = TestDataFactory.create_api_response_data()
    return response


class TestQRadarClientAPIExtra:
    """Branch-coverage tests for QRadarClientAPI."""

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_network_error_wrapped(self, mock_post, mock_sleep):
        """Connection errors are retried then wrapped in QRadarAPIError."""
        client = QRadarClientAPI(config=create_test_config())
        mock_post.side_effect = requests.exceptions.ConnectionError("net down")

        with pytest.raises(QRadarAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_server_error_status(self, mock_post, mock_sleep):
        """A 500 on search creation is retried then wrapped in QRadarAPIError."""
        client = QRadarClientAPI(config=create_test_config())
        response = Mock()
        response.status_code = 500
        response.text = "server error"
        mock_post.return_value = response

        with pytest.raises(QRadarAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_search_error_status(self, mock_post, mock_get, mock_sleep):
        """An Ariel ERROR status is wrapped in QRadarAPIError after retries."""
        client = QRadarClientAPI(config=create_test_config())
        mock_post.return_value = _create_response()
        mock_get.return_value = _status_response("ERROR")

        with pytest.raises(QRadarAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_search_timeout(self, mock_post, mock_sleep):
        """A search that never completes raises (timeout) then QRadarAPIError."""
        config = create_test_config()
        config.qradar.search_timeout = timedelta(seconds=0)
        client = QRadarClientAPI(config=config)
        mock_post.return_value = _create_response()

        with pytest.raises(QRadarAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_running_then_completed(self, mock_post, mock_get, mock_sleep):
        """A RUNNING status is polled until COMPLETED, then results are returned."""
        client = QRadarClientAPI(config=create_test_config())
        mock_post.return_value = _create_response()
        mock_get.side_effect = [
            _status_response("RUNNING"),
            _status_response("COMPLETED"),
            _results_response(),
        ]

        result = client.fetch_signatures(SIGNATURES, "detection")

        assert len(result) == 2  # noqa: S101

    def test_fetch_with_retry_empty_signatures(self):
        """Empty signatures raise a validation error."""
        client = QRadarClientAPI(config=create_test_config())
        with pytest.raises(QRadarValidationError):
            client.fetch_with_retry([], "detection")

    def test_fetch_with_retry_invalid_type(self):
        """Non-detection expectation types raise a validation error."""
        client = QRadarClientAPI(config=create_test_config())
        with pytest.raises(QRadarValidationError):
            client.fetch_with_retry(SIGNATURES, "prevention")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_fetch_with_retry_date_only_fails_fast(self, mock_post, mock_sleep):
        """Date-only signatures fail fast: no Ariel search and no retry.

        Regression test for the ``WHERE (1=1)`` fallback: a criteria with no
        concrete search key must raise QRadarValidationError before any query
        is created, and the error must not be retried (it is re-raised as-is by
        the retry loop, not wrapped into a retriable QRadarAPIError).
        """
        client = QRadarClientAPI(config=create_test_config())

        with pytest.raises(QRadarValidationError):
            client.fetch_with_retry(
                [
                    {"type": "start_date", "value": "2024-01-01T00:00:00Z"},
                    {"type": "end_date", "value": "2024-01-01T23:59:59Z"},
                ],
                "detection",
            )

        mock_post.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_fetch_with_retry_success(self, mock_post, mock_get):
        """A successful Ariel search yields parsed alerts."""
        client = QRadarClientAPI(config=create_test_config())
        mock_post.return_value = _create_response()
        mock_get.side_effect = [_status_response(), _results_response()]

        result = client.fetch_with_retry(SIGNATURES, "detection")

        assert len(result) == 2  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_fetch_with_retry_empty_returns_empty(
        self, mock_post, mock_get, mock_sleep
    ):
        """No result rows after all retries returns an empty list."""
        client = QRadarClientAPI(config=create_test_config())
        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"events": []}
        mock_post.return_value = _create_response()
        mock_get.side_effect = [
            _status_response(),
            empty,
            _status_response(),
            empty,
        ]

        result = client.fetch_with_retry(SIGNATURES, "detection")

        assert result == []  # noqa: S101
