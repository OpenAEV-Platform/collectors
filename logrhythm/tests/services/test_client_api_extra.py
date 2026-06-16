"""Additional branch-coverage tests for LogRhythmClientAPI."""

from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
import requests
from src.services.client_api import LogRhythmClientAPI
from src.services.exception import LogRhythmAPIError, LogRhythmValidationError
from tests.services.fixtures.factories import TestDataFactory, create_test_config

SIGNATURES = [{"type": "source_ipv4_address", "value": "1.2.3.4"}]


def _create_response() -> Mock:
    """Mock search-task creation response."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"TaskId": "task-123", "TaskStatus": "Submitted"}
    return response


def _result_response(status: str = "Completed") -> Mock:
    """Mock search-result response with items."""
    response = Mock()
    response.status_code = 200
    data = TestDataFactory.create_api_response_data()
    data["TaskStatus"] = status
    response.json.return_value = data
    return response


def _status_only_response(status: str) -> Mock:
    """Mock search-result response carrying only a status (no items)."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"TaskStatus": status}
    return response


class TestLogRhythmClientAPIExtra:
    """Branch-coverage tests for LogRhythmClientAPI."""

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_network_error_wrapped(self, mock_post, mock_sleep):
        """Connection errors are retried then wrapped in LogRhythmAPIError."""
        client = LogRhythmClientAPI(config=create_test_config())
        mock_post.side_effect = requests.exceptions.ConnectionError("net down")

        with pytest.raises(LogRhythmAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_server_error_status(self, mock_post, mock_sleep):
        """A 500 on search creation is retried then wrapped in LogRhythmAPIError."""
        client = LogRhythmClientAPI(config=create_test_config())
        response = Mock()
        response.status_code = 500
        response.text = "server error"
        mock_post.return_value = response

        with pytest.raises(LogRhythmAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_search_failed_status(self, mock_post, mock_sleep):
        """A Failed task status is wrapped in LogRhythmAPIError after retries."""
        client = LogRhythmClientAPI(config=create_test_config())
        mock_post.side_effect = [
            _create_response(),
            _status_only_response("Failed"),
            _create_response(),
            _status_only_response("Failed"),
        ]

        with pytest.raises(LogRhythmAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_search_timeout(self, mock_post, mock_sleep):
        """A search that never completes raises (timeout) then LogRhythmAPIError."""
        config = create_test_config()
        config.logrhythm.search_timeout = timedelta(seconds=0)
        client = LogRhythmClientAPI(config=config)
        mock_post.return_value = _create_response()

        with pytest.raises(LogRhythmAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_searching_then_completed(self, mock_post, mock_sleep):
        """A Searching status is polled until Completed, then items are returned."""
        client = LogRhythmClientAPI(config=create_test_config())
        mock_post.side_effect = [
            _create_response(),
            _status_only_response("Searching"),
            _result_response("Completed"),
        ]

        result = client.fetch_signatures(SIGNATURES, "detection")

        assert len(result) == 2  # noqa: S101

    def test_fetch_with_retry_empty_signatures(self):
        """Empty signatures raise a validation error."""
        client = LogRhythmClientAPI(config=create_test_config())
        with pytest.raises(LogRhythmValidationError):
            client.fetch_with_retry([], "detection")

    def test_fetch_with_retry_invalid_type(self):
        """Non-detection expectation types raise a validation error."""
        client = LogRhythmClientAPI(config=create_test_config())
        with pytest.raises(LogRhythmValidationError):
            client.fetch_with_retry(SIGNATURES, "prevention")

    @patch("requests.Session.post")
    def test_fetch_with_retry_success(self, mock_post):
        """A successful search yields parsed alerts."""
        client = LogRhythmClientAPI(config=create_test_config())
        mock_post.side_effect = [_create_response(), _result_response()]

        result = client.fetch_with_retry(SIGNATURES, "detection")

        assert len(result) == 2  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_fetch_with_retry_empty_returns_empty(self, mock_post, mock_sleep):
        """No result items after all retries returns an empty list."""
        client = LogRhythmClientAPI(config=create_test_config())
        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"TaskStatus": "Completed", "Items": []}
        mock_post.side_effect = [
            _create_response(),
            empty,
            _create_response(),
            empty,
        ]

        result = client.fetch_with_retry(SIGNATURES, "detection")

        assert result == []  # noqa: S101
