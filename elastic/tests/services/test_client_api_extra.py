"""Additional branch-coverage tests for ElasticClientAPI."""

from unittest.mock import Mock, patch

import pytest
import requests
from src.services.client_api import ElasticClientAPI
from src.services.exception import ElasticAPIError, ElasticValidationError
from tests.services.fixtures.factories import TestDataFactory, create_test_config

SIGNATURES = [{"type": "source_ipv4_address", "value": "1.2.3.4"}]


class TestElasticClientAPIExtra:
    """Branch-coverage tests for ElasticClientAPI."""

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_network_error_wrapped(self, mock_post, mock_sleep):
        """Connection errors are retried then wrapped in ElasticAPIError."""
        client = ElasticClientAPI(config=create_test_config())
        mock_post.side_effect = requests.exceptions.ConnectionError("net down")

        with pytest.raises(ElasticAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_server_error_status(self, mock_post, mock_sleep):
        """A 500 response is retried then wrapped in ElasticAPIError."""
        client = ElasticClientAPI(config=create_test_config())
        response = Mock()
        response.status_code = 500
        response.text = "server error"
        mock_post.return_value = response

        with pytest.raises(ElasticAPIError):
            client.fetch_signatures(SIGNATURES, "detection")

    def test_fetch_with_retry_empty_signatures(self):
        """Empty signatures raise a validation error."""
        client = ElasticClientAPI(config=create_test_config())
        with pytest.raises(ElasticValidationError):
            client.fetch_with_retry([], "detection")

    def test_fetch_with_retry_invalid_type(self):
        """Non-detection expectation types raise a validation error."""
        client = ElasticClientAPI(config=create_test_config())
        with pytest.raises(ElasticValidationError):
            client.fetch_with_retry(SIGNATURES, "prevention")

    @patch("requests.Session.post")
    def test_fetch_with_retry_success(self, mock_post):
        """A successful response yields parsed alerts."""
        client = ElasticClientAPI(config=create_test_config())
        response = Mock()
        response.status_code = 200
        response.json.return_value = TestDataFactory.create_api_response_data()
        mock_post.return_value = response

        result = client.fetch_with_retry(SIGNATURES, "detection")

        assert len(result) == 2  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_fetch_with_retry_empty_returns_empty(self, mock_post, mock_sleep):
        """No hits after all retries returns an empty list."""
        client = ElasticClientAPI(config=create_test_config())
        response = Mock()
        response.status_code = 200
        response.json.return_value = {"hits": {"hits": []}}
        mock_post.return_value = response

        result = client.fetch_with_retry(SIGNATURES, "detection")

        assert result == []  # noqa: S101
