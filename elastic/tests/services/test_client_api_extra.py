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


class TestCheckConnectivity:
    """Startup connectivity check: never raises, logs the outcome."""

    @staticmethod
    def _client() -> ElasticClientAPI:
        client = ElasticClientAPI(config=create_test_config())
        client.logger = Mock()
        return client

    @staticmethod
    def _response(status_code: int, count: int = 0) -> Mock:
        response = Mock()
        response.status_code = status_code
        response.json.return_value = {"count": count}
        response.text = ""
        return response

    @patch("requests.Session.get")
    def test_reachable_index_logs_success(self, mock_get):
        """A 200 on the alerts index is reported at info with the alert count."""
        # Arrange
        client = self._client()
        mock_get.return_value = self._response(200, count=42)

        # Act
        result = client.check_connectivity()

        # Assert
        assert result is True  # noqa: S101
        assert mock_get.call_args.args[0].endswith(  # noqa: S101
            f"/{client.alerts_index}/_count"
        )
        message = client.logger.info.call_args.args[0]
        assert "Connected to Elastic" in message  # noqa: S101
        assert "42 alert(s)" in message  # noqa: S101
        client.logger.error.assert_not_called()

    @pytest.mark.parametrize(
        ("status_code", "expected"),
        [
            (401, "Authentication with Elastic Security failed"),
            (403, "Authorization failed (403)"),
            (404, "not found (404)"),
            (500, "returned status 500"),
        ],
    )
    @patch("requests.Session.get")
    def test_error_status_logs_error_without_raising(
        self, mock_get, status_code, expected
    ):
        """An error status is reported at error with the actionable reason."""
        # Arrange
        client = self._client()
        mock_get.return_value = self._response(status_code)

        # Act
        result = client.check_connectivity()

        # Assert
        assert result is False  # noqa: S101
        assert expected in client.logger.error.call_args.args[0]  # noqa: S101

    @pytest.mark.parametrize(
        "error",
        [
            requests.exceptions.ConnectionError("Connection refused"),
            requests.exceptions.SSLError("certificate verify failed"),
            requests.exceptions.Timeout("timed out"),
        ],
        ids=["refused", "tls", "timeout"],
    )
    @patch("requests.Session.get")
    def test_unreachable_cluster_logs_error_without_raising(self, mock_get, error):
        """A network or TLS failure is reported at error, never raised."""
        # Arrange
        client = self._client()
        mock_get.side_effect = error

        # Act
        result = client.check_connectivity()

        # Assert
        assert result is False  # noqa: S101
        message = client.logger.error.call_args.args[0]
        assert "cannot reach" in message  # noqa: S101
        assert str(error) in message  # noqa: S101

    @patch("requests.Session.get")
    def test_credentials_in_base_url_are_redacted(self, mock_get):
        """Credentials embedded in the base URL never reach the logs."""
        # Arrange
        client = self._client()
        client.base_url = "https://elastic:s3cr3t@es.example.com:9200"
        mock_get.side_effect = requests.exceptions.ConnectionError("refused")

        # Act
        client.check_connectivity()

        # Assert
        message = client.logger.error.call_args.args[0]
        assert "s3cr3t" not in message  # noqa: S101
        assert "es.example.com:9200" in message  # noqa: S101
