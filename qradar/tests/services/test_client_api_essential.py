"""Essential tests for IBM QRadar Client API service."""

from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr
from requests import Session
from src.services.client_api import QRadarClientAPI
from src.services.exception import QRadarAPIError, QRadarAuthenticationError
from src.services.models import QRadarSearchCriteria
from tests.services.fixtures.factories import TestDataFactory, create_test_config

PARENT_PROCESS_NAME = (
    "oaev-implant-12345678-1234-1234-1234-123456789abc"
    "-agent-87654321-4321-4321-4321-cba987654321"
)


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


class TestQRadarClientAPIEssential:
    """Essential test cases for QRadarClientAPI."""

    def test_init_with_valid_config(self):
        """Client initializes with config values and a session."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        assert client.config == config  # noqa: S101
        assert client.base_url == str(config.qradar.base_url).rstrip("/")  # noqa: S101
        assert client.token == config.qradar.token.get_secret_value()  # noqa: S101
        assert isinstance(client.session, Session)  # noqa: S101

    def test_init_without_config_raises_error(self):
        """Initialization without config raises a validation error."""
        from src.services.exception import QRadarValidationError

        with pytest.raises(QRadarValidationError):
            QRadarClientAPI(config=None)

    def test_create_session_with_token(self):
        """A token configures the SEC header and version, not basic auth."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        assert client.session.headers["SEC"] == "test-token"  # noqa: S101
        assert (
            client.session.headers["Version"] == config.qradar.api_version
        )  # noqa: S101
        assert client.session.auth is None  # noqa: S101

    def test_create_session_with_basic_auth(self):
        """Without a token, username/password configure basic auth."""
        config = create_test_config()
        config.qradar.token = None
        config.qradar.username = "test-user"
        config.qradar.password = SecretStr("test-password")

        client = QRadarClientAPI(config=config)

        assert client.session.auth == ("test-user", "test-password")  # noqa: S101
        assert "SEC" not in client.session.headers  # noqa: S101

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_fetch_signatures_detection_success(self, mock_post, mock_get):
        """A completed Ariel search returns parsed alerts."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        mock_post.return_value = _create_response()
        mock_get.side_effect = [_status_response(), _results_response()]

        result = client.fetch_signatures(
            [{"type": "source_ipv4_address", "value": "192.168.1.100"}], "detection"
        )

        assert len(result) == 2  # noqa: S101
        assert all(hasattr(alert, "src_ip") for alert in result)  # noqa: S101

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_fetch_signatures_builds_aql_with_ips(self, mock_post, mock_get):
        """IP signatures are turned into an AQL query passed to the search API."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        mock_post.return_value = _create_response()
        mock_get.side_effect = [_status_response(), _results_response()]

        client.fetch_signatures(
            [
                {"type": "source_ipv4_address", "value": "192.168.1.100"},
                {"type": "target_ipv4_address", "value": "10.0.0.50"},
            ],
            "detection",
        )

        aql = mock_post.call_args.kwargs["params"]["query_expression"]
        assert "sourceip='192.168.1.100'" in aql  # noqa: S101
        assert "destinationip='10.0.0.50'" in aql  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_authentication_error(self, mock_post):
        """A 401 on search creation raises QRadarAuthenticationError."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        response = Mock()
        response.status_code = 401
        response.text = "Unauthorized"
        mock_post.return_value = response

        with pytest.raises(QRadarAuthenticationError):
            client.fetch_signatures(
                [{"type": "source_ipv4_address", "value": "1.2.3.4"}], "detection"
            )

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_fetch_signatures_no_data_returns_empty(self, mock_post, mock_get):
        """No result rows yields an empty list."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"events": []}
        mock_post.return_value = _create_response()
        # Two attempts (max_retry=1), each polls status then fetches results.
        mock_get.side_effect = [_status_response(), empty, _status_response(), empty]

        result = client.fetch_signatures(
            [{"type": "source_ipv4_address", "value": "1.2.3.4"}], "detection"
        )

        assert result == []  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_fetch_signatures_exception_handling(self, mock_post, mock_sleep):
        """Repeated errors are wrapped in QRadarAPIError."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        mock_post.side_effect = Exception("Network Error")

        with pytest.raises(QRadarAPIError) as exc_info:
            client.fetch_signatures(
                [{"type": "source_ipv4_address", "value": "1.2.3.4"}], "detection"
            )

        assert "All IBM QRadar fetch attempts failed." in str(  # noqa: S101
            exc_info.value
        )

    def test_build_aql_with_ips(self):
        """AQL building includes IP conditions and the time window."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        criteria = QRadarSearchCriteria(
            source_ips=["192.168.1.100"], target_ips=["10.0.0.50"]
        )
        aql = client._build_aql(criteria)

        assert "sourceip='192.168.1.100'" in aql  # noqa: S101
        assert "destinationip='10.0.0.50'" in aql  # noqa: S101
        assert "FROM events" in aql  # noqa: S101
        assert "LAST" in aql and "MINUTES" in aql  # noqa: S101

    def test_build_aql_with_parent_process(self):
        """AQL building includes a URL LIKE clause for parent process matching."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        criteria = QRadarSearchCriteria(
            source_ips=["192.168.1.100"],
            parent_process_names=[PARENT_PROCESS_NAME],
        )
        aql = client._build_aql(criteria)

        assert '"URL" LIKE' in aql  # noqa: S101
        assert "/api/injects/" in aql  # noqa: S101
        assert "executable-payload" in aql  # noqa: S101

    def test_build_aql_time_window_extension(self):
        """Retries widen the AQL time window."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        criteria = QRadarSearchCriteria(source_ips=["192.168.1.100"])
        aql1 = client._build_aql(criteria, extend_end_seconds=0)
        aql2 = client._build_aql(criteria, extend_end_seconds=3600)

        assert aql1 != aql2  # noqa: S101

    def test_build_search_criteria_from_signatures(self):
        """Signatures are extracted into a QRadarSearchCriteria object."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        criteria = client._build_search_criteria(
            [
                {"type": "source_ipv4_address", "value": "192.168.1.100"},
                {"type": "target_ipv6_address", "value": "2001:db8::1"},
                {"type": "parent_process_name", "value": PARENT_PROCESS_NAME},
                {"type": "start_date", "value": "2024-01-01T00:00:00Z"},
                {"type": "end_date", "value": "2024-01-01T23:59:59Z"},
            ]
        )

        assert criteria.source_ips == ["192.168.1.100"]  # noqa: S101
        assert criteria.target_ips == ["2001:db8::1"]  # noqa: S101
        assert criteria.parent_process_names == [PARENT_PROCESS_NAME]  # noqa: S101
        assert criteria.start_date == "2024-01-01T00:00:00Z"  # noqa: S101
        assert criteria.end_date == "2024-01-01T23:59:59Z"  # noqa: S101

    def test_prevention_expectation_not_supported(self):
        """Prevention expectations raise a validation error."""
        from src.services.exception import QRadarValidationError

        config = create_test_config()
        client = QRadarClientAPI(config=config)

        with pytest.raises(QRadarValidationError) as exc_info:
            client.fetch_signatures(
                [{"type": "source_ipv4_address", "value": "1.2.3.4"}], "prevention"
            )

        assert "Invalid expectation_type" in str(exc_info.value)  # noqa: S101

    def test_parent_process_uuid_extraction(self):
        """UUIDs are extracted from a parent process name."""
        config = create_test_config()
        client = QRadarClientAPI(config=config)

        uuids = client.parent_process_parser.extract_uuids_from_parent_process_name(
            PARENT_PROCESS_NAME
        )

        assert uuids is not None  # noqa: S101
        inject_uuid, agent_uuid = uuids
        assert inject_uuid == "12345678-1234-1234-1234-123456789abc"  # noqa: S101
        assert agent_uuid == "87654321-4321-4321-4321-cba987654321"  # noqa: S101
