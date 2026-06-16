"""Essential tests for NetWitness Client API service."""

from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr
from requests import Session
from src.services.client_api import NetWitnessClientAPI
from src.services.exception import (
    NetWitnessAPIError,
    NetWitnessAuthenticationError,
    NetWitnessValidationError,
)
from src.services.models import NetWitnessSearchCriteria
from tests.services.fixtures.factories import TestDataFactory, create_test_config

PARENT_PROCESS_NAME = (
    "oaev-implant-12345678-1234-1234-1234-123456789abc"
    "-agent-87654321-4321-4321-4321-cba987654321"
)

SIGNATURES = [{"type": "source_ipv4_address", "value": "192.168.1.100"}]


def _ok_response() -> Mock:
    """Mock a successful SDK query response."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = TestDataFactory.create_api_response_data()
    return response


class TestNetWitnessClientAPIEssential:
    """Essential test cases for NetWitnessClientAPI."""

    def test_init_with_valid_config(self):
        """Client initializes with config values and a session."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        assert client.config == config  # noqa: S101
        assert client.base_url == str(config.netwitness.base_url).rstrip(
            "/"
        )  # noqa: S101
        assert client.username == config.netwitness.username  # noqa: S101
        assert (  # noqa: S101
            client.password == config.netwitness.password.get_secret_value()
        )
        assert isinstance(client.session, Session)  # noqa: S101

    def test_init_without_config_raises_error(self):
        """Initialization without config raises a validation error."""
        with pytest.raises(NetWitnessValidationError):
            NetWitnessClientAPI(config=None)

    def test_create_session_with_basic_auth(self):
        """Username/password configure HTTP basic auth, not a bearer header."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        assert client.session.auth == ("test-user", "test-password")  # noqa: S101
        assert "Authorization" not in client.session.headers  # noqa: S101

    def test_create_session_with_token(self):
        """A token configures the bearer Authorization header."""
        config = create_test_config()
        config.netwitness.token = SecretStr("my-token")
        client = NetWitnessClientAPI(config=config)

        assert (
            client.session.headers["Authorization"] == "Bearer my-token"
        )  # noqa: S101

    @patch("requests.Session.get")
    def test_fetch_signatures_detection_success(self, mock_get):
        """A successful query returns parsed alerts grouped by session."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)
        mock_get.return_value = _ok_response()

        result = client.fetch_signatures(SIGNATURES, "detection")

        assert len(result) == 2  # noqa: S101
        assert result[0].src_ip == "192.168.1.100"  # noqa: S101
        assert result[0].dst_ip == "10.0.0.50"  # noqa: S101

    @patch("requests.Session.get")
    def test_fetch_signatures_builds_query_with_ips(self, mock_get):
        """IP signatures are turned into an NWQL query passed to the SDK."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)
        mock_get.return_value = _ok_response()

        client.fetch_signatures(
            [
                {"type": "source_ipv4_address", "value": "192.168.1.100"},
                {"type": "target_ipv4_address", "value": "10.0.0.50"},
            ],
            "detection",
        )

        query = mock_get.call_args.kwargs["params"]["query"]
        assert "ip.src=192.168.1.100" in query  # noqa: S101
        assert "ip.dst=10.0.0.50" in query  # noqa: S101

    @patch("requests.Session.get")
    def test_fetch_signatures_authentication_error(self, mock_get):
        """A 401 raises NetWitnessAuthenticationError."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        response = Mock()
        response.status_code = 401
        response.text = "Unauthorized"
        mock_get.return_value = response

        with pytest.raises(NetWitnessAuthenticationError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.get")
    def test_fetch_signatures_no_data_returns_empty(self, mock_get, mock_sleep):
        """No result fields yields an empty list."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"results": {"fields": []}}
        mock_get.return_value = empty

        result = client.fetch_signatures(SIGNATURES, "detection")

        assert result == []  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.get")
    def test_fetch_signatures_exception_handling(self, mock_get, mock_sleep):
        """Repeated errors are wrapped in NetWitnessAPIError."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        mock_get.side_effect = Exception("Network Error")

        with pytest.raises(NetWitnessAPIError) as exc_info:
            client.fetch_signatures(SIGNATURES, "detection")

        assert "All NetWitness fetch attempts failed." in str(  # noqa: S101
            exc_info.value
        )

    def test_build_query_with_ips(self):
        """NWQL building includes IP conditions and a time range."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        criteria = NetWitnessSearchCriteria(
            source_ips=["192.168.1.100"], target_ips=["10.0.0.50"]
        )
        query = client._build_query(criteria)

        assert "ip.src=192.168.1.100" in query  # noqa: S101
        assert "ip.dst=10.0.0.50" in query  # noqa: S101
        assert query.startswith("select ")  # noqa: S101
        assert "time=" in query  # noqa: S101

    def test_build_query_with_parent_process(self):
        """NWQL building includes a URL contains clause for parent process."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        criteria = NetWitnessSearchCriteria(
            source_ips=["192.168.1.100"],
            parent_process_names=[PARENT_PROCESS_NAME],
        )
        query = client._build_query(criteria)

        assert "url contains" in query  # noqa: S101
        assert "/api/injects/" in query  # noqa: S101
        assert "executable-payload" in query  # noqa: S101

    def test_build_query_time_window_extension(self):
        """Retries widen the NWQL time window."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        criteria = NetWitnessSearchCriteria(source_ips=["192.168.1.100"])
        query1 = client._build_query(criteria, extend_end_seconds=0)
        query2 = client._build_query(criteria, extend_end_seconds=86400)

        assert query1 != query2  # noqa: S101

    def test_build_search_criteria_from_signatures(self):
        """Signatures are extracted into a NetWitnessSearchCriteria object."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

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
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        with pytest.raises(NetWitnessValidationError) as exc_info:
            client.fetch_signatures(SIGNATURES, "prevention")

        assert "Invalid expectation_type" in str(exc_info.value)  # noqa: S101

    def test_parent_process_uuid_extraction(self):
        """UUIDs are extracted from a parent process name."""
        config = create_test_config()
        client = NetWitnessClientAPI(config=config)

        uuids = client.parent_process_parser.extract_uuids_from_parent_process_name(
            PARENT_PROCESS_NAME
        )

        assert uuids is not None  # noqa: S101
        inject_uuid, agent_uuid = uuids
        assert inject_uuid == "12345678-1234-1234-1234-123456789abc"  # noqa: S101
        assert agent_uuid == "87654321-4321-4321-4321-cba987654321"  # noqa: S101
