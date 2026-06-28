"""Essential tests for LogRhythm Client API service."""

from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr
from requests import Session
from src.services.client_api import LogRhythmClientAPI
from src.services.exception import LogRhythmAPIError, LogRhythmAuthenticationError
from src.services.models import LogRhythmSearchCriteria
from tests.services.fixtures.factories import TestDataFactory, create_test_config

PARENT_PROCESS_NAME = (
    "oaev-implant-12345678-1234-1234-1234-123456789abc"
    "-agent-87654321-4321-4321-4321-cba987654321"
)

SIGNATURES = [{"type": "source_ipv4_address", "value": "192.168.1.100"}]


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


class TestLogRhythmClientAPIEssential:
    """Essential test cases for LogRhythmClientAPI."""

    def test_init_with_valid_config(self):
        """Client initializes with config values and a session."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        assert client.config == config  # noqa: S101
        assert client.base_url == str(config.logrhythm.base_url).rstrip(
            "/"
        )  # noqa: S101
        assert client.token == config.logrhythm.token.get_secret_value()  # noqa: S101
        assert isinstance(client.session, Session)  # noqa: S101

    def test_init_without_config_raises_error(self):
        """Initialization without config raises a validation error."""
        from src.services.exception import LogRhythmValidationError

        with pytest.raises(LogRhythmValidationError):
            LogRhythmClientAPI(config=None)

    def test_create_session_with_token(self):
        """A token configures the bearer Authorization header, not basic auth."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        assert (
            client.session.headers["Authorization"] == "Bearer test-token"
        )  # noqa: S101
        assert client.session.auth is None  # noqa: S101

    def test_create_session_with_basic_auth(self):
        """Without a token, username/password configure basic auth."""
        config = create_test_config()
        config.logrhythm.token = None
        config.logrhythm.username = "test-user"
        config.logrhythm.password = SecretStr("test-password")

        client = LogRhythmClientAPI(config=config)

        assert client.session.auth == ("test-user", "test-password")  # noqa: S101
        assert "Authorization" not in client.session.headers  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_detection_success(self, mock_post):
        """A completed search returns parsed alerts."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)
        mock_post.side_effect = [_create_response(), _result_response()]

        result = client.fetch_signatures(SIGNATURES, "detection")

        assert len(result) == 2  # noqa: S101
        assert all(hasattr(alert, "src_ip") for alert in result)  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_builds_query_with_ips(self, mock_post):
        """IP signatures are turned into a filter passed to the search-task API."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)
        mock_post.side_effect = [_create_response(), _result_response()]

        client.fetch_signatures(
            [
                {"type": "source_ipv4_address", "value": "192.168.1.100"},
                {"type": "target_ipv4_address", "value": "10.0.0.50"},
            ],
            "detection",
        )

        body = mock_post.call_args_list[0].kwargs["json"]
        filter_items = body["queryFilter"]["filterGroup"]["filterItems"]
        filter_types = {item["filterType"] for item in filter_items}
        assert 18 in filter_types  # noqa: S101
        assert 19 in filter_types  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_authentication_error(self, mock_post):
        """A 401 on search creation raises LogRhythmAuthenticationError."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        response = Mock()
        response.status_code = 401
        response.text = "Unauthorized"
        mock_post.return_value = response

        with pytest.raises(LogRhythmAuthenticationError):
            client.fetch_signatures(SIGNATURES, "detection")

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_fetch_signatures_no_data_returns_empty(self, mock_post, mock_sleep):
        """No result items yields an empty list."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        empty = Mock()
        empty.status_code = 200
        empty.json.return_value = {"TaskStatus": "Completed", "Items": []}
        mock_post.side_effect = [
            _create_response(),
            empty,
            _create_response(),
            empty,
        ]

        result = client.fetch_signatures(SIGNATURES, "detection")

        assert result == []  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_fetch_signatures_exception_handling(self, mock_post, mock_sleep):
        """Repeated errors are wrapped in LogRhythmAPIError."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        mock_post.side_effect = Exception("Network Error")

        with pytest.raises(LogRhythmAPIError) as exc_info:
            client.fetch_signatures(SIGNATURES, "detection")

        assert "All LogRhythm fetch attempts failed." in str(  # noqa: S101
            exc_info.value
        )

    def test_build_query_body_with_ips(self):
        """Query body building includes IP filter items."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        criteria = LogRhythmSearchCriteria(
            source_ips=["192.168.1.100"], target_ips=["10.0.0.50"]
        )
        body = client._build_query_body(criteria)

        filter_items = body["queryFilter"]["filterGroup"]["filterItems"]
        filter_types = {item["filterType"] for item in filter_items}
        assert 18 in filter_types  # noqa: S101
        assert 19 in filter_types  # noqa: S101
        assert body["dateCriteria"]["lastIntervalValue"] >= 1  # noqa: S101

    def test_build_query_body_with_parent_process(self):
        """Query body building includes a URL filter for parent process."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        criteria = LogRhythmSearchCriteria(
            source_ips=["192.168.1.100"],
            parent_process_names=[PARENT_PROCESS_NAME],
        )
        body = client._build_query_body(criteria)

        filter_items = body["queryFilter"]["filterGroup"]["filterItems"]
        url_items = [item for item in filter_items if item["filterType"] == 42]
        assert len(url_items) == 1  # noqa: S101
        value = url_items[0]["values"][0]["value"]["value"]
        assert "/api/injects/" in value  # noqa: S101
        assert "executable-payload" in value  # noqa: S101

    def test_build_query_body_time_window_extension(self):
        """Retries widen the query time window."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        criteria = LogRhythmSearchCriteria(source_ips=["192.168.1.100"])
        body1 = client._build_query_body(criteria, extend_end_seconds=0)
        body2 = client._build_query_body(criteria, extend_end_seconds=3600)

        assert (  # noqa: S101
            body1["dateCriteria"]["lastIntervalValue"]
            != body2["dateCriteria"]["lastIntervalValue"]
        )

    def test_build_search_criteria_from_signatures(self):
        """Signatures are extracted into a LogRhythmSearchCriteria object."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

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
        from src.services.exception import LogRhythmValidationError

        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        with pytest.raises(LogRhythmValidationError) as exc_info:
            client.fetch_signatures(SIGNATURES, "prevention")

        assert "Invalid expectation_type" in str(exc_info.value)  # noqa: S101

    def test_parent_process_uuid_extraction(self):
        """UUIDs are extracted from a parent process name."""
        config = create_test_config()
        client = LogRhythmClientAPI(config=config)

        uuids = client.parent_process_parser.extract_uuids_from_parent_process_name(
            PARENT_PROCESS_NAME
        )

        assert uuids is not None  # noqa: S101
        inject_uuid, agent_uuid = uuids
        assert inject_uuid == "12345678-1234-1234-1234-123456789abc"  # noqa: S101
        assert agent_uuid == "87654321-4321-4321-4321-cba987654321"  # noqa: S101
