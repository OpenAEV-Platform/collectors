"""Essential tests for Elastic Security Client API service."""

from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr
from requests import Session
from src.services.client_api import ElasticClientAPI
from src.services.exception import (
    ElasticAPIError,
    ElasticAuthenticationError,
    ElasticValidationError,
)
from src.services.models import ElasticSearchCriteria
from tests.services.fixtures.factories import TestDataFactory, create_test_config

PARENT_PROCESS_NAME = (
    "oaev-implant-12345678-1234-1234-1234-123456789abc"
    "-agent-87654321-4321-4321-4321-cba987654321"
)


class TestElasticClientAPIEssential:
    """Essential test cases for ElasticClientAPI.

    Tests the core functionality of the Elastic Security client API including
    initialization, session creation, query building, and fetching operations.
    """

    def test_init_with_valid_config(self):
        """Test that ElasticClientAPI initializes correctly with valid config.

        Verifies that the client properly initializes with configuration values,
        creates a session with authentication, and sets connection parameters.
        """
        config = create_test_config()

        client = ElasticClientAPI(config=config)

        assert client.config == config  # noqa: S101
        assert client.base_url == str(config.elastic.base_url).rstrip("/")  # noqa: S101
        assert client.username == config.elastic.username  # noqa: S101
        assert (  # noqa: S101
            client.password == config.elastic.password.get_secret_value()
        )
        assert isinstance(client.session, Session)  # noqa: S101

    def test_init_without_config_raises_error(self):
        """Test that initialization without config raises a validation error."""
        with pytest.raises(ElasticValidationError):
            ElasticClientAPI(config=None)

    def test_create_session_with_credentials(self):
        """Test session creation with username/password.

        Verifies that the HTTP session is configured with basic authentication
        credentials and JSON content type when no API key is provided.
        """
        config = create_test_config()

        client = ElasticClientAPI(config=config)

        expected_auth = (
            config.elastic.username,
            config.elastic.password.get_secret_value(),
        )
        assert client.session.auth == expected_auth  # noqa: S101
        assert (  # noqa: S101
            client.session.headers["Content-Type"] == "application/json"
        )

    def test_create_session_with_api_key(self):
        """Test session creation with an API key.

        Verifies that when an API key is configured it is used as the
        Authorization header and basic auth is not set.
        """
        config = create_test_config()
        config.elastic.api_key = SecretStr("my-api-key")

        client = ElasticClientAPI(config=config)

        assert (  # noqa: S101
            client.session.headers["Authorization"] == "ApiKey my-api-key"
        )
        assert client.session.auth is None  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_detection_success(self, mock_post):
        """Test successful signature fetching for a detection expectation.

        Verifies that detection expectations fetch Elastic Security alerts
        and return proper ElasticAlert objects.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = TestDataFactory.create_api_response_data()
        mock_post.return_value = mock_response

        search_signatures = TestDataFactory.create_expectation_signatures()

        result = client.fetch_signatures(search_signatures, "detection")

        assert len(result) == 2  # noqa: S101
        assert all(hasattr(alert, "time") for alert in result)  # noqa: S101
        assert all(hasattr(alert, "src_ip") for alert in result)  # noqa: S101
        mock_post.assert_called_once()

    @patch("requests.Session.post")
    def test_fetch_signatures_with_ip_addresses(self, mock_post):
        """Test fetching signatures with source and target IP addresses.

        Verifies that IP-based signatures are converted to an Elasticsearch
        terms query on ECS ``source.ip`` and ``destination.ip`` fields.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = TestDataFactory.create_api_response_data()
        mock_post.return_value = mock_response

        search_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.1.100"},
            {"type": "target_ipv4_address", "value": "10.0.0.50"},
        ]

        result = client.fetch_signatures(search_signatures, "detection")

        assert len(result) == 2  # noqa: S101
        body = mock_post.call_args.kwargs["json"]
        should = body["query"]["bool"]["should"]
        assert {"terms": {"source.ip": ["192.168.1.100"]}} in should  # noqa: S101
        assert {"terms": {"destination.ip": ["10.0.0.50"]}} in should  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_uses_configured_index(self, mock_post):
        """Test that the configured alerts index is used in the search endpoint."""
        config = create_test_config()
        config.elastic.alerts_index = "custom-index"
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"hits": {"hits": []}}
        mock_post.return_value = mock_response

        client.fetch_signatures(
            TestDataFactory.create_expectation_signatures(), "detection"
        )

        endpoint = mock_post.call_args.args[0]
        assert "/custom-index/_search" in endpoint  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_authentication_error(self, mock_post):
        """Test handling of authentication errors.

        Verifies that 401 HTTP responses are converted to
        ElasticAuthenticationError exceptions.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(ElasticAuthenticationError):
            client.fetch_signatures(search_signatures, "detection")

    @patch("requests.Session.post")
    def test_fetch_signatures_no_data_returns_empty(self, mock_post):
        """Test behavior when no alerts are found.

        Verifies that when Elasticsearch returns no hits, the method
        returns an empty list without errors.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"hits": {"hits": []}}
        mock_post.return_value = mock_response

        search_signatures = TestDataFactory.create_expectation_signatures()

        result = client.fetch_signatures(search_signatures, "detection")

        assert result == []  # noqa: S101

    @patch("src.services.client_api.time.sleep")
    @patch("requests.Session.post")
    def test_fetch_signatures_exception_handling(self, mock_post, mock_sleep):
        """Test exception handling in fetch_signatures.

        Verifies that repeated API errors are caught and wrapped in
        ElasticAPIError with a descriptive error message.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        mock_post.side_effect = Exception("Network Error")

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(ElasticAPIError) as exc_info:
            client.fetch_signatures(search_signatures, "detection")

        assert "All Elastic Security fetch attempts failed." in str(  # noqa: S101
            exc_info.value
        )

    def test_build_query_with_ips(self):
        """Test query building with IP addresses.

        Verifies that search criteria containing IPs are converted to a
        valid Elasticsearch terms query with a time-window range filter.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_criteria = ElasticSearchCriteria(
            source_ips=["192.168.1.100"],
            target_ips=["10.0.0.50"],
        )

        query = client._build_query(search_criteria)

        bool_query = query["query"]["bool"]
        assert {"terms": {"source.ip": ["192.168.1.100"]}} in (  # noqa: S101
            bool_query["should"]
        )
        assert {"terms": {"destination.ip": ["10.0.0.50"]}} in (  # noqa: S101
            bool_query["should"]
        )
        assert bool_query["minimum_should_match"] == 1  # noqa: S101
        gte = bool_query["filter"][0]["range"]["@timestamp"]["gte"]
        assert gte.startswith("now-")  # noqa: S101

    def test_build_query_with_parent_process_name(self):
        """Test query building with a parent process name.

        Verifies that parent process names are converted to a ``url.path``
        match_phrase clause with the injected executable-payload path.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_criteria = ElasticSearchCriteria(
            source_ips=["192.168.1.100"],
            parent_process_names=[PARENT_PROCESS_NAME],
        )

        query = client._build_query(search_criteria)

        should = query["query"]["bool"]["should"]
        url_path_clauses = [clause for clause in should if "match_phrase" in clause]
        assert len(url_path_clauses) == 1  # noqa: S101
        url_path = url_path_clauses[0]["match_phrase"]["url.path"]
        assert "/api/injects/" in url_path  # noqa: S101
        assert "executable-payload" in url_path  # noqa: S101

    def test_build_query_time_window_extension(self):
        """Test that retries widen the query time window.

        Verifies that increasing ``extend_end_seconds`` produces a different
        (larger) time window in the range filter.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_criteria = ElasticSearchCriteria(source_ips=["192.168.1.100"])

        query1 = client._build_query(search_criteria, extend_end_seconds=0)
        query2 = client._build_query(search_criteria, extend_end_seconds=30)

        gte1 = query1["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"]
        gte2 = query2["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"]
        assert gte1 != gte2  # noqa: S101

    def test_build_search_criteria_from_signatures(self):
        """Test building search criteria from a signature list.

        Verifies that various signature types are extracted and converted
        to an ElasticSearchCriteria object.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.1.100"},
            {"type": "target_ipv6_address", "value": "2001:db8::1"},
            {"type": "parent_process_name", "value": PARENT_PROCESS_NAME},
            {"type": "start_date", "value": "2024-01-01T00:00:00Z"},
            {"type": "end_date", "value": "2024-01-01T23:59:59Z"},
        ]

        criteria = client._build_search_criteria(search_signatures)

        assert criteria.source_ips == ["192.168.1.100"]  # noqa: S101
        assert criteria.target_ips == ["2001:db8::1"]  # noqa: S101
        assert criteria.parent_process_names == [PARENT_PROCESS_NAME]  # noqa: S101
        assert criteria.start_date == "2024-01-01T00:00:00Z"  # noqa: S101
        assert criteria.end_date == "2024-01-01T23:59:59Z"  # noqa: S101

    def test_prevention_expectation_not_supported(self):
        """Test that prevention expectations raise a validation error.

        Verifies that Elastic Security rejects prevention expectation types
        as it only supports detection expectations.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(ElasticValidationError) as exc_info:
            client.fetch_signatures(search_signatures, "prevention")

        assert "Invalid expectation_type" in str(exc_info.value)  # noqa: S101

    def test_parent_process_uuid_extraction(self):
        """Test UUID extraction from parent process names.

        Verifies that UUIDs are extracted from parent process names and
        converted to a URL path search query.
        """
        config = create_test_config()
        client = ElasticClientAPI(config=config)

        uuids = client.parent_process_parser.extract_uuids_from_parent_process_name(
            PARENT_PROCESS_NAME
        )

        assert uuids is not None  # noqa: S101
        inject_uuid, agent_uuid = uuids
        assert inject_uuid == "12345678-1234-1234-1234-123456789abc"  # noqa: S101
        assert agent_uuid == "87654321-4321-4321-4321-cba987654321"  # noqa: S101
