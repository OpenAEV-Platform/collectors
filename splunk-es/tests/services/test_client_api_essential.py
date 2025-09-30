"""Essential tests for Splunk ES Client API service."""

from unittest.mock import Mock, patch

import pytest
from requests import Session

from src.services.client_api import SplunkESClientAPI
from src.services.exception import SplunkESAPIError, SplunkESAuthenticationError
from tests.services.fixtures.factories import TestDataFactory, create_test_config


class TestSplunkESClientAPIEssential:
    """Essential test cases for SplunkESClientAPI.

    Tests the core functionality of the Splunk ES client API including
    initialization, session creation, and signature fetching operations.
    """

    def test_init_with_valid_config(self):
        """Test that SplunkESClientAPI initializes correctly with valid config.

        Verifies that the client properly initializes with configuration values,
        creates session with authentication, and sets up connection parameters.
        """
        config = create_test_config()

        client = SplunkESClientAPI(config=config)

        assert client.config == config  # noqa: S101
        assert client.base_url == str(config.splunk_es.base_url).rstrip(  # noqa: S101
            "/"
        )
        assert client.username == config.splunk_es.username  # noqa: S101
        assert (  # noqa: S101
            client.password == config.splunk_es.password.get_secret_value()
        )
        assert isinstance(client.session, Session)  # noqa: S101

    def test_create_session_with_credentials(self):
        """Test session creation with username/password.

        Verifies that the HTTP session is properly configured with
        authentication credentials and content type settings.
        """
        config = create_test_config()

        client = SplunkESClientAPI(config=config)

        expected_auth = (
            config.splunk_es.username,
            config.splunk_es.password.get_secret_value(),
        )
        assert client.session.auth == expected_auth  # noqa: S101
        assert (  # noqa: S101
            client.session.headers["Content-Type"]
            == "application/x-www-form-urlencoded"
        )

    @patch("requests.Session.post")
    def test_fetch_signatures_detection_success(self, mock_post):
        """Test successful signature fetching for detection expectation.

        Verifies that detection expectations fetch Splunk ES alerts
        and return proper SplunkESAlert objects.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        api_response_data = TestDataFactory.create_api_response_data()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = api_response_data
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

        Verifies that IP-based signatures are properly converted to SPL queries
        and executed against the Splunk ES API.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        api_response_data = TestDataFactory.create_api_response_data()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = api_response_data
        mock_post.return_value = mock_response

        search_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.1.100"},
            {"type": "target_ipv4_address", "value": "10.0.0.50"},
        ]

        result = client.fetch_signatures(search_signatures, "detection")

        assert len(result) == 2  # noqa: S101
        # Verify the SPL query was built with IP conditions
        call_args = mock_post.call_args
        assert "src_ip" in str(call_args)  # noqa: S101
        assert "dst_ip" in str(call_args)  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_authentication_error(self, mock_post):
        """Test handling of authentication errors.

        Verifies that 401 HTTP responses are properly converted to
        SplunkESAuthenticationError exceptions.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(SplunkESAuthenticationError):
            client.fetch_signatures(search_signatures, "detection")

    def test_build_spl_query_with_ips(self):
        """Test SPL query building with IP addresses.

        Verifies that search criteria containing IP addresses
        are properly converted to valid SPL query syntax with OR logic.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        from src.services.models import SplunkESSearchCriteria

        search_criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.100"],
            target_ips=["10.0.0.50"],
        )

        query = client._build_spl_query(search_criteria)

        assert "index=_notable" in query  # noqa: S101
        assert "src_ip=192.168.1.100" in query  # noqa: S101
        assert "dst_ip=10.0.0.50" in query  # noqa: S101
        assert "earliest=-" in query  # noqa: S101
        assert "url_path" in query  # noqa: S101

    def test_build_spl_query_with_custom_index(self):
        """Test SPL query building with custom alerts index.

        Verifies that custom alert index configuration is properly
        included in the generated SPL queries.
        """
        config = create_test_config()
        # Override the default alerts index
        config.splunk_es.alerts_index = "custom_security"

        client = SplunkESClientAPI(config=config)

        from src.services.models import SplunkESSearchCriteria

        search_criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.100"],
        )

        query = client._build_spl_query(search_criteria)

        assert "index=custom_security" in query  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_no_data_returns_empty(self, mock_post):
        """Test behavior when no alerts are found.

        Verifies that when Splunk ES returns no results,
        the method returns empty list without errors.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": []}
        mock_post.return_value = mock_response

        search_signatures = TestDataFactory.create_expectation_signatures()

        result = client.fetch_signatures(search_signatures, "detection")

        assert result == []  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_exception_handling(self, mock_post):
        """Test exception handling in fetch_signatures.

        Verifies that API errors are properly caught and wrapped
        in SplunkESAPIError with descriptive error messages.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        mock_post.side_effect = Exception("Network Error")

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(SplunkESAPIError) as exc_info:
            client.fetch_signatures(search_signatures, "detection")

        assert "All Splunk ES fetch attempts failed." in str(  # noqa: S101
            exc_info.value
        )

    def test_build_search_criteria_from_signatures(self):
        """Test building search criteria from signature list.

        Verifies that various signature types are properly extracted
        and converted to SplunkESSearchCriteria objects.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        search_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.1.100"},
            {"type": "target_ipv6_address", "value": "2001:db8::1"},
            {
                "type": "parent_process_name",
                "value": "obas-implant-test-uuid-agent-test-uuid",
            },
            {"type": "start_date", "value": "2024-01-01T00:00:00Z"},
            {"type": "end_date", "value": "2024-01-01T23:59:59Z"},
        ]

        criteria = client._build_search_criteria(search_signatures)

        assert criteria.source_ips == ["192.168.1.100"]  # noqa: S101
        assert criteria.target_ips == ["2001:db8::1"]  # noqa: S101
        assert criteria.parent_process_names == [  # noqa: S101
            "obas-implant-test-uuid-agent-test-uuid"
        ]
        assert criteria.start_date == "2024-01-01T00:00:00Z"  # noqa: S101
        assert criteria.end_date == "2024-01-01T23:59:59Z"  # noqa: S101

    def test_prevention_expectation_not_supported(self):
        """Test that prevention expectations raise validation error.

        Verifies that Splunk ES correctly rejects prevention expectation
        types as it only supports detection expectations.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        search_signatures = TestDataFactory.create_expectation_signatures()

        with pytest.raises(Exception) as exc_info:
            client.fetch_signatures(search_signatures, "prevention")

        assert "Invalid expectation_type" in str(exc_info.value)  # noqa: S101

    def test_build_spl_query_with_parent_process_name(self):
        """Test SPL query building with parent process name.

        Verifies that parent process names are converted to URL path searches
        with proper UUID extraction and AND logic with IPs.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        from src.services.models import SplunkESSearchCriteria

        search_criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.100"],
            parent_process_names=[
                "obas-implant-12345678-1234-1234-1234-123456789abc-agent-87654321-4321-4321-4321-cba987654321"
            ],
        )

        query = client._build_spl_query(search_criteria)

        assert "index=_notable" in query  # noqa: S101
        assert "src_ip=192.168.1.100" in query  # noqa: S101
        assert "AND" in query  # noqa: S101
        assert "url_path" in query  # noqa: S101
        assert "/api/injects/" in query  # noqa: S101
        assert "executable-payload" in query  # noqa: S101

    def test_build_spl_query_time_window_format(self):
        """Test SPL query time window format.

        Verifies that time windows use the earliest=-Xs format
        instead of absolute date ranges.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        from src.services.models import SplunkESSearchCriteria

        search_criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.100"],
        )

        query = client._build_spl_query(search_criteria, extend_end_seconds=30)

        assert "earliest=-" in query  # noqa: S101
        assert "s" in query  # noqa: S101
        # Should not have absolute dates when using time window
        assert "2024-" not in query  # noqa: S101

    def test_build_spl_query_includes_all_url_fields(self):
        """Test SPL query includes all URL field alternatives.

        Verifies that the query includes url_path, url, path, and query
        fields in the table output for proper data collection.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        from src.services.models import SplunkESSearchCriteria

        search_criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.100"],
        )

        query = client._build_spl_query(search_criteria)

        assert "url_path" in query  # noqa: S101
        assert "url" in query  # noqa: S101
        assert "path" in query  # noqa: S101
        assert "query" in query  # noqa: S101

    @patch("requests.Session.post")
    def test_fetch_signatures_with_parent_process_name(self, mock_post):
        """Test fetching signatures with parent process name.

        Verifies that parent process name signatures are properly converted
        to URL path searches and executed against the Splunk ES API.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        api_response_data = TestDataFactory.create_api_response_data()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = api_response_data
        mock_post.return_value = mock_response

        search_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.1.100"},
            {
                "type": "parent_process_name",
                "value": "obas-implant-12345678-1234-1234-1234-123456789abc-agent-87654321-4321-4321-4321-cba987654321",
            },
        ]

        result = client.fetch_signatures(search_signatures, "detection")

        assert len(result) == 2  # noqa: S101
        # Verify the SPL query was built with parent process conditions
        call_args = mock_post.call_args
        query_str = str(call_args)
        assert "url_path" in query_str  # noqa: S101
        assert "/api/injects/" in query_str  # noqa: S101
        assert "executable-payload" in query_str  # noqa: S101
        assert "AND" in query_str  # noqa: S101

    def test_parent_process_uuid_extraction(self):
        """Test UUID extraction from parent process names.

        Verifies that UUIDs are properly extracted from parent process names
        and converted to URL path search queries.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        parent_process_name = "obas-implant-12345678-1234-1234-1234-123456789abc-agent-87654321-4321-4321-4321-cba987654321"

        # Test UUID extraction
        uuids = client.parent_process_parser.extract_uuids_from_parent_process_name(
            parent_process_name
        )

        assert uuids is not None  # noqa: S101
        inject_uuid, agent_uuid = uuids
        assert inject_uuid == "12345678-1234-1234-1234-123456789abc"  # noqa: S101
        assert agent_uuid == "87654321-4321-4321-4321-cba987654321"  # noqa: S101

        # Test URL path query building
        url_query = client.parent_process_parser.build_url_path_search_query(
            inject_uuid, agent_uuid
        )

        expected_path = "/api/injects/12345678-1234-1234-1234-123456789abc/87654321-4321-4321-4321-cba987654321/executable-payload"
        assert expected_path in url_query  # noqa: S101
        assert "url_path" in url_query  # noqa: S101
        assert "url=" in url_query  # noqa: S101
        assert "path=" in url_query  # noqa: S101
        assert "query=" in url_query  # noqa: S101

    def test_build_spl_query_and_logic_with_parent_process(self):
        """Test SPL query AND logic with parent process.

        Verifies that when parent process names are present, the query
        uses AND logic between IP conditions and URL path conditions.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        from src.services.models import SplunkESSearchCriteria

        search_criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.100", "10.0.0.1"],
            target_ips=["172.16.0.1"],
            parent_process_names=[
                "obas-implant-12345678-1234-1234-1234-123456789abc-agent-87654321-4321-4321-4321-cba987654321"
            ],
        )

        query = client._build_spl_query(search_criteria)

        # Verify AND logic structure
        assert "AND" in query  # noqa: S101
        # Verify IP OR conditions are grouped
        assert "src_ip=192.168.1.100 OR" in query  # noqa: S101
        assert "src_ip=10.0.0.1" in query  # noqa: S101
        assert "dst_ip=172.16.0.1" in query  # noqa: S101
        # Verify URL path conditions
        assert "url_path=" in query  # noqa: S101
        assert "/api/injects/" in query  # noqa: S101

    def test_build_spl_query_retry_time_extension(self):
        """Test SPL query time extension for retries.

        Verifies that retry attempts properly extend the time window
        by adding extend_end_seconds to the base time window.
        """
        config = create_test_config()
        client = SplunkESClientAPI(config=config)

        from src.services.models import SplunkESSearchCriteria

        search_criteria = SplunkESSearchCriteria(
            source_ips=["192.168.1.100"],
        )

        # First attempt (no extension)
        query1 = client._build_spl_query(search_criteria, extend_end_seconds=0)
        # Second attempt (30s extension)
        query2 = client._build_spl_query(search_criteria, extend_end_seconds=30)

        # Both should have earliest= but with different values
        assert "earliest=-" in query1  # noqa: S101
        assert "earliest=-" in query2  # noqa: S101
        # The second query should have a larger time window
        # Extract the time values to compare (basic check)
        assert query1 != query2  # noqa: S101
