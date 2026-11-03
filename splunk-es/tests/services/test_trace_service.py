"""Tests for the Splunk ES trace service."""

from unittest.mock import Mock

import pytest
from src.services.exception import SplunkESValidationError
from src.services.trace_service import SplunkESTraceService
from tests.services.fixtures.factories import create_test_config


class TestSplunkESTraceServiceInit:
    """Test cases for SplunkESTraceService initialization."""

    def test_init_without_config_raises(self):
        """Initialization without a config raises a validation error."""
        with pytest.raises(SplunkESValidationError):
            SplunkESTraceService(config=None)

    def test_init_reuses_given_client(self):
        """A given client is reused, so the collector builds and logs a single one."""
        client_api = Mock()

        service = SplunkESTraceService(create_test_config(), client_api=client_api)

        assert service.client_api is client_api


class TestSplunkESTraceServiceUrl:
    """Test cases for the Detection trace link."""

    def test_link_opens_the_detection_search_on_splunk_web(self):
        """The link targets Splunk Web (port 8000) with the encoded Detection SPL."""
        client_api = Mock()
        client_api._build_search_criteria.return_value = Mock()
        client_api._build_spl_query.return_value = (
            'search index="_notable" src="1.2.3.4"'
        )
        service = SplunkESTraceService(create_test_config(), client_api=client_api)
        expectation = Mock(inject_expectation_signatures=[])

        url = service._build_trace_url_from_expectation(expectation)

        assert url == (
            "https://test-splunk.example.com:8000/en-US/app/search/search"
            "?q=search%20index%3D%22_notable%22%20src%3D%221.2.3.4%22"
        )
