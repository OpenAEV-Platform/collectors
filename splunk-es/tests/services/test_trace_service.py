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
