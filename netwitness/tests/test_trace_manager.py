"""Tests for the TraceManager."""

from unittest.mock import Mock

import pytest
from src.collector.exception import TracingError
from src.collector.trace_manager import TraceManager


def _trace() -> Mock:
    """Build a mock trace with an API dict representation."""
    trace = Mock()
    trace.to_api_dict.return_value = {"inject_expectation_trace_expectation": "e1"}
    return trace


class TestTraceManager:
    """Test cases for TraceManager."""

    def test_no_trace_service_skips_submission(self):
        """Without a trace service, no API calls are made."""
        api = Mock()
        manager = TraceManager(api, "collector-id", trace_service=None)
        manager.create_and_submit_traces([Mock()])
        api.inject_expectation_trace.bulk_create.assert_not_called()

    def test_create_and_submit_success(self):
        """Traces are created and bulk-submitted to the API."""
        api = Mock()
        trace_service = Mock()
        trace_service.create_traces_from_results.return_value = [_trace()]
        manager = TraceManager(api, "collector-id", trace_service=trace_service)

        manager.create_and_submit_traces([Mock()])

        api.inject_expectation_trace.bulk_create.assert_called_once()

    def test_no_traces_created_skips_submission(self):
        """When no traces are produced, no submission happens."""
        api = Mock()
        trace_service = Mock()
        trace_service.create_traces_from_results.return_value = []
        manager = TraceManager(api, "collector-id", trace_service=trace_service)

        manager.create_and_submit_traces([Mock()])

        api.inject_expectation_trace.bulk_create.assert_not_called()

    def test_bulk_failure_falls_back_to_individual(self):
        """A bulk failure triggers individual creation and raises TracingError."""
        api = Mock()
        api.inject_expectation_trace.bulk_create.side_effect = RuntimeError("bulk")
        trace_service = Mock()
        trace_service.create_traces_from_results.return_value = [_trace()]
        manager = TraceManager(api, "collector-id", trace_service=trace_service)

        with pytest.raises(TracingError):
            manager.create_and_submit_traces([Mock()])

        api.inject_expectation_trace.create.assert_called()

    def test_bulk_and_individual_failure(self):
        """When both bulk and individual creation fail, TracingError is raised."""
        api = Mock()
        api.inject_expectation_trace.bulk_create.side_effect = RuntimeError("bulk")
        api.inject_expectation_trace.create.side_effect = RuntimeError("individual")
        trace_service = Mock()
        trace_service.create_traces_from_results.return_value = [_trace()]
        manager = TraceManager(api, "collector-id", trace_service=trace_service)

        with pytest.raises(TracingError):
            manager.create_and_submit_traces([Mock()])
