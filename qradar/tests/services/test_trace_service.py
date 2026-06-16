"""Tests for the IBM QRadar trace service."""

from unittest.mock import Mock

import pytest
from src.collector.models import ExpectationResult
from src.services.exception import QRadarValidationError
from src.services.trace_service import QRadarTraceService
from tests.services.fixtures.factories import create_test_config


def _make_expectation(sig_type: str = "source_ipv4_address", value: str = "1.2.3.4"):
    """Build a mock expectation with a single signature."""
    signature = Mock()
    signature.type.value = sig_type
    signature.value = value
    expectation = Mock()
    expectation.inject_expectation_signatures = [signature]
    return expectation


def _make_result(matching_data: dict) -> ExpectationResult:
    """Build a valid ExpectationResult with a matched alert."""
    return ExpectationResult(
        expectation_id="exp-1",
        is_valid=True,
        expectation=_make_expectation(),
        matched_alerts=[matching_data],
    )


class TestQRadarTraceService:
    """Test cases for QRadarTraceService."""

    def test_init_without_config_raises(self):
        """Initialization without a config raises a validation error."""
        with pytest.raises(QRadarValidationError):
            QRadarTraceService(config=None)

    def test_create_traces_from_results_success(self):
        """A valid result produces a single trace with a source-IP alert name."""
        service = QRadarTraceService(config=create_test_config())
        result = _make_result({"source_ipv4_address": {"data": "1.2.3.4"}})

        traces = service.create_traces_from_results([result], "qradar--collector")

        assert len(traces) == 1  # noqa: S101
        trace = traces[0]
        assert trace.inject_expectation_trace_expectation == "exp-1"  # noqa: S101
        assert (
            trace.inject_expectation_trace_source_id == "qradar--collector"
        )  # noqa: S101
        assert "Source IP" in trace.inject_expectation_trace_alert_name  # noqa: S101
        assert trace.inject_expectation_trace_alert_link.startswith(
            "http"
        )  # noqa: S101

    def test_create_traces_target_ip_alert_name(self):
        """A target-IP match yields a target-IP alert name."""
        service = QRadarTraceService(config=create_test_config())
        result = _make_result({"target_ipv4_address": {"data": "10.0.0.1"}})

        traces = service.create_traces_from_results([result], "qradar--collector")

        assert (
            "Target IP" in traces[0].inject_expectation_trace_alert_name
        )  # noqa: S101

    def test_create_traces_generic_alert_name(self):
        """A non-IP match yields the generic alert name."""
        service = QRadarTraceService(config=create_test_config())
        result = _make_result({"parent_process_name": {"data": "x.exe"}})

        traces = service.create_traces_from_results([result], "qradar--collector")

        name = traces[0].inject_expectation_trace_alert_name
        assert name == "IBM QRadar Detection Alert"  # noqa: S101

    def test_create_traces_empty_collector_id_raises(self):
        """An empty collector_id raises a validation error."""
        service = QRadarTraceService(config=create_test_config())
        with pytest.raises(QRadarValidationError):
            service.create_traces_from_results([], "")

    def test_create_traces_non_list_raises(self):
        """A non-list results argument raises a validation error."""
        service = QRadarTraceService(config=create_test_config())
        with pytest.raises(QRadarValidationError):
            service.create_traces_from_results("nope", "qradar--collector")

    def test_create_traces_no_valid_results(self):
        """Invalid results (no matches) produce no traces."""
        service = QRadarTraceService(config=create_test_config())
        invalid = ExpectationResult(
            expectation_id="exp-2", is_valid=False, matched_alerts=None
        )
        assert service.create_traces_from_results([invalid], "c") == []  # noqa: S101

    def test_create_traces_console_url_used(self):
        """When console_url is configured it is used for the trace link."""
        config = create_test_config()
        config.qradar.console_url = "https://console.example.com"
        service = QRadarTraceService(config=config)
        result = _make_result({"source_ipv4_address": {"data": "1.2.3.4"}})

        traces = service.create_traces_from_results([result], "qradar--collector")

        assert traces[0].inject_expectation_trace_alert_link.startswith(  # noqa: S101
            "https://console.example.com"
        )

    def test_get_service_info(self):
        """The service exposes detection-only metadata."""
        service = QRadarTraceService(config=create_test_config())
        info = service.get_service_info()
        assert info["creates_detection_traces"] is True  # noqa: S101
        assert info["creates_prevention_traces"] is False  # noqa: S101
