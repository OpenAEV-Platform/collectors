"""Essential tests for SentinelOne Trace Service - Gherkin GWT Format."""

import pytest
from src.services.exception import SentinelOneValidationError
from src.services.trace_service import SentinelOneTraceService
from tests.gwt_shared import (
    given_test_config,
)

# --------
# Scenarios
# --------


# Scenario: Initialize trace service with valid configuration
def test_initialize_trace_service_with_valid_config():
    """Scenario: Initialize trace service with valid configuration."""
    # Given: A valid configuration is available
    config = _given_valid_config_for_trace_service()

    # When: I initialize the trace service
    service = _when_initialize_trace_service(config)

    # Then: The trace service should be initialized successfully
    _then_trace_service_initialized_successfully(service, config)


# Scenario: Initialize with invalid configuration raises error
def test_initialize_with_invalid_config():
    """Scenario: Initialize with invalid configuration raises error."""
    # Given: An invalid configuration (None)
    invalid_config = _given_invalid_config()

    # When: I attempt to initialize the trace service
    # Then: A validation error should be raised
    _when_initialize_trace_service_then_validation_error_raised(invalid_config)


# Scenario: Create traces from valid expectation results
def test_create_traces_from_valid_expectation_results():
    """Scenario: Create traces from valid expectation results."""
    # Given: A valid trace service
    service = _given_valid_trace_service()
    # Given: Valid expectation results with matching alerts
    results = _given_valid_expectation_results_with_alerts()

    # When: I create traces from the results
    traces = _when_create_traces_from_results(service, results)

    # Then: Traces should be created successfully
    _then_traces_created_successfully(traces, results)


# Scenario: Trace timestamp format is correct for Java backend
def test_trace_timestamp_format_is_correct():
    """Scenario: Trace timestamp format is correct for Java backend."""
    # Given: A valid trace service
    service = _given_valid_trace_service()
    # Given: Valid expectation results with matching alerts
    results = _given_valid_expectation_results_with_alerts()

    # When: I create traces from the results
    traces = _when_create_traces_from_results(service, results)

    # Then: Timestamp format should be valid for Java backend
    _then_timestamp_format_is_valid(traces)


# --------
# Given Methods
# --------


# Given: A valid configuration is available
def _given_valid_config_for_trace_service():
    """Create a valid configuration for trace service testing.

    Returns:
        Test configuration object.

    """
    return given_test_config()


# Given: An invalid configuration (None)
def _given_invalid_config():
    """Create an invalid configuration.

    Returns:
        None (invalid configuration).

    """
    return None


# Given: A valid trace service
def _given_valid_trace_service():
    """Create a valid trace service for testing.

    Returns:
        Initialized SentinelOneTraceService instance.

    """
    config = given_test_config()
    return SentinelOneTraceService(config=config)


# Given: Valid expectation results with matching alerts
def _given_valid_expectation_results_with_alerts():
    """Create valid expectation results with alerts for testing.

    Returns:
        List of expectation results with alerts.

    """
    from unittest.mock import Mock

    result1 = Mock()
    result1.expectation_id = "test_expectation_1"
    result1.is_valid = True
    result1.matched_alerts = [
        {
            "alert_id": "alert_1",
            "severity": "high",
            "message": "Test alert 1",
            "alert_name": "SentinelOne Test Alert 1",
            "alert_link": "https://console.sentinelone.com/alerts/alert_1",
        }
    ]
    result1.expectation = Mock()
    result1.expectation.inject_expectation_id = "test_expectation_1"

    return [result1]


# --------
# When Methods
# --------


# When: I initialize the trace service
def _when_initialize_trace_service(config):
    """Initialize trace service with given configuration.

    Args:
        config: Configuration object to use.

    Returns:
        Initialized SentinelOneTraceService instance.

    """
    return SentinelOneTraceService(config=config)


# When: I attempt to initialize with invalid config and expect validation error
def _when_initialize_trace_service_then_validation_error_raised(invalid_config):
    """Attempt to initialize with invalid config and expect validation error.

    Args:
        invalid_config: Invalid configuration to test.

    """
    with pytest.raises(SentinelOneValidationError):
        SentinelOneTraceService(config=invalid_config)


# When: I create traces from the results
def _when_create_traces_from_results(service, results):
    """Create traces from expectation results.

    Args:
        service: The trace service instance.
        results: List of expectation results.

    Returns:
        List of created traces.

    """
    return service.create_traces_from_results(results, "test_collector_id")


# --------
# Then Methods
# --------


# Then: The trace service should be initialized successfully
def _then_trace_service_initialized_successfully(service, config):
    """Verify trace service was initialized successfully.

    Args:
        service: The service instance to verify.
        config: The configuration used for initialization.

    """
    assert service is not None  # noqa: S101
    assert service.config == config  # noqa: S101
    assert service.logger is not None  # noqa: S101


# Then: Traces should be created successfully
def _then_traces_created_successfully(traces, results):
    """Verify traces were created successfully from results.

    Args:
        traces: The created traces to verify.
        results: The original expectation results.

    """
    assert isinstance(traces, list)  # noqa: S101
    assert len(traces) > 0  # noqa: S101

    from src.collector.models import ExpectationTrace

    for trace in traces:
        assert isinstance(trace, ExpectationTrace)  # noqa: S101
        assert hasattr(trace, "inject_expectation_trace_expectation")  # noqa: S101
        assert hasattr(trace, "inject_expectation_trace_alert_name")  # noqa: S101
        assert hasattr(trace, "inject_expectation_trace_alert_link")  # noqa: S101


# Then: Timestamp format should be valid for Java backend
def _then_timestamp_format_is_valid(traces):
    """Verify timestamp format is valid for Java backend.

    Args:
        traces: The created traces to verify.

    """
    import re

    valid_timestamp_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"

    for trace in traces:
        timestamp = trace.inject_expectation_trace_date
        assert re.match(valid_timestamp_pattern, timestamp)  # noqa: S101
        assert "+00:00Z" not in timestamp  # noqa: S101
