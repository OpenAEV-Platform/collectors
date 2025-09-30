"""Conftest for services tests with polyfactory fixtures."""

from unittest.mock import Mock, patch

import pytest
from tests.services.fixtures.factories import (
    ConfigLoaderFactory,
    ExpectationResultFactory,
    ExpectationTraceFactory,
    MockObjectsFactory,
    SplunkESAlertFactory,
    TestDataFactory,
    create_test_config,
)


@pytest.fixture
def mock_config():
    """Provide a mock configuration for tests.

    Returns:
        ConfigLoader instance with test configuration values.

    """
    return create_test_config()


@pytest.fixture
def mock_client_api():
    """Provide a mock Splunk ES client API.

    Returns:
        Mock Splunk ES client API instance for testing.

    """
    return MockObjectsFactory.create_mock_client_api()


@pytest.fixture
def mock_detection_helper():
    """Provide a mock detection helper that matches by default.

    Returns:
        Mock OpenBAS detection helper that returns True for matches.

    """
    return MockObjectsFactory.create_mock_detection_helper(match_result=True)


@pytest.fixture
def mock_detection_helper_no_match():
    """Provide a mock detection helper that doesn't match.

    Returns:
        Mock OpenBAS detection helper that returns False for matches.

    """
    return MockObjectsFactory.create_mock_detection_helper(match_result=False)


@pytest.fixture
def sample_alert():
    """Provide a sample Splunk ES alert.

    Returns:
        SplunkESAlert instance for testing.

    """
    return SplunkESAlertFactory.build()


@pytest.fixture
def sample_alerts():
    """Provide a list of sample Splunk ES alerts.

    Returns:
        List of 3 SplunkESAlert instances for testing.

    """
    return [SplunkESAlertFactory.build() for _ in range(3)]


@pytest.fixture
def sample_expectation_result():
    """Provide a sample expectation result.

    Returns:
        ExpectationResult instance for testing.

    """
    return ExpectationResultFactory.build()


@pytest.fixture
def sample_expectation_trace():
    """Provide a sample expectation trace.

    Returns:
        ExpectationTrace instance for testing.

    """
    return ExpectationTraceFactory.build()


@pytest.fixture
def detection_signatures():
    """Provide sample detection expectation signatures.

    Returns:
        List of signature dictionaries for detection expectations.

    """
    return TestDataFactory.create_expectation_signatures(
        signature_type="source_ipv4_address"
    )


@pytest.fixture
def ip_signatures():
    """Provide sample IP-based expectation signatures.

    Returns:
        List of signature dictionaries for IP-based expectations.

    """
    return TestDataFactory.create_expectation_signatures(
        signature_type="target_ipv4_address"
    )


@pytest.fixture
def oaev_detection_data():
    """Provide sample OAEV detection data.

    Returns:
        List of OAEV-formatted detection data dictionaries.

    """
    return TestDataFactory.create_oaev_detection_data()


@pytest.fixture
def mixed_splunk_es_data():
    """Provide mixed Splunk ES data (alerts).

    Returns:
        List containing SplunkESAlert instances.

    """
    return TestDataFactory.create_mixed_splunk_es_data()


@pytest.fixture
def mock_expectation_detection():
    """Provide a mock detection expectation.

    Returns:
        Mock DetectionExpectation instance for testing.

    """
    return MockObjectsFactory.create_mock_expectation(expectation_type="detection")


@pytest.fixture
def mock_requests_session():
    """Provide a mock requests session.

    Returns:
        Mock requests.Session instance for HTTP testing.

    """
    return MockObjectsFactory.create_mock_session()


@pytest.fixture
def api_response_data():
    """Provide sample API response data.

    Returns:
        Dictionary containing mock Splunk ES API response.

    """
    return TestDataFactory.create_api_response_data()


@pytest.fixture(autouse=True)
def mock_logging():
    """Auto-mock logging to reduce noise in tests.

    Auto-applies to all tests to prevent logging output during test execution.

    Yields:
        Mock logger instance.

    """
    with patch("logging.getLogger") as mock_logger:
        mock_logger.return_value = Mock()
        yield mock_logger


@pytest.fixture
def disable_sleep():
    """Disable time.sleep in tests for faster execution.

    Patches time.sleep to prevent actual delays during testing.

    Yields:
        None (context manager for sleep patching).

    """
    with patch("time.sleep"):
        yield


# Parametrized fixtures for testing different scenarios
@pytest.fixture(params=[1, 3, 5])
def various_counts(request):
    """Provide various counts for testing different data sizes.

    Args:
        request: Pytest request object containing parameter values.

    Returns:
        Integer count (1, 3, or 5) for parameterized testing.

    """
    return request.param


@pytest.fixture(params=[True, False])
def match_scenarios(request):
    """Provide both matching and non-matching scenarios.

    Args:
        request: Pytest request object containing parameter values.

    Returns:
        Boolean value (True or False) for match testing scenarios.

    """
    return request.param


@pytest.fixture(
    params=[
        "source_ipv4_address",
        "target_ipv4_address",
        "source_ipv6_address",
        "target_ipv6_address",
    ]
)
def ip_signature_types(request):
    """Provide different IP signature types.

    Args:
        request: Pytest request object containing parameter values.

    Returns:
        String IP signature type for testing.

    """
    return request.param


# Factory fixtures that can be called in tests
@pytest.fixture
def config_factory():
    """Provide the ConfigLoaderFactory for creating configs in tests.

    Returns:
        ConfigLoaderFactory class for generating test configurations.

    """
    return ConfigLoaderFactory


@pytest.fixture
def alert_factory():
    """Provide the SplunkESAlertFactory for creating alerts.

    Returns:
        SplunkESAlertFactory class for generating test alerts.

    """
    return SplunkESAlertFactory


@pytest.fixture
def expectation_result_factory():
    """Provide the ExpectationResultFactory for creating results.

    Returns:
        ExpectationResultFactory class for generating test results.

    """
    return ExpectationResultFactory


@pytest.fixture
def expectation_trace_factory():
    """Provide the ExpectationTraceFactory for creating traces.

    Returns:
        ExpectationTraceFactory class for generating test traces.

    """
    return ExpectationTraceFactory


@pytest.fixture
def test_data_factory():
    """Provide the TestDataFactory for creating test data combinations.

    Returns:
        TestDataFactory class for generating complex test data scenarios.

    """
    return TestDataFactory


@pytest.fixture
def mock_objects_factory():
    """Provide the MockObjectsFactory for creating mock objects.

    Returns:
        MockObjectsFactory class for generating mock instances.

    """
    return MockObjectsFactory


# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_mocks():
    """Auto-cleanup mocks after each test.

    Auto-applies to all tests to ensure proper mock cleanup.

    Yields:
        None (context manager for cleanup operations).

    """
    yield
    # Any cleanup logic can go here if needed


# Error simulation fixtures
@pytest.fixture
def api_error_responses():
    """Provide various API error responses for testing error handling.

    Returns:
        Dictionary mapping HTTP status codes to error response data.

    """
    return {
        "400": {
            "status_code": 400,
            "text": "Bad Request",
            "json": {"errors": ["Bad request"]},
        },
        "401": {
            "status_code": 401,
            "text": "Unauthorized",
            "json": {"errors": ["Unauthorized"]},
        },
        "403": {
            "status_code": 403,
            "text": "Forbidden",
            "json": {"errors": ["Forbidden"]},
        },
        "404": {
            "status_code": 404,
            "text": "Not Found",
            "json": {"errors": ["Not found"]},
        },
        "500": {
            "status_code": 500,
            "text": "Internal Server Error",
            "json": {"errors": ["Server error"]},
        },
    }


@pytest.fixture
def network_errors():
    """Provide various network errors for testing error handling.

    Returns:
        List of different exception types for network error testing.

    """
    return [
        ConnectionError("Connection failed"),
        TimeoutError("Request timeout"),
        Exception("Generic network error"),
    ]
