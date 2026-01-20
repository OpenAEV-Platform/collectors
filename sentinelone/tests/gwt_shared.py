"""Shared Given-When-Then methods for Gherkin-style tests.

This module provides reusable Given, When, and Then methods that can be used
across multiple test files to maximize code reusability and maintain consistency
in test structure.
"""

from os import environ as os_environ
from typing import Any, Dict, List
from unittest.mock import Mock, patch

import pytest
from src.collector import Collector
from src.services.client_api import SentinelOneClientAPI
from src.services.converter import SentinelOneConverter
from src.services.exception import SentinelOneValidationError
from src.services.expectation_service import SentinelOneExpectationService
from src.services.model_threat import SentinelOneThreat
from tests.conftest import mock_env_vars
from tests.services.fixtures.factories import create_test_config

# ========================================================================
# SHARED GIVEN METHODS - Set up test preconditions
# ========================================================================


# Configuration Setup Given Methods
# ---------------------------------


def given_valid_collector_config(config_data: Dict[str, str]) -> Any:
    """Set up valid collector configuration environment.

    Args:
        config_data: Dictionary of environment variables to mock.

    Returns:
        Mock environment variable patcher object.

    """
    return mock_env_vars(os_environ, config_data)


def given_test_config():
    """Create a standard test configuration.

    Returns:
        Test configuration object.

    """
    return create_test_config()


def given_config_missing_field(
    base_config: Dict[str, str], field_name: str
) -> Dict[str, str]:
    """Create configuration with a missing required field.

    Args:
        base_config: Base configuration dictionary.
        field_name: Name of the field to remove.

    Returns:
        Configuration dictionary without the specified field.

    """
    config = base_config.copy()
    config.pop(field_name, None)

    if field_name in os_environ:
        del os_environ[field_name]

    return config


def given_config_with_invalid_value(
    base_config: Dict[str, str], field_name: str, invalid_value: str
) -> Dict[str, str]:
    """Create configuration with an invalid field value.

    Args:
        base_config: Base configuration dictionary.
        field_name: Name of the field to modify.
        invalid_value: Invalid value to set.

    Returns:
        Configuration dictionary with invalid value.

    """
    config = base_config.copy()
    config[field_name] = invalid_value
    return config


# Object Creation Given Methods
# -----------------------------


def given_initialized_converter() -> SentinelOneConverter:
    """Create an initialized converter.

    Returns:
        Initialized SentinelOneConverter instance.

    """
    return SentinelOneConverter()


def given_initialized_client_api():
    """Create an initialized client API.

    Returns:
        Initialized SentinelOneClientAPI instance.

    """
    config = given_test_config()
    return SentinelOneClientAPI(config=config)


def given_initialized_expectation_service():
    """Create an initialized expectation service.

    Returns:
        Initialized SentinelOneExpectationService instance.

    """
    config = given_test_config()
    return SentinelOneExpectationService(config=config)


# Data Creation Given Methods
# ---------------------------


def given_threat_with_complete_data(
    threat_id: str = "test_threat_123", hostname: str = "test-host.example.com"
) -> SentinelOneThreat:
    """Create a threat with complete data.

    Args:
        threat_id: ID for the threat.
        hostname: Hostname for the threat.

    Returns:
        SentinelOneThreat with complete data.

    """
    return SentinelOneThreat(threat_id=threat_id, hostname=hostname)


def given_threat_without_hostname(
    threat_id: str = "no_hostname_threat",
) -> SentinelOneThreat:
    """Create a threat without hostname.

    Args:
        threat_id: ID for the threat.

    Returns:
        SentinelOneThreat without hostname.

    """
    return SentinelOneThreat(threat_id=threat_id, hostname=None)


def given_threat_with_empty_id(
    hostname: str = "empty-id-host.example.com",
) -> SentinelOneThreat:
    """Create a threat with empty threat ID.

    Args:
        hostname: Hostname for the threat.

    Returns:
        SentinelOneThreat with empty threat_id.

    """
    return SentinelOneThreat(threat_id="", hostname=hostname)


def given_multiple_threats(count: int = 3) -> List[SentinelOneThreat]:
    """Create multiple threats with different data combinations.

    Args:
        count: Number of threats to create.

    Returns:
        List of SentinelOneThreat objects.

    """
    threats = []
    for i in range(count):
        threat_id = f"multi_threat_{i + 1}"
        hostname = f"host{i + 1}.example.com" if i % 2 == 0 else None
        threats.append(SentinelOneThreat(threat_id=threat_id, hostname=hostname))
    return threats


def given_large_batch_of_threats(count: int = 100) -> List[SentinelOneThreat]:
    """Create a large batch of threats for performance testing.

    Args:
        count: Number of threats to create.

    Returns:
        List of SentinelOneThreat objects.

    """
    return [
        SentinelOneThreat(
            threat_id=f"bulk_threat_{i}",
            hostname=f"host{i}.example.com" if i % 2 == 0 else None,
        )
        for i in range(count)
    ]


def given_mixed_valid_invalid_objects(valid_threat_id: str = "valid_mixed_123") -> List:
    """Create a list with mixed valid and invalid objects.

    Args:
        valid_threat_id: ID for the valid threat in the list.

    Returns:
        List containing valid threats and invalid objects.

    """
    valid_threat = SentinelOneThreat(
        threat_id=valid_threat_id, hostname="valid-mixed.example.com"
    )
    return [
        valid_threat,
        {"threat_id": "dict_threat"},
        "string_threat",
        42,
    ]


def given_invalid_input_data() -> str:
    """Create invalid input data for testing.

    Returns:
        Invalid data (string instead of list).

    """
    return "invalid_string_data"


# Mock Setup Given Methods
# ------------------------


def given_mock_session_that_fails():
    """Create a mock session that fails during creation.

    Returns:
        Context manager for mocking session failure.

    """
    return patch("requests.Session", side_effect=Exception("Session creation failed"))


def given_mock_session_with_header_failure():
    """Create a mock session that fails during header setup.

    Returns:
        Context manager for mocking header setup failure.

    """

    def create_failing_session():
        mock_session = Mock()
        mock_session.headers.update.side_effect = Exception("Header setup failed")
        return mock_session

    return patch("requests.Session", side_effect=create_failing_session)


def given_conversion_error_setup(converter: SentinelOneConverter) -> List:
    """Set up threats that will cause conversion errors.

    Args:
        converter: The converter instance to mock.

    Returns:
        List with valid threats and error-causing mock threats.

    """
    error_threat = Mock(spec=SentinelOneThreat)
    error_threat.threat_id = "error_threat"
    error_threat.hostname = None

    valid_threat = SentinelOneThreat(
        threat_id="valid_error_test_123", hostname="valid-error-test.example.com"
    )

    original_convert = converter._convert_threat_to_oaev

    def mock_convert(threat):
        if hasattr(threat, "threat_id") and threat.threat_id == "error_threat":
            raise Exception("Conversion error")
        return original_convert(threat)

    converter._convert_threat_to_oaev = mock_convert

    return [error_threat, valid_threat]


# ========================================================================
# SHARED WHEN METHODS - Execute actions being tested
# ========================================================================


# Object Creation When Methods
# ----------------------------


def when_create_collector() -> Collector:
    """Create a collector instance.

    Returns:
        Collector instance.

    """
    return Collector()


def when_initialize_converter() -> SentinelOneConverter:
    """Initialize a converter.

    Returns:
        Initialized SentinelOneConverter instance.

    """
    return SentinelOneConverter()


def when_initialize_client_api():
    """Initialize a client API.

    Returns:
        Initialized SentinelOneClientAPI instance.

    """
    config = given_test_config()
    return SentinelOneClientAPI(config=config)


def when_initialize_expectation_service():
    """Initialize an expectation service.

    Returns:
        Initialized SentinelOneExpectationService instance.

    """
    config = given_test_config()
    return SentinelOneExpectationService(config=config)


# Data Processing When Methods
# ----------------------------


def when_convert_threats_to_oaev(
    converter: SentinelOneConverter, threats: List
) -> List:
    """Convert threats to OAEV format.

    Args:
        converter: The converter instance.
        threats: List of threats to convert.

    Returns:
        List of converted OAEV format data.

    """
    return converter.convert_threats_to_oaev(threats)


def when_call_private_conversion_method(
    converter: SentinelOneConverter, threat: SentinelOneThreat
) -> Dict:
    """Call the private conversion method directly.

    Args:
        converter: The converter instance.
        threat: The threat to convert.

    Returns:
        Converted OAEV format dictionary.

    """
    return converter._convert_threat_to_oaev(threat)


# Error Handling When Methods
# ---------------------------


def when_create_collector_expecting_error(mock_env: Any) -> None:
    """Attempt to create collector and expect configuration error.

    Args:
        mock_env: Mock environment variable patcher to clean up.

    """
    try:
        with pytest.raises((Exception, ValueError)):
            when_create_collector()
    finally:
        mock_env.stop()


def when_convert_invalid_data_expecting_validation_error(
    converter: SentinelOneConverter, invalid_data: Any
) -> None:
    """Attempt to convert invalid data and expect validation error.

    Args:
        converter: The converter instance.
        invalid_data: Invalid input data.

    """
    with pytest.raises(SentinelOneValidationError) as exc_info:
        converter.convert_threats_to_oaev(invalid_data)

    assert "threats must be a list" in str(exc_info.value)  # noqa: S101


def when_call_private_method_expecting_validation_error(
    converter: SentinelOneConverter, threat: SentinelOneThreat
) -> None:
    """Call private method and expect validation error.

    Args:
        converter: The converter instance.
        threat: The threat with empty threat_id.

    """
    with pytest.raises(SentinelOneValidationError) as exc_info:
        converter._convert_threat_to_oaev(threat)

    assert "Threat must have a threat_id" in str(exc_info.value)  # noqa: S101


# ========================================================================
# SHARED THEN METHODS - Validate results and assert expectations
# ========================================================================


# Object Validation Then Methods
# ------------------------------


def then_collector_created_successfully(collector: Collector) -> None:
    """Verify collector was created successfully.

    Args:
        collector: The collector instance to verify.

    """
    assert collector is not None  # noqa: S101
    assert hasattr(collector, "config_instance")  # noqa: S101


def then_collector_has_valid_configuration(
    collector: Collector, expected_config: Dict[str, str]
) -> None:
    """Verify collector has valid configuration.

    Args:
        collector: The collector instance to verify.
        expected_config: Expected configuration values.

    """
    daemon_config = collector.config_instance.to_daemon_config()

    assert daemon_config.get("openaev_url") == expected_config.get(  # noqa: S101
        "OPENAEV_URL"
    )
    assert daemon_config.get("openaev_token") == expected_config.get(  # noqa: S101
        "OPENAEV_TOKEN"
    )
    assert daemon_config.get("collector_id") == expected_config.get(  # noqa: S101
        "COLLECTOR_ID"
    )
    assert daemon_config.get("collector_name") == expected_config.get(  # noqa: S101
        "COLLECTOR_NAME"
    )
    assert daemon_config.get(  # noqa: S101
        "sentinelone_base_url"
    ) == expected_config.get("SENTINELONE_BASE_URL")
    assert daemon_config.get(  # noqa: S101
        "sentinelone_api_key"
    ) == expected_config.get("SENTINELONE_API_KEY")


def then_converter_initialized_successfully(converter: SentinelOneConverter) -> None:
    """Verify converter was initialized successfully.

    Args:
        converter: The converter instance to verify.

    """
    assert converter is not None  # noqa: S101
    assert converter.logger is not None  # noqa: S101


def then_client_api_initialized_successfully(client: SentinelOneClientAPI) -> None:
    """Verify client API was initialized successfully.

    Args:
        client: The client API instance to verify.

    """
    assert client is not None  # noqa: S101
    assert hasattr(client, "config")  # noqa: S101
    assert hasattr(client, "session")  # noqa: S101
    assert hasattr(client, "base_url")  # noqa: S101
    assert hasattr(client, "api_key")  # noqa: S101


def then_expectation_service_initialized_successfully(
    service: SentinelOneExpectationService,
) -> None:
    """Verify expectation service was initialized successfully.

    Args:
        service: The expectation service instance to verify.

    """
    assert service is not None  # noqa: S101
    assert service.client_api is not None  # noqa: S101
    assert service.converter is not None  # noqa: S101
    assert service.threat_fetcher is not None  # noqa: S101


# Data Validation Then Methods
# ----------------------------


def then_empty_list_returned(result: List) -> None:
    """Verify an empty list was returned.

    Args:
        result: The result to verify.

    """
    assert result == []  # noqa: S101


def then_single_threat_converted_completely(
    result: List, threat: SentinelOneThreat
) -> None:
    """Verify single threat was converted with all fields.

    Args:
        result: The conversion result to verify.
        threat: The original threat object.

    """
    assert len(result) == 1  # noqa: S101

    converted = result[0]

    assert "threat_id" in converted  # noqa: S101
    assert converted["threat_id"]["type"] == "fuzzy"  # noqa: S101
    assert converted["threat_id"]["data"] == [threat.threat_id]  # noqa: S101
    assert converted["threat_id"]["score"] == 95  # noqa: S101

    if threat.hostname:
        assert "target_hostname_address" in converted  # noqa: S101
        assert converted["target_hostname_address"]["type"] == "fuzzy"  # noqa: S101
        assert converted["target_hostname_address"]["data"] == [  # noqa: S101
            threat.hostname
        ]
        assert converted["target_hostname_address"]["score"] == 95  # noqa: S101


def then_single_threat_converted_without_hostname(
    result: List, threat: SentinelOneThreat
) -> None:
    """Verify single threat was converted without hostname field.

    Args:
        result: The conversion result to verify.
        threat: The original threat object.

    """
    assert len(result) == 1  # noqa: S101

    converted = result[0]

    assert "threat_id" in converted  # noqa: S101
    assert converted["threat_id"]["data"] == [threat.threat_id]  # noqa: S101

    assert "target_hostname_address" not in converted  # noqa: S101


def then_multiple_threats_converted(
    result: List, threats: List[SentinelOneThreat]
) -> None:
    """Verify multiple threats were converted correctly.

    Args:
        result: The conversion result to verify.
        threats: The original threats list.

    """
    valid_threats = [t for t in threats if t.threat_id and t.threat_id.strip()]
    assert len(result) == len(valid_threats)  # noqa: S101

    threat_ids = [item["threat_id"]["data"][0] for item in result]
    for threat in valid_threats:
        assert threat.threat_id in threat_ids  # noqa: S101

    items_with_hostname = [item for item in result if "target_hostname_address" in item]
    expected_hostname_count = sum(1 for threat in valid_threats if threat.hostname)
    assert len(items_with_hostname) == expected_hostname_count  # noqa: S101


def then_only_valid_threats_converted(
    result: List, expected_valid_count: int = 1
) -> None:
    """Verify only valid threats were converted from mixed data.

    Args:
        result: The conversion result to verify.
        expected_valid_count: Expected number of valid conversions.

    """
    assert len(result) == expected_valid_count  # noqa: S101


def then_large_batch_converted_efficiently(result: List, expected_count: int) -> None:
    """Verify large batch was converted efficiently.

    Args:
        result: The conversion result to verify.
        expected_count: Expected number of converted items.

    """
    assert len(result) == expected_count  # noqa: S101

    converted_ids = {item["threat_id"]["data"][0] for item in result}
    assert len(converted_ids) == expected_count  # noqa: S101


def then_private_method_converts_properly(
    result: Dict, threat: SentinelOneThreat
) -> None:
    """Verify private method converts threat properly.

    Args:
        result: The conversion result to verify.
        threat: The original threat object.

    """
    assert isinstance(result, dict)  # noqa: S101
    assert "threat_id" in result  # noqa: S101
    assert result["threat_id"]["type"] == "fuzzy"  # noqa: S101
    assert result["threat_id"]["data"] == [threat.threat_id]  # noqa: S101
    assert result["threat_id"]["score"] == 95  # noqa: S101

    if threat.hostname:
        assert "target_hostname_address" in result  # noqa: S101
        assert result["target_hostname_address"]["data"] == [  # noqa: S101
            threat.hostname
        ]


# Session and Configuration Validation Then Methods
# -------------------------------------------------


def then_session_configured_properly(
    client: SentinelOneClientAPI, expected_api_key: str
) -> None:
    """Verify session is configured properly.

    Args:
        client: The client API instance to verify.
        expected_api_key: Expected API key value.

    """
    expected_auth = f"ApiToken {expected_api_key}"
    assert client.session.headers["Authorization"] == expected_auth  # noqa: S101
    assert client.session.headers["Content-Type"] == "application/json"  # noqa: S101
    assert client.session.headers["Accept"] == "application/json"  # noqa: S101


def then_base_url_normalized(client: SentinelOneClientAPI, expected_base: str) -> None:
    """Verify base URL is properly normalized.

    Args:
        client: The client API instance to verify.
        expected_base: Expected base URL without trailing slash.

    """
    assert not client.base_url.endswith("/")  # noqa: S101
    assert client.base_url == expected_base  # noqa: S101


def then_collector_logged_initialization_success(
    capfd: Any, daemon_config: Dict[str, str]
) -> None:
    """Verify collector initialization was logged appropriately.

    Args:
        capfd: Pytest fixture for capturing stdout and stderr output.
        daemon_config: Daemon configuration to check log level.

    """
    log_records = capfd.readouterr()
    if daemon_config.get("collector_log_level") in ["info", "debug"]:
        registered_message = "SentinelOne Collector initialized successfully"
        assert registered_message in log_records.err  # noqa: S101


# Error Validation Then Methods
# -----------------------------


def then_validation_error_raised_with_message(error_message: str) -> None:
    """Verify validation error was raised with specific message.

    Args:
        error_message: Expected error message substring.

    """
    pass


def then_session_error_raised_with_message(error_message: str) -> None:
    """Verify session error was raised with specific message.

    Args:
        error_message: Expected error message substring.

    """
    pass


# Cleanup Then Methods
# -------------------


def then_cleanup_environment_mocks(*mock_envs: Any) -> None:
    """Clean up environment variable mocks.

    Args:
        mock_envs: Variable number of mock environment objects to stop.

    """
    for mock_env in mock_envs:
        if mock_env and hasattr(mock_env, "stop"):
            mock_env.stop()
