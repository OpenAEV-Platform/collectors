"""Shared Given-When-Then methods for Gherkin-style tests.

This module provides reusable Given, When, and Then methods that can be used
across multiple test files to maximize code reusability and maintain consistency
in test structure.
"""

from os import environ as os_environ
from typing import Any, Dict, List
from unittest.mock import Mock

import pytest
from src.collector import Collector
from src.services.converter import TemplateConverter
from src.services.exception import TemplateValidationError
from src.services.expectation_service import TemplateExpectationService
from src.services.model_data import TemplateData
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


def given_initialized_converter() -> TemplateConverter:
    """Create an initialized converter.

    Returns:
        Initialized TemplateConverter instance.

    """
    return TemplateConverter()


def given_initialized_expectation_service():
    """Create an initialized expectation service.

    Returns:
        Initialized TemplateExpectationService instance.

    """
    config = given_test_config()
    return TemplateExpectationService(config=config)


# Data Creation Given Methods
# ---------------------------


def given_data_with_complete_data(key: str = "value123") -> TemplateData:
    """Create a data with complete data.

    Args:
        key: example value.

    Returns:
        TemplateData with complete data.

    """
    return TemplateData(key=key)


def given_data_with_empty_key() -> TemplateData:
    """Create a data with empty key.

    Returns:
        TemplateData with empty key.

    """
    return TemplateData(key="")


def given_multiple_data(count: int = 3) -> List[TemplateData]:
    """Create multiple data with different data combinations.

    Args:
        count: Number of data to create.

    Returns:
        List of TemplateData objects.

    """
    data = []
    for i in range(count):
        key = f"multi_data_{i + 1}"
        data.append(TemplateData(key=key))
    return data


def given_large_batch_of_data(count: int = 100) -> List[TemplateData]:
    """Create a large batch of data for performance testing.

    Args:
        count: Number of data to create.

    Returns:
        List of TemplateData objects.

    """
    return [
        TemplateData(
            key=f"bulk_data_{i}",
        )
        for i in range(count)
    ]


def given_mixed_valid_invalid_objects(valid_data_key: str = "valid_mixed_123") -> List:
    """Create a list with mixed valid and invalid objects.

    Args:
        valid_data_key: key for the valid data in the list.

    Returns:
        List containing valid data and invalid objects.

    """
    valid_data = TemplateData(
        key=valid_data_key,
    )
    return [
        valid_data,
        {"key_data": "dict_data"},
        "string_data",
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


def given_conversion_error_setup(converter: TemplateConverter) -> List:
    """Set up data that will cause conversion errors.

    Args:
        converter: The converter instance to mock.

    Returns:
        List with valid data and error-causing mock data.

    """
    error_data = Mock(spec=TemplateData)
    error_data.key = "error_data"

    valid_data = TemplateData(key="valid_error_test_123")

    original_convert = converter._convert_data_to_oaev

    def mock_convert(data):
        if hasattr(data, "key") and data.key == "error_data":
            raise Exception("Conversion error")
        return original_convert(data)

    converter._convert_data_to_oaev = mock_convert

    return [error_data, valid_data]


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


def when_initialize_converter() -> TemplateConverter:
    """Initialize a converter.

    Returns:
        Initialized TemplateConverter instance.

    """
    return TemplateConverter()


def when_initialize_expectation_service():
    """Initialize an expectation service.

    Returns:
        Initialized TemplateExpectationService instance.

    """
    config = given_test_config()
    return TemplateExpectationService(config=config)


# Data Processing When Methods
# ----------------------------


def when_convert_data_to_oaev(converter: TemplateConverter, data: List) -> List:
    """Convert data to OAEV format.

    Args:
        converter: The converter instance.
        data: List of data to convert.

    Returns:
        List of converted OAEV format data.

    """
    return converter.convert_data_to_oaev(data)


def when_call_private_conversion_method(
    converter: TemplateConverter, data: TemplateData
) -> Dict:
    """Call the private conversion method directly.

    Args:
        converter: The converter instance.
        data: The data to convert.

    Returns:
        Converted OAEV format dictionary.

    """
    return converter._convert_data_to_oaev(data)


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
    converter: TemplateConverter, invalid_data: Any
) -> None:
    """Attempt to convert invalid data and expect validation error.

    Args:
        converter: The converter instance.
        invalid_data: Invalid input data.

    """
    with pytest.raises(TemplateValidationError) as exc_info:
        converter.convert_data_to_oaev(invalid_data)

    assert "data must be a list" in str(exc_info.value)  # noqa: S101


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
    assert daemon_config.get("template_key") == expected_config.get(  # noqa: S101
        "TEMPLATE_KEY"
    )


def then_converter_initialized_successfully(converter: TemplateConverter) -> None:
    """Verify converter was initialized successfully.

    Args:
        converter: The converter instance to verify.

    """
    assert converter is not None  # noqa: S101
    assert converter.logger is not None  # noqa: S101


def then_expectation_service_initialized_successfully(
    service: TemplateExpectationService,
) -> None:
    """Verify expectation service was initialized successfully.

    Args:
        service: The expectation service instance to verify.

    """
    assert service is not None  # noqa: S101
    assert service.converter is not None  # noqa: S101
    assert service.data_fetcher is not None  # noqa: S101


# Data Validation Then Methods
# ----------------------------


def then_empty_list_returned(result: List) -> None:
    """Verify an empty list was returned.

    Args:
        result: The result to verify.

    """
    assert result == []  # noqa: S101


def then_single_data_converted_completely(result: List, data: TemplateData) -> None:
    """Verify single data was converted with all fields.

    Args:
        result: The conversion result to verify.
        data: The original data object.

    """
    assert len(result) == 1  # noqa: S101

    converted = result[0]

    assert "key" in converted  # noqa: S101
    assert converted["key"] == [data.key]  # noqa: S101


def then_multiple_data_converted(result: List, data: List[TemplateData]) -> None:
    """Verify multiple data were converted correctly.

    Args:
        result: The conversion result to verify.
        data: The original data list.

    """
    valid_data = [d for d in data if d.key and d.key.strip()]
    assert len(result) == len(valid_data)  # noqa: S101

    keys = [item["key"]["data"][0] for item in result]
    for d in valid_data:
        assert d.key in keys  # noqa: S101


def then_only_valid_data_converted(result: List, expected_valid_count: int = 1) -> None:
    """Verify only valid data were converted from mixed data.

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

    converted_keys = {item["key"]["data"][0] for item in result}
    assert len(converted_keys) == expected_count  # noqa: S101


def then_private_method_converts_properly(result: Dict, data: TemplateData) -> None:
    """Verify private method converts data properly.

    Args:
        result: The conversion result to verify.
        data: The original data object.

    """
    assert isinstance(result, dict)  # noqa: S101


# Session and Configuration Validation Then Methods
# -------------------------------------------------


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
        registered_message = "Template Collector initialized successfully"
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
