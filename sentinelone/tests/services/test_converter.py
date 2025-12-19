"""Essential tests for SentinelOne Converter services - Gherkin GWT Format."""

import pytest
from src.services.converter import SentinelOneConverter
from src.services.exception import SentinelOneValidationError
from src.services.model_threat import SentinelOneThreat

# --------
# Scenarios
# --------


# Scenario: Initialize converter successfully
def test_initialize_converter():
    """Scenario: Initialize converter successfully."""
    # Given: All dependencies are available
    _given_converter_dependencies_available()

    # When: I initialize the converter
    converter = _when_initialize_converter()

    # Then: The converter should be initialized successfully
    _then_converter_initialized_successfully(converter)


# Scenario: Convert empty threats list
def test_convert_empty_threats():
    """Scenario: Convert empty threats list."""
    # Given: A converter is available
    converter = _given_initialized_converter()

    # When: I convert an empty threats list
    result = _when_convert_threats_to_oaev(converter, [])

    # Then: An empty list should be returned
    _then_empty_list_returned(result)


# Scenario: Convert single threat with complete data
def test_convert_single_threat_complete_data():
    """Scenario: Convert single threat with complete data."""
    # Given: A converter is available
    converter = _given_initialized_converter()
    # Given: A threat with complete data
    threat = _given_threat_with_complete_data()

    # When: I convert the threat to OAEV format
    result = _when_convert_threats_to_oaev(converter, [threat])

    # Then: The threat should be converted with all fields
    _then_single_threat_converted_completely(result, threat)


# Scenario: Convert invalid data type
def test_convert_invalid_data_type():
    """Scenario: Convert invalid data type."""
    # Given: A converter is available
    converter = _given_initialized_converter()
    # Given: Invalid input data (not a list)
    invalid_data = _given_invalid_input_data()

    # When: I attempt to convert invalid data
    # Then: A validation error should be raised
    _when_convert_invalid_data_then_validation_error_raised(converter, invalid_data)


# --------
# Given Methods
# --------


# Given: All dependencies are available
def _given_converter_dependencies_available():
    """Ensure all converter dependencies are available."""
    pass


# Given: A converter is available
def _given_initialized_converter() -> SentinelOneConverter:
    """Create and return an initialized converter.

    Returns:
        Initialized SentinelOneConverter instance.

    """
    return SentinelOneConverter()


# Given: A threat with complete data
def _given_threat_with_complete_data() -> SentinelOneThreat:
    """Create a threat with complete data.

    Returns:
        SentinelOneThreat with threat_id and hostname.

    """
    return SentinelOneThreat(
        threat_id="complete_threat_123", hostname="complete-host.example.com"
    )


# Given: Invalid input data (not a list)
def _given_invalid_input_data() -> str:
    """Create invalid input data for testing.

    Returns:
        Invalid data (string instead of list).

    """
    return "invalid_string_data"


# --------
# When Methods
# --------


# When: I initialize the converter
def _when_initialize_converter() -> SentinelOneConverter:
    """Initialize the converter.

    Returns:
        Initialized SentinelOneConverter instance.

    """
    return SentinelOneConverter()


# When: I convert threats to OAEV format
def _when_convert_threats_to_oaev(
    converter: SentinelOneConverter, threats: list
) -> list:
    """Convert threats to OAEV format.

    Args:
        converter: The converter instance.
        threats: List of threats to convert.

    Returns:
        List of converted OAEV format data.

    """
    return converter.convert_threats_to_oaev(threats)


# When: I attempt to convert invalid data and expect validation error
def _when_convert_invalid_data_then_validation_error_raised(
    converter: SentinelOneConverter, invalid_data: str
) -> None:
    """Attempt to convert invalid data and expect validation error.

    Args:
        converter: The converter instance.
        invalid_data: Invalid input data.

    """
    with pytest.raises(SentinelOneValidationError) as exc_info:
        converter.convert_threats_to_oaev(invalid_data)

    assert "threats must be a list" in str(exc_info.value)  # noqa: S101


# --------
# Then Methods
# --------


# Then: The converter should be initialized successfully
def _then_converter_initialized_successfully(converter: SentinelOneConverter) -> None:
    """Verify the converter was initialized successfully.

    Args:
        converter: The converter instance to verify.

    """
    assert converter is not None  # noqa: S101
    assert converter.logger is not None  # noqa: S101


# Then: An empty list should be returned
def _then_empty_list_returned(result: list) -> None:
    """Verify an empty list was returned.

    Args:
        result: The conversion result to verify.

    """
    assert result == []  # noqa: S101


# Then: The threat should be converted with all fields
def _then_single_threat_converted_completely(
    result: list, threat: SentinelOneThreat
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

    assert "target_hostname_address" in converted  # noqa: S101
    assert converted["target_hostname_address"]["type"] == "fuzzy"  # noqa: S101
    assert converted["target_hostname_address"]["data"] == [  # noqa: S101
        threat.hostname
    ]
    assert converted["target_hostname_address"]["score"] == 95  # noqa: S101
