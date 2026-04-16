"""Essential tests for Template Converter services - Gherkin GWT Format."""

import pytest
from src.services.converter import TemplateConverter
from src.services.exception import TemplateValidationError
from src.services.model_data import TemplateData

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


# Scenario: Convert empty data list
def test_convert_empty_data():
    """Scenario: Convert empty data list."""
    # Given: A converter is available
    converter = _given_initialized_converter()

    # When: I convert an empty data list
    result = _when_convert_data_to_oaev(converter, [])

    # Then: An empty list should be returned
    _then_empty_list_returned(result)


# Scenario: Convert single data with complete data
def test_convert_single_data_complete_data():
    """Scenario: Convert single data with complete data."""
    # Given: A converter is available
    converter = _given_initialized_converter()
    # Given: A data with complete data
    data = _given_data_with_complete_data()

    # When: I convert the data to OAEV format
    result = _when_convert_data_to_oaev(converter, [data])

    # Then: The data should be converted with all fields
    _then_single_data_converted_completely(result, data)


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
def _given_initialized_converter() -> TemplateConverter:
    """Create and return an initialized converter.

    Returns:
        Initialized TemplateConverter instance.

    """
    return TemplateConverter()


# Given: A data with complete data
def _given_data_with_complete_data() -> TemplateData:
    """Create a data with complete data.

    Returns:
        TemplateData with key.

    """
    return TemplateData(key="complete_data_123")


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
def _when_initialize_converter() -> TemplateConverter:
    """Initialize the converter.

    Returns:
        Initialized TemplateConverter instance.

    """
    return TemplateConverter()


# When: I convert data to OAEV format
def _when_convert_data_to_oaev(converter: TemplateConverter, data: list) -> list:
    """Convert data to OAEV format.

    Args:
        converter: The converter instance.
        data: List of data to convert.

    Returns:
        List of converted OAEV format data.

    """
    return converter.convert_data_to_oaev(data)


# When: I attempt to convert invalid data and expect validation error
def _when_convert_invalid_data_then_validation_error_raised(
    converter: TemplateConverter, invalid_data: str
) -> None:
    """Attempt to convert invalid data and expect validation error.

    Args:
        converter: The converter instance.
        invalid_data: Invalid input data.

    """
    with pytest.raises(TemplateValidationError) as exc_info:
        converter.convert_data_to_oaev(invalid_data)

    assert "data must be a list" in str(exc_info.value)  # noqa: S101


# --------
# Then Methods
# --------


# Then: The converter should be initialized successfully
def _then_converter_initialized_successfully(converter: TemplateConverter) -> None:
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


# Then: The data should be converted with all fields
def _then_single_data_converted_completely(result: list, data: TemplateData) -> None:
    """Verify single data was converted with all fields.

    Args:
        result: The conversion result to verify.
        data: The original data object.

    """
    assert len(result) == 1  # noqa: S101
