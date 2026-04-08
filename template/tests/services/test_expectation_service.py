"""Essential tests for Template Expectation Service - Gherkin GWT Format."""

from unittest.mock import Mock
from uuid import uuid4

import pytest
from pyoaev.signatures.types import SignatureTypes
from src.services.expectation_service import (
    ExpectationResult,
    TemplateExpectationService,
)
from src.services.model_data import TemplateData
from tests.gwt_shared import (
    given_initialized_expectation_service,
    given_test_config,
    then_expectation_service_initialized_successfully,
)

# --------
# Scenarios
# --------


# Scenario: Initialize expectation service with valid configuration
def test_initialize_expectation_service_with_valid_config():
    """Scenario: Initialize expectation service with valid configuration."""
    # Given: A valid configuration is available
    config = _given_valid_config_for_expectation_service()

    # When: I initialize the expectation service
    service = _when_initialize_expectation_service(config)

    # Then: The expectation service should be initialized successfully
    _then_expectation_service_initialized_with_valid_config(service, config)


# Scenario: Initialize with invalid configuration raises error
def test_initialize_with_invalid_config():
    """Scenario: Initialize with invalid configuration raises error."""
    # Given: An invalid configuration (None)
    invalid_config = _given_invalid_config()

    # When: I attempt to initialize the expectation service
    # Then: An AttributeError should be raised
    _when_initialize_expectation_service_then_attribute_error_raised(invalid_config)


# Scenario: Handle single detection expectation
def test_handle_single_detection_expectation():
    """Scenario: Handle single detection expectation."""
    # Given: An initialized expectation service
    service = _given_initialized_expectation_service()
    # Given: A detection helper
    detection_helper = _given_mock_detection_helper()
    # Given: Mock data are available
    _given_mock_data_for_service(service)
    # Given: A detection expectation
    expectation = _given_detection_expectation()

    # When: I handle the detection expectation
    result = _when_handle_batch_expectations(service, [expectation], detection_helper)

    # Then: A detection result should be returned
    _then_detection_result_returned(result, expectation)


# Scenario: Handle prevention expectation
def test_handle_prevention_expectation():
    """Scenario: Handle prevention expectation."""
    # Given: An initialized expectation service
    service = _given_initialized_expectation_service()
    # Given: A detection helper
    detection_helper = _given_mock_detection_helper()
    # Given: A prevention expectation
    expectation = _given_prevention_expectation()

    # When: I handle the prevention expectation
    result = _when_handle_batch_expectations(service, [expectation], detection_helper)

    # Then: A prevention result should be returned
    _then_prevention_result_returned(result, expectation)


# Scenario: Match data to expectations
def test_match_data_to_expectations():
    """Scenario: Match data to expectations."""
    # Given: An initialized expectation service
    service = _given_initialized_expectation_service()
    # Given: data and expectations
    data, expectations = _given_data_and_expectations()

    # When: I match data to expectations
    matches = _when_match_data_to_expectations(service, data, expectations)

    # Then: Proper matches should be found
    _then_proper_matches_found(matches, data, expectations)
    # Then: The match should succeed without requiring mitigation
    _then_match_succeeds_without_mitigation_requirement(matches)


# --------
# Given Methods
# --------


# Given: A valid configuration is available
def _given_valid_config_for_expectation_service():
    """Create a valid configuration for expectation service testing.

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


# Given: An initialized expectation service
def _given_initialized_expectation_service():
    """Create an initialized expectation service.

    Returns:
        Initialized TemplateExpectationService instance.

    """
    return given_initialized_expectation_service()


# Given: A detection helper
def _given_mock_detection_helper():
    """Create a mock detection helper.

    Returns:
        Mock detection helper instance.

    """
    return Mock()


# Given: Mock data are available
def _given_mock_data_for_service(service):
    """Set up mock data for the service.

    Args:
        service: The expectation service instance.

    """
    mock_data = [
        TemplateData(
            key="test_data_1",
        )
    ]
    service.data_fetcher.fetch_data_for_time_window = Mock(return_value=mock_data)


# Given: A detection expectation
def _given_detection_expectation():
    """Create a detection expectation.

    Returns:
        Mock detection expectation.

    """
    hostname_sig = _create_mock_signature(
        SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS, "target-host.example.com"
    )
    end_date_sig = _create_mock_signature(
        Mock(value="end_date"), "2024-01-01T12:00:00Z"
    )

    expectation = _create_mock_expectation(
        expectation_id="detection_test_1", signatures=[hostname_sig, end_date_sig]
    )
    return expectation


# Given: A prevention expectation
def _given_prevention_expectation():
    """Create a prevention expectation.

    Returns:
        Mock prevention expectation.

    """
    hostname_sig = _create_mock_signature(
        SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS, "target-host.example.com"
    )
    end_date_sig = _create_mock_signature(
        Mock(value="end_date"), "2024-01-01T12:00:00Z"
    )

    expectation = _create_mock_expectation(
        expectation_id="prevention_test_1", signatures=[hostname_sig, end_date_sig]
    )
    expectation.is_prevention = True
    return expectation


# Given: data and expectations
def _given_data_and_expectations():
    """Create data and expectations for matching tests.

    Returns:
        Tuple of (data, expectations).

    """
    data = [
        TemplateData(
            key="match_data_1",
        )
    ]

    hostname_sig = _create_mock_signature(
        SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS, "match-host.example.com"
    )
    expectation = _create_mock_expectation(signatures=[hostname_sig])
    expectations = [expectation]

    return data, expectations


# Given: A static expectation
def _given_static_expectation():
    """Create a static expectation.

    Returns:
        Mock static expectation.

    """
    hostname_sig = _create_mock_signature(
        SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS, "static-host.example.com"
    )
    end_date_sig = _create_mock_signature(
        Mock(value="end_date"), "2024-01-01T12:00:00Z"
    )

    expectation = _create_mock_expectation(
        expectation_id="static_test_1", signatures=[hostname_sig, end_date_sig]
    )
    return expectation


# --------
# When Methods
# --------


# When: I initialize the expectation service
def _when_initialize_expectation_service(config):
    """Initialize expectation service with given configuration.

    Args:
        config: Configuration object to use.

    Returns:
        Initialized TemplateExpectationService instance.

    """
    return TemplateExpectationService(config=config)


# When: I attempt to initialize with invalid config and expect AttributeError
def _when_initialize_expectation_service_then_attribute_error_raised(invalid_config):
    """Attempt to initialize with invalid config and expect AttributeError.

    Args:
        invalid_config: Invalid configuration to test.

    """
    with pytest.raises(AttributeError):
        TemplateExpectationService(config=invalid_config)


# When: I handle batch expectations
def _when_handle_batch_expectations(service, expectations, detection_helper):
    """Handle batch expectations using the service.

    Args:
        service: The expectation service instance.
        expectations: List of expectations to handle.
        detection_helper: The detection helper to use.

    Returns:
        List of expectation results.

    """
    results, _ = service.handle_batch_expectations(expectations, detection_helper)
    return results


# When: I match data to expectations
def _when_match_data_to_expectations(service, data, expectations):
    """Match data to expectations.

    Args:
        service: The expectation service instance.
        data: List of data.
        expectations: List of expectations.

    Returns:
        List of matches.

    """
    return service._match_data_to_expectations(expectations, data, "detection")


# When: I check if expectation matches data
def _when_check_expectation_matches_data(service, expectation, data):
    """Check if expectation matches data.

    Args:
        service: The expectation service instance.
        expectation: The expectation to check.
        data: The data to match against.

    Returns:
        Boolean indicating if there's a match.

    """
    expectation_type = (
        "prevention"
        if hasattr(expectation, "is_prevention") and expectation.is_prevention
        else "detection"
    )
    return service._expectation_matches_data(expectation, data, expectation_type)


# --------
# Then Methods
# --------


# Then: The expectation service should be initialized successfully with valid config
def _then_expectation_service_initialized_with_valid_config(service, config):
    """Verify expectation service was initialized successfully.

    Args:
        service: The service instance to verify.
        config: The configuration used for initialization.

    """
    then_expectation_service_initialized_successfully(service)
    assert service.batch_size == config.template.expectation_batch_size  # noqa: S101


# Then: A detection result should be returned
def _then_detection_result_returned(result, expectation):
    """Verify a detection result was returned.

    Args:
        result: The result to verify.
        expectation: The original expectation.

    """
    assert len(result) == 1  # noqa: S101
    assert isinstance(result[0], ExpectationResult)  # noqa: S101
    assert result[0].expectation_id == expectation.inject_expectation_id  # noqa: S101


# Then: A prevention result should be returned
def _then_prevention_result_returned(result, expectation):
    """Verify a prevention result was returned.

    Args:
        result: The result to verify.
        expectation: The original expectation.

    """
    assert len(result) == 1  # noqa: S101
    assert isinstance(result[0], ExpectationResult)  # noqa: S101
    assert result[0].expectation_id == expectation.inject_expectation_id  # noqa: S101


# Then: Proper matches should be found
def _then_proper_matches_found(matches, data, expectations):
    """Verify proper matches were found.

    Args:
        matches: The found matches.
        data: The original data.
        expectations: The original expectations.

    """
    assert len(matches) > 0  # noqa: S101


# Then: The match should succeed without requiring mitigation
def _then_match_succeeds_without_mitigation_requirement(matches):
    """Verify match succeeds without requiring mitigation.

    Args:
        matches: The match results.

    """
    assert matches is not None  # noqa: S101


# Then: A static result with Deep Visibility events should be returned
def _then_static_result_with_deep_visibility_returned(result, expectation):
    """Verify a static result with Deep Visibility events was returned.

    Args:
        result: The result to verify.
        expectation: The original expectation.

    """
    assert len(result) == 1  # noqa: S101
    assert isinstance(result[0], ExpectationResult)  # noqa: S101
    assert result[0].expectation_id == expectation.inject_expectation_id  # noqa: S101
    assert result[0].is_valid  # noqa: S101
    assert len(result[0].matched_alerts) > 0  # noqa: S101


# Then: A static result without Deep Visibility events should be returned
def _then_static_result_without_deep_visibility_returned(result, expectation):
    """Verify a static result without Deep Visibility events was returned.

    Args:
        result: The result to verify.
        expectation: The original expectation.

    """
    assert len(result) == 1  # noqa: S101
    assert isinstance(result[0], ExpectationResult)  # noqa: S101
    assert result[0].expectation_id == expectation.inject_expectation_id  # noqa: S101
    assert result[0].is_valid  # noqa: S101


# --------
# Helper Methods
# --------


def _create_mock_signature(sig_type, value):
    """Create a mock signature with proper attributes.

    Args:
        sig_type: The signature type.
        value: The signature value.

    Returns:
        Mock signature object.

    """
    sig = Mock()
    sig.type = sig_type
    sig.value = value
    return sig


def _create_mock_expectation(expectation_id=None, signatures=None):
    """Create a mock expectation with proper attributes.

    Args:
        expectation_id: The expectation ID.
        signatures: List of signatures.

    Returns:
        Mock expectation object.

    """
    if expectation_id is None:
        expectation_id = str(uuid4())
    if signatures is None:
        signatures = []

    expectation = Mock()
    expectation.inject_expectation_id = expectation_id
    expectation.inject_expectation_signatures = signatures
    expectation.id = expectation_id
    return expectation
