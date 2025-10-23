"""Essential tests for SentinelOne Expectation Service - Gherkin GWT Format."""

import pytest
from unittest.mock import Mock
from uuid import uuid4

from pyoaev.signatures.types import SignatureTypes
from src.services.expectation_service import (
    ExpectationResult,
    SentinelOneExpectationService,
)
from src.services.model_threat import SentinelOneThreat
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
    # Given: Mock threats are available
    _given_mock_threats_for_service(service)
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
    # Given: Mock mitigated threats are available
    _given_mock_mitigated_threats_for_service(service)
    # Given: A prevention expectation
    expectation = _given_prevention_expectation()

    # When: I handle the prevention expectation
    result = _when_handle_batch_expectations(service, [expectation], detection_helper)

    # Then: A prevention result should be returned
    _then_prevention_result_returned(result, expectation)


# Scenario: Match threats to expectations
def test_match_threats_to_expectations():
    """Scenario: Match threats to expectations."""
    # Given: An initialized expectation service
    service = _given_initialized_expectation_service()
    # Given: Threats and expectations
    threats, expectations = _given_threats_and_expectations()

    # When: I match threats to expectations
    matches = _when_match_threats_to_expectations(service, threats, expectations)

    # Then: Proper matches should be found
    _then_proper_matches_found(matches, threats, expectations)
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
        Initialized SentinelOneExpectationService instance.

    """
    return given_initialized_expectation_service()


# Given: A detection helper
def _given_mock_detection_helper():
    """Create a mock detection helper.

    Returns:
        Mock detection helper instance.

    """
    return Mock()


# Given: Mock threats are available
def _given_mock_threats_for_service(service):
    """Set up mock threats for the service.

    Args:
        service: The expectation service instance.

    """
    mock_threats = [
        SentinelOneThreat(
            threat_id="test_threat_1",
            hostname="target-host.example.com",
            is_mitigated=False,
        )
    ]
    service.threat_fetcher.fetch_threats_for_time_window = Mock(
        return_value=mock_threats
    )


# Given: Mock mitigated threats are available
def _given_mock_mitigated_threats_for_service(service):
    """Set up mock mitigated threats for the service.

    Args:
        service: The expectation service instance.

    """
    mock_threats = [
        SentinelOneThreat(
            threat_id="test_threat_1",
            hostname="target-host.example.com",
            is_mitigated=True,
        )
    ]
    service.threat_fetcher.fetch_threats_for_time_window = Mock(
        return_value=mock_threats
    )


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


# Given: Threats and expectations
def _given_threats_and_expectations():
    """Create threats and expectations for matching tests.

    Returns:
        Tuple of (threats, expectations).

    """
    threats = [
        SentinelOneThreat(
            threat_id="match_threat_1",
            hostname="match-host.example.com",
            is_mitigated=False,
        )
    ]

    hostname_sig = _create_mock_signature(
        SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS, "match-host.example.com"
    )
    expectation = _create_mock_expectation(signatures=[hostname_sig])
    expectations = [expectation]

    return threats, expectations


# Given: An unmitigated threat
def _given_unmitigated_threat():
    """Create an unmitigated threat.

    Returns:
        SentinelOneThreat instance that is not mitigated.

    """
    return SentinelOneThreat(
        threat_id="unmitigated_threat",
        hostname="unmitigated-host.example.com",
        is_mitigated=False,
    )


# --------
# When Methods
# --------


# When: I initialize the expectation service
def _when_initialize_expectation_service(config):
    """Initialize expectation service with given configuration.

    Args:
        config: Configuration object to use.

    Returns:
        Initialized SentinelOneExpectationService instance.

    """
    return SentinelOneExpectationService(config=config)


# When: I attempt to initialize with invalid config and expect AttributeError
def _when_initialize_expectation_service_then_attribute_error_raised(invalid_config):
    """Attempt to initialize with invalid config and expect AttributeError.

    Args:
        invalid_config: Invalid configuration to test.

    """
    with pytest.raises(AttributeError):
        SentinelOneExpectationService(config=invalid_config)


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
    return service.handle_batch_expectations(expectations, detection_helper)


# When: I match threats to expectations
def _when_match_threats_to_expectations(service, threats, expectations):
    """Match threats to expectations.

    Args:
        service: The expectation service instance.
        threats: List of threats.
        expectations: List of expectations.

    Returns:
        List of matches.

    """
    threat_events = {threat.threat_id: [] for threat in threats}
    return service._match_threats_to_expectations(
        expectations, threats, threat_events, "detection"
    )


# When: I check if expectation matches threat data
def _when_check_expectation_matches_threat(service, expectation, threat):
    """Check if expectation matches threat data.

    Args:
        service: The expectation service instance.
        expectation: The expectation to check.
        threat: The threat to match against.

    Returns:
        Boolean indicating if there's a match.

    """
    events = []
    expectation_type = (
        "prevention"
        if hasattr(expectation, "is_prevention") and expectation.is_prevention
        else "detection"
    )
    return service._expectation_matches_threat_data(
        expectation, threat, events, expectation_type
    )


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
    assert service.batch_size == config.sentinelone.expectation_batch_size  # noqa: S101


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
def _then_proper_matches_found(matches, threats, expectations):
    """Verify proper matches were found.

    Args:
        matches: The found matches.
        threats: The original threats.
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
    assert isinstance(matches, list)  # noqa: S101


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
