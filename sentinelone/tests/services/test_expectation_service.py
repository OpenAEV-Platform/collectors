"""Essential tests for SentinelOne Expectation Service - Gherkin GWT Format."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest
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


# Scenario: Handle static threats with Deep Visibility enabled
def test_handle_static_threats_with_deep_visibility_enabled():
    """Scenario: Handle static threats with Deep Visibility enabled."""
    # Given: A detection helper
    detection_helper = _given_mock_detection_helper()
    # Given: A static expectation
    expectation = _given_static_expectation()

    # When: I handle the static expectation with Deep Visibility enabled
    with _given_expectation_service_with_deep_visibility_enabled() as service:
        mock_static_threats = _given_mock_static_threats_for_service(service)
        mock_dv_events = _given_mock_deep_visibility_events_for_service(service)

        with mock_static_threats, mock_dv_events:
            result = _when_handle_batch_expectations(
                service, [expectation], detection_helper
            )

    # Then: A static result with Deep Visibility events should be returned
    _then_static_result_with_deep_visibility_returned(result, expectation)


# Scenario: Handle static threats with Deep Visibility disabled
def test_handle_static_threats_with_deep_visibility_disabled():
    """Scenario: Handle static threats with Deep Visibility disabled."""
    # Given: A detection helper
    detection_helper = _given_mock_detection_helper()
    # Given: A static expectation
    expectation = _given_static_expectation()

    # When: I handle the static expectation with Deep Visibility disabled
    with _given_expectation_service_with_deep_visibility_disabled() as service:
        mock_static_threats = _given_mock_static_threats_for_service(service)

        with mock_static_threats:
            result = _when_handle_batch_expectations(
                service, [expectation], detection_helper
            )

    # Then: A static result without Deep Visibility events should be returned
    _then_static_result_without_deep_visibility_returned(result, expectation)


# Scenario: Verify Deep Visibility fetcher is called when enabled
def test_deep_visibility_fetcher_called_when_enabled():
    """Scenario: Verify Deep Visibility fetcher is called when enabled."""
    # Given: A detection helper
    detection_helper = _given_mock_detection_helper()
    # Given: A static expectation
    static_expectation = _given_static_expectation()

    # When: I handle the static expectation with Deep Visibility enabled
    with _given_expectation_service_with_deep_visibility_enabled() as service:
        mock_static_threats = _given_mock_static_threats_for_service(service)
        mock_dv_events = _given_mock_deep_visibility_events_for_service(service)

        with mock_static_threats, mock_dv_events as dv_mock:
            _when_handle_batch_expectations(
                service, [static_expectation], detection_helper
            )

            # Then: Deep Visibility fetcher should have been called
            dv_mock.assert_called_once()


# Scenario: Verify Deep Visibility fetcher is not called when disabled
def test_deep_visibility_fetcher_not_called_when_disabled():
    """Scenario: Verify Deep Visibility fetcher is not called when disabled."""
    # Given: A detection helper
    detection_helper = _given_mock_detection_helper()
    # Given: A static expectation
    static_expectation = _given_static_expectation()

    # When: I handle the static expectation with Deep Visibility disabled
    with _given_expectation_service_with_deep_visibility_disabled() as service:
        mock_static_threats = _given_mock_static_threats_for_service(service)
        mock_dv_events = _given_mock_deep_visibility_events_for_service(service)

        with mock_static_threats, mock_dv_events as dv_mock:
            _when_handle_batch_expectations(
                service, [static_expectation], detection_helper
            )

            # Then: Deep Visibility fetcher should not have been called
            dv_mock.assert_not_called()


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


# Scenario: The alert window and the DV event window are decoupled
def test_alert_and_dv_windows_are_decoupled():
    """Scenario: The DV event window ignores the signature dates and pivots on
    the file SHA1 with a fixed lookback, while the alert window keeps anchoring
    its start to the signature start date."""
    # Given: A detection helper
    detection_helper = _given_mock_detection_helper()
    # Given: A static expectation with start and end date signatures
    static_expectation = _given_expectation_with_date_signatures(
        start_date="2024-01-01T10:00:00Z",
        end_date="2024-01-01T12:00:00Z",
    )
    # Given: A pinned DV lookback so the assertion is deterministic
    lookback = timedelta(hours=6)

    # When: I handle the static expectation with Deep Visibility enabled
    with _given_expectation_service_with_deep_visibility_enabled() as service:
        service.client_api.deep_visibility_lookback = lookback
        mock_static_threats = _given_mock_static_threats_for_service(service)
        mock_dv_events = _given_mock_deep_visibility_events_for_service(service)

        with mock_static_threats as threats_mock, mock_dv_events as dv_mock:
            _when_handle_batch_expectations(
                service, [static_expectation], detection_helper
            )

    # Then: The alert window still uses the signature start date, and the DV
    # event window spans exactly the pinned lookback ending at now
    _then_alert_and_dv_windows_are_decoupled(
        threats_mock, dv_mock, "2024-01-01T10:00:00Z", lookback
    )


# Scenario: Fetch windows fall back to the time window without a start date
def test_fetch_windows_fall_back_to_time_window_without_start_date():
    """Scenario: without a start date signature, the threat window spans
    now - SENTINELONE_TIME_WINDOW to now.
    """
    # Given: An initialized expectation service
    service = _given_initialized_expectation_service()
    # Given: An expectation without a start date signature
    expectation = _given_expectation_with_date_signatures(
        start_date=None, end_date="2024-01-01T12:00:00Z"
    )

    # When: I compute the fetch time window for the batch
    start_time, end_time = _when_compute_fetch_time_window(service, [expectation])

    # Then: The window spans now - SENTINELONE_TIME_WINDOW to now
    _then_fetch_window_falls_back_to_time_window(service, start_time, end_time)


# Scenario: Fetch windows fall back to the time window when the start date is in the future
def test_fetch_windows_fall_back_to_time_window_when_start_in_future():
    """Scenario: a start date after the current time is anomalous; the
    threat window falls back to now - SENTINELONE_TIME_WINDOW to now.
    """
    # Given: An initialized expectation service
    service = _given_initialized_expectation_service()
    # Given: An expectation whose start date lies in the future
    expectation = _given_expectation_with_date_signatures(
        start_date="2999-01-01T12:00:00Z", end_date="2024-01-01T12:00:00Z"
    )

    # When: I compute the fetch time window for the batch
    start_time, end_time = _when_compute_fetch_time_window(service, [expectation])

    # Then: The window spans now - SENTINELONE_TIME_WINDOW to now
    _then_fetch_window_falls_back_to_time_window(service, start_time, end_time)


# Scenario: Fetch windows fall back to the time window when the start date is unparsable
def test_fetch_windows_fall_back_to_time_window_when_start_unparsable():
    """Scenario: an unparsable start date signature falls back to
    now - SENTINELONE_TIME_WINDOW to now.
    """
    # Given: An initialized expectation service
    service = _given_initialized_expectation_service()
    # Given: An expectation with an unparsable start date signature
    expectation = _given_expectation_with_date_signatures(
        start_date="not-a-date", end_date="2024-01-01T12:00:00Z"
    )

    # When: I compute the fetch time window for the batch
    start_time, end_time = _when_compute_fetch_time_window(service, [expectation])

    # Then: The window spans now - SENTINELONE_TIME_WINDOW to now
    _then_fetch_window_falls_back_to_time_window(service, start_time, end_time)


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


# Given: An expectation service with Deep Visibility enabled
def _given_expectation_service_with_deep_visibility_enabled():
    """Create an expectation service with Deep Visibility enabled.

    Returns:
        Context manager that yields SentinelOneExpectationService with Deep Visibility enabled.

    """
    import os
    from contextlib import contextmanager
    from unittest.mock import patch

    @contextmanager
    def _service_context():
        with patch.dict(
            os.environ, {"SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH": "true"}
        ):
            config = given_test_config()
            yield SentinelOneExpectationService(config)

    return _service_context()


# Given: An expectation service with Deep Visibility disabled
def _given_expectation_service_with_deep_visibility_disabled():
    """Create an expectation service with Deep Visibility disabled.

    Returns:
        Context manager that yields SentinelOneExpectationService with Deep Visibility disabled.

    """
    import os
    from contextlib import contextmanager
    from unittest.mock import patch

    @contextmanager
    def _service_context():
        with patch.dict(
            os.environ, {"SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH": "false"}
        ):
            config = given_test_config()
            yield SentinelOneExpectationService(config)

    return _service_context()


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


# Given: An expectation with date signatures
def _given_expectation_with_date_signatures(start_date: str | None, end_date: str):
    """Create a static expectation with date signatures.

    Args:
        start_date: ISO 8601 start date signature value, or None to omit.
        end_date: ISO 8601 end date signature value.

    Returns:
        Mock static expectation.

    """
    signatures = [
        _create_mock_signature(
            SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS,
            "static-host.example.com",
        )
    ]
    if start_date is not None:
        signatures.append(
            _create_mock_signature(SignatureTypes.SIG_TYPE_START_DATE, start_date)
        )
    signatures.append(
        _create_mock_signature(SignatureTypes.SIG_TYPE_END_DATE, end_date)
    )

    return _create_mock_expectation(
        expectation_id="static_date_test_1", signatures=signatures
    )


# Given: Mock static threats for service
def _given_mock_static_threats_for_service(service):
    """Set up mock static threats for the service.

    Args:
        service: The expectation service to mock.

    """
    from unittest.mock import patch

    static_threats = [
        SentinelOneThreat(
            threat_id="static_threat_1",
            hostname="static-host.example.com",
            is_mitigated=False,
            is_static=True,
            sha1="a1b2c3d4e5f6789012345678901234567890abcd",
        ),
        SentinelOneThreat(
            threat_id="static_threat_2",
            hostname="static-host.example.com",
            is_mitigated=False,
            is_static=True,
            sha1="b2c3d4e5f6789012345678901234567890abcdef",
        ),
    ]

    return patch.object(
        service.threat_fetcher,
        "fetch_threats_for_time_window",
        return_value=static_threats,
    )


# Given: Mock mixed threats for service
def _given_mock_mixed_threats_for_service(service):
    """Set up mock mixed threats (static and non-static) for the service.

    Args:
        service: The expectation service to mock.

    """
    from unittest.mock import patch

    mixed_threats = [
        SentinelOneThreat(
            threat_id="static_threat_1",
            hostname="mixed-host.example.com",
            is_mitigated=False,
            is_static=True,
            sha1="a1b2c3d4e5f6789012345678901234567890abcd",
        ),
        SentinelOneThreat(
            threat_id="behavior_threat_1",
            hostname="mixed-host.example.com",
            is_mitigated=False,
            is_static=False,
            sha1=None,
        ),
    ]

    return patch.object(
        service.threat_fetcher,
        "fetch_threats_for_time_window",
        return_value=mixed_threats,
    )


# Given: Mock Deep Visibility events for service
def _given_mock_deep_visibility_events_for_service(service):
    """Set up mock Deep Visibility events for the service.

    Args:
        service: The expectation service to mock.

    """
    from unittest.mock import patch

    mock_dv_events = {
        "a1b2c3d4e5f6789012345678901234567890abcd": [
            {
                "fileSha1": "a1b2c3d4e5f6789012345678901234567890abcd",
                "processName": "oaev-implant-test.exe",
                "timestamp": "2024-01-01T12:00:00Z",
                "eventType": "Process Creation",
                "parentProcessName": "cmd.exe",
            }
        ],
        "b2c3d4e5f6789012345678901234567890abcdef": [
            {
                "fileSha1": "b2c3d4e5f6789012345678901234567890abcdef",
                "processName": "oaev-implant-test2.exe",
                "timestamp": "2024-01-01T12:01:00Z",
                "eventType": "Process Creation",
                "parentProcessName": "powershell.exe",
            }
        ],
    }

    return patch.object(
        service.deep_visibility_fetcher,
        "fetch_events_for_batch_sha1",
        return_value=mock_dv_events,
    )


# Given: Mock threat events for service
def _given_mock_threat_events_for_service(service):
    """Set up mock threat events for the service.

    Args:
        service: The expectation service to mock.

    """
    from unittest.mock import patch

    mock_threat_events = {
        "behavior_threat_1": [
            {
                "processName": "oaev-implant-behavior.exe",
                "parentProcessName": "cmd.exe",
                "timestamp": "2024-01-01T12:00:00Z",
                "eventType": "Process Creation",
            }
        ]
    }

    return patch.object(
        service.threat_events_fetcher,
        "fetch_events_for_threat",
        return_value=mock_threat_events,
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
    results, _ = service.handle_batch_expectations(expectations, detection_helper)
    return results


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


# When: I compute the fetch time window for a batch
def _when_compute_fetch_time_window(service, batch):
    """Compute the fetch time window for a batch.

    Args:
        service: The expectation service instance.
        batch: Batch of expectations.

    Returns:
        Tuple of (start_time, end_time).

    """
    return service._get_fetch_time_window(batch)


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


# Then: Both the threat and DV windows use the signature start and end dates
def _then_alert_and_dv_windows_are_decoupled(
    threats_mock, dv_mock, start_date, lookback
):
    """Verify the alert window and the DV event window are decoupled.

    The alert (threat) window keeps anchoring its start to the signature
    start_date. The DV event window ignores the signature dates entirely: it
    starts at now - lookback and ends at now, so it can reach a file that was
    dropped or executed well before the alert that references it.

    Args:
        threats_mock: Mock of the threat fetcher time window fetch.
        dv_mock: Mock of the Deep Visibility batch SHA1 fetch.
        start_date: ISO 8601 start date signature value.
        lookback: Pinned DV lookback duration.

    """
    # Alert window: its start still anchors to the signature start_date.
    assert threats_mock.call_args.kwargs["start_time"] == _parse_date_signature(
        start_date
    )  # noqa: S101

    # DV window: spans exactly the pinned lookback and ends at now.
    dv_start = dv_mock.call_args.args[1]
    dv_end = dv_mock.call_args.args[2]
    assert dv_end - dv_start == lookback  # noqa: S101

    # The DV window is decoupled from the signature start date...
    assert dv_start != _parse_date_signature(start_date)  # noqa: S101
    # ...and both windows are now-anchored on the end.
    assert abs(threats_mock.call_args.kwargs["end_time"] - dv_end) < timedelta(
        minutes=1
    )  # noqa: S101


# Then: The fallback window spans now - SENTINELONE_TIME_WINDOW to now
def _then_fetch_window_falls_back_to_time_window(service, start_time, end_time):
    """Verify the threat window fell back to now - SENTINELONE_TIME_WINDOW.

    Under the decoupled contract the threat window ends at the current time;
    the signature end date no longer anchors it.

    Args:
        service: The expectation service instance.
        start_time: Computed window start.
        end_time: Computed window end.

    """
    assert start_time == end_time - service.client_api.time_window  # noqa: S101
    now_at_assertion = datetime.now(timezone.utc)
    assert abs(end_time - now_at_assertion) < timedelta(minutes=1)  # noqa: S101


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


def _parse_date_signature(value: str) -> datetime:
    """Parse an ISO 8601 date signature value.

    Args:
        value: ISO 8601 date string, e.g. "2024-01-01T12:00:00Z".

    Returns:
        Parsed datetime.

    """
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
