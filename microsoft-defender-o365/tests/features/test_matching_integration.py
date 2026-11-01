"""Behavioural tests for the matching integration flow - Gherkin GWT Format.

Uses raw pytest with _given/_when/_then helpers. No pytest-bdd.
"""

from tests.conftest import (
    _given_detection_expectation_with_supported_sigs,
    _given_empty_fetched_data,
    _given_expectation_with_unsupported_sigs,
    _given_fetched_data_error,
    _given_matching_alert_data,
    _given_non_matching_alert_data,
    _given_prevention_expectation_with_supported_sigs,
    _then_all_results_invalid,
    _then_expectation_result_has_error,
    _then_expectation_result_is_valid_with_traces,
    _then_expectation_result_not_valid_no_traces,
    _then_only_supported_sigs_retained,
    _when_engine_processes_batch,
    _when_source_handler_filters_sigs,
)

# --------
# Scenarios
# --------


# Scenario: Fully matching alert produces ExpectationResult with is_valid=True
def test_fully_matching_alert_produces_valid_result():
    """Scenario: Fully matching alert produces ExpectationResult with is_valid=True."""
    # Given: a DetectionExpectation with matching signatures
    expectation = _given_detection_expectation_with_supported_sigs()

    # Given: source data producing matching OAEVData and is_detected()=True
    alert_data = _given_matching_alert_data()

    # When: the engine processes the expectation against the fetched data
    results = _when_engine_processes_batch([expectation], alert_data)

    # Then: ExpectationResult.is_valid is True
    _then_expectation_result_is_valid_with_traces(results[0])


# Scenario: Non-matching alert produces ExpectationResult with is_valid=False
def test_non_matching_alert_produces_invalid_result():
    """Scenario: Non-matching alert produces ExpectationResult with is_valid=False."""
    # Given: a DetectionExpectation with signatures for supported types
    expectation = _given_detection_expectation_with_supported_sigs()

    # Given: source data producing non-matching OAEVData
    alert_data = _given_non_matching_alert_data()

    # When: the engine processes the expectation against the fetched data
    results = _when_engine_processes_batch([expectation], alert_data)

    # Then: ExpectationResult.is_valid is False and matched_alerts is empty
    _then_expectation_result_not_valid_no_traces(results[0])


# Scenario: Unsupported signature types in expectation are filtered out
def test_unsupported_signature_types_filtered():
    """Scenario: Unsupported signature types in expectation are filtered out."""
    # Given: an expectation with signatures including unsupported types
    expectation = _given_expectation_with_unsupported_sigs()

    # When: SourceHandler.get_expectation_signature_groups filters
    sig_groups = _when_source_handler_filters_sigs(expectation)

    # Then: only signatures matching SUPPORTED_SIGNATURES are retained
    _then_only_supported_sigs_retained(sig_groups)


# Scenario: PreventionExpectation with is_prevented=True produces is_valid=True with break
def test_prevention_expectation_produces_valid_with_break():
    """Scenario: PreventionExpectation with is_prevented=True produces is_valid=True with break."""
    # Given: a PreventionExpectation with matching signatures
    expectation = _given_prevention_expectation_with_supported_sigs()

    # Given: source data with is_prevented()=True
    alert_data = _given_matching_alert_data(prevention=True)

    # When: the engine processes the expectation
    results = _when_engine_processes_batch([expectation], alert_data)

    # Then: ExpectationResult.is_valid is True
    _then_expectation_result_is_valid_with_traces(results[0])


# Scenario: Empty fetched data produces is_valid=False for all expectations
def test_empty_fetched_data_produces_invalid():
    """Scenario: Empty fetched data produces is_valid=False for all expectations."""
    # Given: expectations exist
    expectation1 = _given_detection_expectation_with_supported_sigs()
    expectation2 = _given_detection_expectation_with_supported_sigs("exp-002")

    # Given: fetch_data() returns empty list
    _given_empty_fetched_data()

    # When: the engine processes the batch
    results = _when_engine_processes_batch([expectation1, expectation2], [])

    # Then: all ExpectationResult objects have is_valid=False
    _then_all_results_invalid(results)


# Scenario: Data fetch error produces ExpectationResult.from_error per expectation
def test_data_fetch_error_produces_error_result():
    """Scenario: Data fetch error produces ExpectationResult.from_error per expectation."""
    # Given: expectations exist
    expectation1 = _given_detection_expectation_with_supported_sigs()
    expectation2 = _given_detection_expectation_with_supported_sigs("exp-002")

    # Given: fetch_data() raises an exception
    _given_fetched_data_error()

    # When: the engine processes the batch
    results = _when_engine_processes_batch([expectation1, expectation2], [])

    # Then: each expectation gets an ExpectationResult with is_valid=False and error_message
    for result in results:
        _then_expectation_result_has_error(result)
