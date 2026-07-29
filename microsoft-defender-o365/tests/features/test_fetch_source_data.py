"""Behavioural tests for the data fetch cycle - Gherkin GWT Format.

Uses raw pytest with _given/_when/_then helpers matching the existing
tests/features/ pattern. No pytest-bdd.
"""

from unittest.mock import MagicMock

import pytest
from tests.conftest import (
    _given_microsoft_defender_o365_empty_response,
    _given_microsoft_defender_o365_mixed_evidence_response,
    _given_microsoft_defender_o365_multi_page_response,
    _given_microsoft_defender_o365_rate_limited_response,
    _given_microsoft_defender_o365_single_page_response,
    _given_microsoft_defender_o365_token_expired_response,
    _then_each_result_has_raw_alert,
    _then_only_analyzed_message_evidence_preserved,
    _then_result_count_equals,
    _then_result_is_empty,
    _then_result_is_list_of_source_data,
    _when_microsoft_defender_o365_fetcher_fetches_data,
)

# --------
# Scenarios
# --------

# Scenario: Fetch alerts from a single page response
@pytest.mark.parametrize(
    "alert_count",
    [3],
    ids=["single_page_three_alerts"],
)
def test_fetch_alerts_from_single_page(alert_count, source_config_fixture):
    """Scenario: Fetch alerts from a single page response."""
    mock_session = MagicMock()
    mock_auth = MagicMock()
    mock_auth.get_access_token.return_value = "test-token"

    # Given: the API returns a single page of 3 alerts
    _given_microsoft_defender_o365_single_page_response(mock_session, alert_count)

    # When: the data fetcher retrieves alerts
    result = _when_microsoft_defender_o365_fetcher_fetches_data(
        source_config_fixture, mock_session, mock_auth
    )

    # Then: the fetcher returns a list of source data objects
    _then_result_is_list_of_source_data(result)

    # Then: each source data object contains the raw alert data
    _then_each_result_has_raw_alert(result)

    # Then: the number of results matches the API response count
    _then_result_count_equals(result, alert_count)


# Scenario: Fetch alerts with pagination
@pytest.mark.parametrize(
    "page_sizes, total_expected",
    [([2, 3], 5)],
    ids=["two_pages_5_alerts"],
)
def test_fetch_alerts_with_pagination(page_sizes, total_expected, source_config_fixture):
    """Scenario: Fetch alerts with pagination."""
    mock_session = MagicMock()
    mock_auth = MagicMock()
    mock_auth.get_access_token.return_value = "test-token"

    # Given: the API returns multiple pages of alerts
    _given_microsoft_defender_o365_multi_page_response(mock_session, page_sizes)

    # When: the data fetcher retrieves alerts
    result = _when_microsoft_defender_o365_fetcher_fetches_data(
        source_config_fixture, mock_session, mock_auth
    )

    # Then: the total result count equals the sum of all pages
    _then_result_count_equals(result, total_expected)


# Scenario: Handle rate limiting (HTTP 429)
def test_handle_rate_limiting(source_config_fixture):
    """Scenario: Handle rate limiting (HTTP 429)."""
    mock_session = MagicMock()
    mock_auth = MagicMock()
    mock_auth.get_access_token.return_value = "test-token"

    # Given: the API returns a 429 rate limit response
    _given_microsoft_defender_o365_rate_limited_response(mock_session)

    # When: the data fetcher retrieves alerts
    result = _when_microsoft_defender_o365_fetcher_fetches_data(
        source_config_fixture, mock_session, mock_auth
    )

    # Then: the final result includes the alerts
    _then_result_is_list_of_source_data(result)
    _then_result_count_equals(result, 1)


# Scenario: Handle token expiry (HTTP 401)
def test_handle_token_expiry(source_config_fixture):
    """Scenario: Handle token expiry (HTTP 401)."""
    mock_session = MagicMock()
    mock_auth = MagicMock()
    mock_auth.get_access_token.return_value = "test-token"

    # Given: the API returns a 401 unauthorized response
    _given_microsoft_defender_o365_token_expired_response(mock_session)

    # When: the data fetcher retrieves alerts
    result = _when_microsoft_defender_o365_fetcher_fetches_data(
        source_config_fixture, mock_session, mock_auth
    )

    # Then: the final result includes the alerts
    _then_result_is_list_of_source_data(result)
    _then_result_count_equals(result, 1)


# Scenario: Filter evidence to analyzedMessageEvidence only
def test_filter_evidence_to_analyzed_message(source_config_fixture):
    """Scenario: Filter evidence to analyzedMessageEvidence only."""
    mock_session = MagicMock()
    mock_auth = MagicMock()
    mock_auth.get_access_token.return_value = "test-token"

    # Given: the alerts contain mixed evidence types
    _given_microsoft_defender_o365_mixed_evidence_response(mock_session)

    # When: the data fetcher retrieves alerts
    result = _when_microsoft_defender_o365_fetcher_fetches_data(
        source_config_fixture, mock_session, mock_auth
    )

    # Then: only analyzedMessageEvidence items are preserved
    _then_only_analyzed_message_evidence_preserved(result)


# Scenario: Empty response returns empty list
def test_empty_response_returns_empty_list(source_config_fixture):
    """Scenario: Empty response returns empty list."""
    mock_session = MagicMock()
    mock_auth = MagicMock()
    mock_auth.get_access_token.return_value = "test-token"

    # Given: the API returns an empty value array
    _given_microsoft_defender_o365_empty_response(mock_session)

    # When: the data fetcher retrieves alerts
    result = _when_microsoft_defender_o365_fetcher_fetches_data(
        source_config_fixture, mock_session, mock_auth
    )

    # Then: the fetcher returns an empty list
    _then_result_is_empty(result)


# Scenario: OData filter is applied to the request
def test_odata_filter_applied_to_request(source_config_fixture):
    """Scenario: OData filter is applied to the request."""
    from tests.conftest import (
        _given_microsoft_defender_o365_single_page_response,
        _then_result_is_list_of_source_data,
        _when_microsoft_defender_o365_fetcher_fetches_data,
    )

    mock_session = MagicMock()
    mock_auth = MagicMock()
    mock_auth.get_access_token.return_value = "test-token"

    # Given: the API returns a single page of 1 alert
    _given_microsoft_defender_o365_single_page_response(mock_session, 1)

    # When: the data fetcher retrieves alerts
    result = _when_microsoft_defender_o365_fetcher_fetches_data(
        source_config_fixture, mock_session, mock_auth
    )

    # Then: the request URL contains the serviceSource filter
    _then_result_is_list_of_source_data(result)
    call_args = mock_session.get.call_args
    params = call_args[1].get("params", {})
    assert "$filter" in params
    assert "microsoftDefenderForOffice365" in params["$filter"]