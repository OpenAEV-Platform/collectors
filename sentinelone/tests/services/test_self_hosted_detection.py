"""Essential tests for self-hosted detection on the SentinelOne Client API service - Gherkin GWT Format."""

import logging
from typing import Any
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import HTTPError
from src.models.configs.config_loader import ConfigLoader
from src.services.client_api import SentinelOneClientAPI
from tests.services.fixtures.factories import create_test_config

# --------
# Fixtures
# --------


@pytest.fixture(autouse=True)
def mock_logging() -> logging.Logger:
    """Shadow the services conftest ``mock_logging`` fixture for this module.

    The conftest autouse fixture replaces every named logger with a shared
    ``Mock``; log calls on that mock never reach the real logging hierarchy,
    so the ``caplog`` fixture cannot observe them. The probe-failure scenario
    must emit its warning through the real loggers for ``caplog`` to capture
    it, so this module-level fixture shadows the conftest one and restores
    real logging for this module only.

    Yields:
        The real root logger.

    """
    yield logging.getLogger()


# --------
# Scenarios
# --------


# Scenario: Account listing with an accountType field resolves SaaS
def test_account_listing_with_account_type_resolves_saas():
    """Scenario: Account listing with an accountType field resolves SaaS."""
    # Given: A test configuration
    config = _given_config()
    # Given: An account listing response containing an accountType field
    mock_get = _given_mock_http_with_account_listing(
        [
            {
                "id": "saas-account-1",
                "name": "SaaS Trial Account",
                "accountType": "Trial",
                "creator": "SentinelOne",
                "billingMode": "Subscription",
            }
        ]
    )

    # When: I initialize the client API with the HTTP layer mocked
    client = _when_initialize_client_api_with_http_mock(config, mock_get)

    # Then: The probe runs once and the resolved value is False (SaaS)
    _then_self_hosted_resolved(client, mock_get, expected=False)


# Scenario: Account listing without an accountType field resolves self-hosted
def test_account_listing_without_account_type_resolves_self_hosted():
    """Scenario: Account listing without an accountType field resolves self-hosted."""
    # Given: A test configuration
    config = _given_config()
    # Given: An account listing response without any accountType field
    mock_get = _given_mock_http_with_account_listing(
        [
            {
                "id": "self-hosted-account-1",
                "name": "On Prem Account",
            }
        ]
    )

    # When: I initialize the client API with the HTTP layer mocked
    client = _when_initialize_client_api_with_http_mock(config, mock_get)

    # Then: The probe runs once and the resolved value is True (self-hosted)
    _then_self_hosted_resolved(client, mock_get, expected=True)


# Scenario: HTTP error during the probe defaults to SaaS with a warning
def test_probe_http_error_defaults_saas_with_warning(caplog):  # type: ignore
    """Scenario: HTTP error during the probe defaults to SaaS with a warning."""
    # Given: A test configuration
    config = _given_config()
    # Given: The account listing endpoint raises an HTTP error
    mock_get = _given_mock_http_with_error(
        HTTPError("404 Client Error: Not Found for url: /web/api/v2.1/accounts")
    )

    # When: I initialize the client API with the HTTP layer mocked
    client = _when_initialize_client_api_with_http_mock(config, mock_get)

    # Then: The probe ran, the resolved value is False (SaaS), and a warning was logged
    _then_self_hosted_resolved(client, mock_get, expected=False)
    _then_probe_failure_warning_logged(caplog)


# --------
# Given Methods
# --------


# Given: A test configuration
def _given_config() -> ConfigLoader:
    """Create the standard test configuration.

    Returns:
        ConfigLoader instance for the SentinelOne tests.

    """
    return create_test_config()


# Given: A mocked HTTP layer returning an account listing response
def _given_mock_http_with_account_listing(accounts: list[dict]) -> Mock:
    """Create a mock session get returning an account listing body.

    Args:
        accounts: The account objects returned in the "data" field.

    Returns:
        Mock replacing the session HTTP get method.

    """
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"data": accounts}
    return Mock(return_value=mock_response)


# Given: A mocked HTTP layer raising an HTTP error
def _given_mock_http_with_error(error: Exception) -> Mock:
    """Create a mock session get raising an HTTP error.

    Args:
        error: The HTTP error to raise.

    Returns:
        Mock replacing the session HTTP get method.

    """
    return Mock(side_effect=error)


# --------
# When Methods
# --------


# When: I initialize the client API with the HTTP layer mocked
def _when_initialize_client_api_with_http_mock(
    config: ConfigLoader, mock_get: Mock
) -> SentinelOneClientAPI:
    """Initialize the client API with the session HTTP get method mocked.

    Args:
        config: Configuration object to use.
        mock_get: Mock replacing the session HTTP get method.

    Returns:
        Initialized SentinelOneClientAPI instance.

    """
    with patch("requests.Session.get", new=mock_get):
        return SentinelOneClientAPI(config=config)


# --------
# Then Methods
# --------


# Then: The self-hosted flag is resolved as expected after a single probe
def _then_self_hosted_resolved(
    client: SentinelOneClientAPI, mock_get: Mock, expected: bool
) -> None:
    """Verify the resolved is_self_hosted value and probe behaviour.

    Args:
        client: The client API instance to verify.
        mock_get: The mock used for the session HTTP get method.
        expected: The expected resolved boolean value.

    """
    assert client.is_self_hosted is expected  # noqa: S101
    assert mock_get.call_count == 1  # noqa: S101


# Then: The probe failure was logged as a warning
def _then_probe_failure_warning_logged(caplog: Any) -> None:
    """Verify the probe failure was logged as a warning.

    Args:
        caplog: Pytest fixture capturing log records.

    """
    messages = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ]
    assert any(  # noqa: S101
        "Self-hosted probe failed" in message for message in messages
    )
