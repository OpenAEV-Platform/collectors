"""Essential tests for SentinelOne Client API service - Gherkin GWT Format."""

from requests import Session
from src.services.client_api import SentinelOneClientAPI
from tests.gwt_shared import (  # Given methods
    given_test_config,
    then_client_api_initialized_successfully,
)

# --------
# Scenarios
# --------


# Scenario: Initialize client API with valid configuration
def test_initialize_client_api_with_valid_config():
    """Scenario: Initialize client API with valid configuration."""
    # Given: A valid configuration is available
    config = _given_valid_config_for_client_api()

    # When: I initialize the client API
    client = _when_initialize_client_api_with_config(config)

    # Then: The client API should be initialized successfully
    _then_client_api_initialized_with_valid_config(client, config)


# Scenario: Initialize with invalid configuration raises error
def test_initialize_with_invalid_config():
    """Scenario: Initialize with invalid configuration raises error."""
    # Given: An invalid configuration (None)
    invalid_config = _given_invalid_config()

    # When: I attempt to initialize the client API
    # Then: An AttributeError should be raised
    _when_initialize_client_api_then_attribute_error_raised(invalid_config)


# --------
# Given Methods
# --------


# Given: A valid configuration is available
def _given_valid_config_for_client_api():
    """Create a valid configuration for client API testing.

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


# --------
# When Methods
# --------


# When: I initialize the client API with configuration
def _when_initialize_client_api_with_config(config):
    """Initialize client API with given configuration.

    Args:
        config: Configuration object to use.

    Returns:
        Initialized SentinelOneClientAPI instance.

    """
    return SentinelOneClientAPI(config=config)


# When: I attempt to initialize with invalid config and expect AttributeError
def _when_initialize_client_api_then_attribute_error_raised(invalid_config):
    """Attempt to initialize with invalid config and expect AttributeError.

    Args:
        invalid_config: Invalid configuration to test.

    """
    import pytest

    with pytest.raises(AttributeError):
        SentinelOneClientAPI(config=invalid_config)


# --------
# Then Methods
# --------


# Then: The client API should be initialized successfully with valid config
def _then_client_api_initialized_with_valid_config(client, config):
    """Verify client API was initialized successfully with valid configuration.

    Args:
        client: The client API instance to verify.
        config: The configuration used for initialization.

    """
    then_client_api_initialized_successfully(client)

    assert client.config == config  # noqa: S101
    assert client.base_url == str(config.sentinelone.base_url).rstrip("/")  # noqa: S101
    assert client.api_key == config.sentinelone.api_key.get_secret_value()  # noqa: S101
    assert isinstance(client.session, Session)  # noqa: S101
    assert client.time_window == config.sentinelone.time_window  # noqa: S101
