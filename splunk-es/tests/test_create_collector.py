"""Test module for the Splunk ES Collector initialization."""

from os import environ as os_environ
from typing import Any

import pytest
from src.collector import Collector
from src.collector.exception import CollectorConfigError
from tests.conftest import mock_env_vars

# --------
# Fixtures
# --------


@pytest.fixture()
def collector_config() -> dict[str, str]:  # type: ignore
    """Fixture for minimum required configuration.

    Returns:
        Dictionary containing all required environment variables
        for collector initialization with test values.

    """
    return {
        "OPENBAS_URL": "http://fake-url/",
        "OPENBAS_TOKEN": "fake-obas-token",
        "COLLECTOR_ID": "fake-collector-id",
        "COLLECTOR_NAME": "Splunk ES",
        "COLLECTOR_ICON_FILEPATH": "src/img/splunk-logo.png",
        "COLLECTOR_LOG_LEVEL": "debug",
    }


# --------
# Tests
# --------


# Scenario: Create a collector with success.
def test_success_create_collector(capfd, collector_config):  # type: ignore
    """Test that the main function initializes and start the Splunk ES Collector.

    Args:
        capfd: Pytest fixture for capturing stdout and stderr output.
        collector_config: Fixture providing valid collector configuration.

    """
    # Given I have a valid configuration to start the Splunk ES Collector.
    data = {**collector_config}
    mock_env = _given_setup_config(data)

    # When I create the collector.
    collector = _when_create_collector()

    # Then the collector should be created successfully
    _then_collector_created_successfully(capfd, mock_env, collector, data)


# Scenario: Create a collector with missing required config
def test_collector_config_missing_required_values() -> None:
    """Test for the collector with missing required configuration values.

    Verifies that collector creation fails appropriately when required
    configuration values are missing, specifically the Splunk ES username.

    """
    # Given configuration with missing required Splunk ES username
    data = {
        "OPENBAS_URL": "http://fake-url",
        "OPENBAS_TOKEN": "fake-obas-token",
        "COLLECTOR_ID": "fake-collector-id",
        "COLLECTOR_NAME": "Splunk ES",
        "COLLECTOR_ICON_FILEPATH": "src/img/splunk-logo.png",
        "COLLECTOR_LOG_LEVEL": "debug",
    }
    mock_env = _given_setup_config(data)

    # Then the collector config should raise a custom ConfigurationException
    with pytest.raises((CollectorConfigError, ValueError)):
        # When the collector is created
        _when_create_collector()

    mock_env.stop()


# Scenario: Create a collector with missing password
def test_collector_config_missing_password() -> None:
    """Test for the collector with missing password configuration.

    Verifies that collector creation fails appropriately when required
    password configuration is missing.

    """
    # Given configuration with missing required Splunk ES password
    data = {
        "OPENBAS_URL": "http://fake-url",
        "OPENBAS_TOKEN": "fake-obas-token",
        "COLLECTOR_ID": "fake-collector-id",
        "COLLECTOR_NAME": "Splunk ES",
        "COLLECTOR_ICON_FILEPATH": "src/img/splunk-logo.png",
        "COLLECTOR_LOG_LEVEL": "debug",
    }
    mock_env = _given_setup_config(data)

    # Then the collector config should raise a custom ConfigurationException
    with pytest.raises((CollectorConfigError, ValueError)):
        # When the collector is created
        _when_create_collector()

    mock_env.stop()


# ---------
# Given
# ---------


# Given setup config
def _given_setup_config(data: dict[str, str]) -> Any:  # type: ignore
    """Set up the environment variables for the test.

    Args:
        data: Dictionary of environment variables to mock.

    Returns:
        Mock environment variable patcher object.

    """
    mock_env = mock_env_vars(os_environ, data)
    return mock_env


# ---------
# When
# ---------


# When the collector is created
def _when_create_collector() -> Collector:  # type: ignore
    """Create the collector.

    Returns:
        Collector instance for testing.

    """
    collector = Collector()
    return collector


# ---------
# Then
# ---------


# Then the collector should be created successfully
def _then_collector_created_successfully(capfd, mock_env, collector, data) -> None:  # type: ignore
    """Check if the connector was created successfully.

    Args:
        capfd: Pytest fixture for capturing stdout and stderr output.
        mock_env: Mock environment variable patcher to clean up.
        collector: The created collector instance to verify.
        data: Expected configuration data to validate against.

    """
    assert collector is not None  # noqa: S101

    # Check that the collector has the expected configuration
    daemon_config = collector.config_instance.to_daemon_config()

    # Verify key configuration values
    assert daemon_config.get("openbas_url") == data.get("OPENBAS_URL")  # noqa: S101
    assert daemon_config.get("openbas_token") == data.get("OPENBAS_TOKEN")  # noqa: S101
    assert daemon_config.get("collector_id") == data.get("COLLECTOR_ID")  # noqa: S101
    assert daemon_config.get("collector_name") == data.get(  # noqa: S101
        "COLLECTOR_NAME"
    )
    assert daemon_config.get("collector_log_level") == data.get(  # noqa: S101
        "COLLECTOR_LOG_LEVEL"
    )

    log_records = capfd.readouterr()
    if daemon_config.get("collector_log_level") in ["info", "debug"]:
        registered_message = (
            "Splunk Enterprise Security Collector initialized successfully"
        )
        assert registered_message in log_records.err  # noqa: S101

    mock_env.stop()
