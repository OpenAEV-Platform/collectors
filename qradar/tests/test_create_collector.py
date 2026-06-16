"""Test module for the IBM QRadar Collector initialization."""

from os import environ as os_environ
from typing import Any
from uuid import UUID

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
        "OPENAEV_URL": "http://fake-url/",
        "OPENAEV_TOKEN": "fake-oaev-token",
        "OPENAEV_TENANT_ID": "deadbeef-dead-beef-dead-beefdeadbeef",
        "COLLECTOR_ID": "fake-collector-id",
        "COLLECTOR_NAME": "IBM QRadar",
        "QRADAR_BASE_URL": "https://fake-qradar.net/",
        "QRADAR_TOKEN": "fake-token",
        "QRADAR_API_VERSION": "20.0",
        "COLLECTOR_ICON_FILEPATH": "src/img/qradar-logo.png",
        "COLLECTOR_LOG_LEVEL": "debug",
    }


# --------
# Tests
# --------


# Scenario: Create a collector with success.
def test_success_create_collector(capfd, collector_config):  # type: ignore
    """Test that the main function initializes and start the IBM QRadar Collector.

    Args:
        capfd: Pytest fixture for capturing stdout and stderr output.
        collector_config: Fixture providing valid collector configuration.

    """
    # Given I have a valid configuration to start the IBM QRadar Collector.
    data = {**collector_config}
    mock_env = _given_setup_config(data)

    # When I create the collector.
    collector = _when_create_collector()

    # Then the collector should be created successfully
    _then_collector_created_successfully(capfd, mock_env, collector, data)


# Scenario: Create a collector with no authentication configured
def test_collector_config_missing_auth() -> None:
    """Test for the collector with no authentication configured.

    Verifies that collector creation fails appropriately when neither a token
    nor a username/password pair is provided.

    """
    data = {
        "OPENAEV_URL": "http://fake-url",
        "OPENAEV_TOKEN": "fake-oaev-token",
        "OPENAEV_TENANT_ID": "deadbeef-dead-beef-dead-beefdeadbeef",
        "COLLECTOR_ID": "fake-collector-id",
        "COLLECTOR_NAME": "IBM QRadar",
        "QRADAR_BASE_URL": "https://fake-qradar.net/",
        # No QRADAR_TOKEN and no username/password - should fail validation
        "COLLECTOR_ICON_FILEPATH": "src/img/qradar-logo.png",
        "COLLECTOR_LOG_LEVEL": "debug",
    }
    mock_env = _given_setup_config(data)

    for key in ("QRADAR_TOKEN", "QRADAR_USERNAME", "QRADAR_PASSWORD"):
        if key in os_environ:
            del os_environ[key]

    with pytest.raises((CollectorConfigError, ValueError)):
        _when_create_collector()

    mock_env.stop()


# Scenario: Create a collector with incomplete basic auth (no password, no token)
def test_collector_config_partial_basic_auth() -> None:
    """Test that a username without a password (and no token) fails validation."""
    data = {
        "OPENAEV_URL": "http://fake-url",
        "OPENAEV_TOKEN": "fake-oaev-token",
        "OPENAEV_TENANT_ID": "deadbeef-dead-beef-dead-beefdeadbeef",
        "COLLECTOR_ID": "fake-collector-id",
        "COLLECTOR_NAME": "IBM QRadar",
        "QRADAR_BASE_URL": "https://fake-qradar.net/",
        "QRADAR_USERNAME": "fake-user",
        # No QRADAR_PASSWORD and no QRADAR_TOKEN - should fail validation
        "COLLECTOR_ICON_FILEPATH": "src/img/qradar-logo.png",
        "COLLECTOR_LOG_LEVEL": "debug",
    }
    mock_env = _given_setup_config(data)

    for key in ("QRADAR_TOKEN", "QRADAR_PASSWORD"):
        if key in os_environ:
            del os_environ[key]

    with pytest.raises((CollectorConfigError, ValueError)):
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
    assert daemon_config.get("openaev_url") == data.get("OPENAEV_URL")  # noqa: S101
    assert daemon_config.get("openaev_token") == data.get("OPENAEV_TOKEN")  # noqa: S101
    assert daemon_config.get("openaev_tenant_id") == UUID(
        data.get("OPENAEV_TENANT_ID")
    )  # noqa: S101
    assert daemon_config.get("collector_id") == data.get("COLLECTOR_ID")  # noqa: S101
    assert daemon_config.get("collector_name") == data.get(  # noqa: S101
        "COLLECTOR_NAME"
    )
    assert daemon_config.get("qradar_base_url") == data.get(  # noqa: S101
        "QRADAR_BASE_URL"
    )
    assert daemon_config.get("qradar_token") == data.get("QRADAR_TOKEN")  # noqa: S101
    assert daemon_config.get("qradar_api_version") == data.get(  # noqa: S101
        "QRADAR_API_VERSION"
    )
    assert daemon_config.get("collector_log_level") == data.get(  # noqa: S101
        "COLLECTOR_LOG_LEVEL"
    )

    log_records = capfd.readouterr()
    if daemon_config.get("collector_log_level") in ["info", "debug"]:
        registered_message = "IBM QRadar Collector initialized successfully"
        assert registered_message in log_records.err  # noqa: S101

    mock_env.stop()
