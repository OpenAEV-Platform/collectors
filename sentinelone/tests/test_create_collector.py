"""Test module for the SentinelOne Collector initialization - Gherkin GWT Format."""

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
        "OPENAEV_URL": "http://fake-url/",
        "OPENAEV_TOKEN": "fake-oaev-token",
        "COLLECTOR_ID": "fake-collector-id",
        "COLLECTOR_NAME": "SentinelOne",
        "SENTINELONE_BASE_URL": "https://fake-sentinelone.net/",
        "SENTINELONE_API_KEY": "fake-api-key",
        "COLLECTOR_ICON_FILEPATH": "src/img/sentinelone-logo.png",
        "COLLECTOR_LOG_LEVEL": "debug",
    }


# --------
# Scenarios
# --------


# Scenario: Create a collector with success
def test_create_collector_with_valid_config(capfd, collector_config):  # type: ignore
    """Scenario: Create a collector with success.

    Args:
        capfd: Pytest fixture for capturing stdout and stderr output.
        collector_config: Fixture providing valid collector configuration.

    """
    # Given: A valid configuration is available
    mock_env = _given_valid_collector_config(collector_config)

    # When: I create the collector
    collector = _when_create_collector()

    # Then: The collector should be created successfully
    _then_collector_created_successfully(capfd, mock_env, collector, collector_config)


# Scenario: Create a collector with missing required config
def test_create_collector_with_missing_api_key(collector_config) -> None:
    """Scenario: Create a collector with missing required config.

    Args:
        collector_config: Fixture providing base collector configuration.

    """
    # Given: Configuration with missing required SentinelOne API key
    incomplete_config = _given_config_missing_api_key(collector_config)
    mock_env = _given_valid_collector_config(incomplete_config)

    # When: I attempt to create the collector
    # Then: The collector creation should fail with configuration error
    _when_create_collector_then_raises_config_error(mock_env)


# --------
# Given Methods
# --------


# Given: A valid configuration is available
def _given_valid_collector_config(config_data: dict[str, str]) -> Any:  # type: ignore
    """Set up valid collector configuration environment.

    Args:
        config_data: Dictionary of environment variables to mock.

    Returns:
        Mock environment variable patcher object.

    """
    mock_env = mock_env_vars(os_environ, config_data)
    return mock_env


# Given: Configuration with missing required SentinelOne API key
def _given_config_missing_api_key(base_config: dict[str, str]) -> dict[str, str]:
    """Create configuration with missing SentinelOne API key.

    Args:
        base_config: Base configuration dictionary.

    Returns:
        Configuration dictionary without SentinelOne API key.

    """
    config = base_config.copy()
    config.pop("SENTINELONE_API_KEY", None)

    if "SENTINELONE_API_KEY" in os_environ:
        del os_environ["SENTINELONE_API_KEY"]

    return config


# --------
# When Methods
# --------


# When: I create the collector
def _when_create_collector() -> Collector:  # type: ignore
    """Create the collector instance.

    Returns:
        Collector instance for testing.

    """
    collector = Collector()
    return collector


# When: I attempt to create the collector and expect configuration error
def _when_create_collector_then_config_error_raised(mock_env: Any) -> None:  # type: ignore
    """Attempt to create collector and expect configuration error.

    Args:
        mock_env: Mock environment variable patcher to clean up.

    """
    try:
        with pytest.raises((CollectorConfigError, ValueError)):
            _when_create_collector()
    finally:
        mock_env.stop()


# When: I attempt to create the collector and expect configuration error (alias)
def _when_create_collector_then_raises_config_error(mock_env: Any) -> None:  # type: ignore
    """Attempt to create collector and expect configuration error.

    Args:
        mock_env: Mock environment variable patcher to clean up.

    """
    _when_create_collector_then_config_error_raised(mock_env)


# --------
# Then Methods
# --------


# Then: The collector should be created successfully
def _then_collector_created_successfully(
    capfd: Any,  # type: ignore
    mock_env: Any,  # type: ignore
    collector: Collector,  # type: ignore
    expected_config: dict[str, str],
) -> None:
    """Verify the collector was created successfully with correct configuration.

    Args:
        capfd: Pytest fixture for capturing stdout and stderr output.
        mock_env: Mock environment variable patcher to clean up.
        collector: The created collector instance to verify.
        expected_config: Expected configuration data to validate against.

    """
    assert collector is not None  # noqa: S101

    daemon_config = collector.config_instance.to_daemon_config()

    assert daemon_config.get("openaev_url") == expected_config.get(
        "OPENAEV_URL"
    )  # noqa: S101
    assert daemon_config.get("openaev_token") == expected_config.get(
        "OPENAEV_TOKEN"
    )  # noqa: S101
    assert daemon_config.get("collector_id") == expected_config.get(
        "COLLECTOR_ID"
    )  # noqa: S101
    assert daemon_config.get("collector_name") == expected_config.get(
        "COLLECTOR_NAME"
    )  # noqa: S101
    assert daemon_config.get(
        "sentinelone_base_url"
    ) == expected_config.get(  # noqa: S101
        "SENTINELONE_BASE_URL"
    )
    assert daemon_config.get(
        "sentinelone_api_key"
    ) == expected_config.get(  # noqa: S101
        "SENTINELONE_API_KEY"
    )
    assert daemon_config.get(
        "collector_log_level"
    ) == expected_config.get(  # noqa: S101
        "COLLECTOR_LOG_LEVEL"
    )

    _then_collector_logged_initialization_success(capfd, daemon_config)
    mock_env.stop()


# Then: The collector initialization should be logged
def _then_collector_logged_initialization_success(
    capfd: Any,  # type: ignore
    daemon_config: dict[str, str],
) -> None:
    """Verify that collector initialization was logged appropriately.

    Args:
        capfd: Pytest fixture for capturing stdout and stderr output.
        daemon_config: Daemon configuration to check log level.

    """
    log_records = capfd.readouterr()
    if daemon_config.get("collector_log_level") in ["info", "debug"]:
        registered_message = "SentinelOne Collector initialized successfully"
        assert registered_message in log_records.err  # noqa: S101
