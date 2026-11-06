"""Tests for the Splunk ES configuration model."""

from datetime import timedelta

import pytest
from src.models.configs.splunkes_configs import _ConfigLoaderSplunkES


@pytest.fixture()
def required_env(monkeypatch):  # type: ignore
    """Set the required Splunk ES settings."""
    monkeypatch.setenv("SPLUNKES_BASE_URL", "https://splunk.example.com:8089")
    monkeypatch.setenv("SPLUNKES_USERNAME", "admin")
    monkeypatch.setenv("SPLUNKES_PASSWORD", "changeme")


@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
def test_blank_optional_env_vars_load_as_defaults(
    monkeypatch, required_env, blank
):  # type: ignore
    """Blank optional settings sent by the platform fall back to their defaults."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_QUERY_TEMPLATE", blank)
    monkeypatch.setenv("SPLUNKES_ALERTS_INDEX", blank)
    monkeypatch.setenv("SPLUNKES_TIME_WINDOW", blank)

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.query_template is None  # noqa: S101
    assert config.alerts_index == "notable"  # noqa: S101
    assert config.time_window == timedelta(hours=1)  # noqa: S101


def test_set_optional_env_vars_are_kept(monkeypatch, required_env):  # type: ignore
    """Non-blank optional settings are loaded as given."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_QUERY_TEMPLATE", "index={alerts_index} | table _time")
    monkeypatch.setenv("SPLUNKES_ALERTS_INDEX", "custom_index")
    monkeypatch.setenv("SPLUNKES_TIME_WINDOW", "PT2H")

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.query_template == "index={alerts_index} | table _time"  # noqa: S101
    assert config.alerts_index == "custom_index"  # noqa: S101
    assert config.time_window == timedelta(hours=2)  # noqa: S101
