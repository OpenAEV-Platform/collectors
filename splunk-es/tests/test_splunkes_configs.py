"""Tests for the Splunk ES configuration model."""

from datetime import timedelta

import pytest
from pydantic import ValidationError
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


def test_logging_is_disabled_by_default(monkeypatch, required_env):  # type: ignore
    """Without the Logging settings, Logging is off and no index is set."""
    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.logging_enabled is False  # noqa: S101
    assert config.logging_indexes is None  # noqa: S101


def test_logging_indexes_are_kept_as_written(monkeypatch, required_env):  # type: ignore
    """The index setting is kept as written, like SPLUNKES_ALERTS_INDEX."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_LOGGING_ENABLED", "true")
    monkeypatch.setenv("SPLUNKES_LOGGING_INDEXES", "sysmon, win*")

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.logging_enabled is True  # noqa: S101
    assert config.logging_indexes == "sysmon, win*"  # noqa: S101


@pytest.mark.parametrize("indexes", [None, "", "  ", ",, "])
def test_logging_enabled_without_index_fails(
    monkeypatch, required_env, indexes
):  # type: ignore
    """Enabling Logging without any index fails at startup with a clear message."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_LOGGING_ENABLED", "true")
    if indexes is not None:
        monkeypatch.setenv("SPLUNKES_LOGGING_INDEXES", indexes)

    # Act / Assert
    with pytest.raises(ValidationError, match="SPLUNKES_LOGGING_INDEXES is empty"):
        _ConfigLoaderSplunkES()


def test_logging_settings_leave_detection_settings_unchanged(
    monkeypatch, required_env
):  # type: ignore
    """Turning Logging on does not change the Detection settings."""
    # Arrange
    without_logging = _ConfigLoaderSplunkES()
    monkeypatch.setenv("SPLUNKES_LOGGING_ENABLED", "true")
    monkeypatch.setenv("SPLUNKES_LOGGING_INDEXES", "sysmon")

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    logging_fields = {"logging_enabled", "logging_indexes"}
    assert config.model_dump(exclude=logging_fields) == (  # noqa: S101
        without_logging.model_dump(exclude=logging_fields)
    )


VALID_LOGGING_TEMPLATE = (
    "index IN ({indexes}) sourcetype=XmlWinEventLog* earliest={earliest} "
    "latest={latest} ({terms}) | table _time, index, _raw"
)


@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "spaces"])
def test_blank_logging_query_template_uses_the_built_in_search(
    monkeypatch, required_env, blank
):  # type: ignore
    """An empty Logging template means "use the built-in search"."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_LOGGING_QUERY_TEMPLATE", blank)

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.logging_query_template is None  # noqa: S101


def test_valid_logging_query_template_is_kept(
    monkeypatch, required_env
):  # type: ignore
    """A Logging template is kept as written (the client checks it)."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_LOGGING_QUERY_TEMPLATE", VALID_LOGGING_TEMPLATE)

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.logging_query_template == VALID_LOGGING_TEMPLATE  # noqa: S101
