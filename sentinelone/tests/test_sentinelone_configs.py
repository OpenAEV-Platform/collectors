"""Tests for the Logging settings of the SentinelOne configuration model."""

import logging
from datetime import timedelta

import pytest
from pydantic import ValidationError
from src.models.configs.sentinelone_configs import _ConfigLoaderSentinelOne


@pytest.fixture()
def required_env(monkeypatch):  # type: ignore
    """Set the required SentinelOne settings."""
    monkeypatch.setenv("SENTINELONE_API_KEY", "fake-api-key")


@pytest.fixture()
def logging_on(monkeypatch):  # type: ignore
    """Enable Logging, with the raw-event search it needs."""
    monkeypatch.setenv("SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH", "true")
    monkeypatch.setenv("SENTINELONE_LOGGING_ENABLED", "true")


def test_logging_is_disabled_by_default(required_env):  # type: ignore
    """Without the Logging settings, Logging is off with a 15-minute max interval."""
    # Act
    config = _ConfigLoaderSentinelOne()

    # Assert
    assert config.logging_enabled is False  # noqa: S101
    assert config.logging_max_interval == timedelta(minutes=15)  # noqa: S101


def test_logging_enabled_with_deep_visibility_search_is_kept(
    required_env, logging_on
):  # type: ignore
    """Logging loads when raw-event search is enabled too."""
    # Act
    config = _ConfigLoaderSentinelOne()

    # Assert
    assert config.logging_enabled is True  # noqa: S101
    assert config.enable_deep_visibility_search is True  # noqa: S101


@pytest.mark.parametrize("search", [None, "false"], ids=["search-unset", "search-false"])
def test_logging_enabled_without_deep_visibility_search_fails(
    monkeypatch, required_env, search
):  # type: ignore
    """Enabling Logging without raw-event search fails at startup with a clear message."""
    # Arrange
    monkeypatch.setenv("SENTINELONE_LOGGING_ENABLED", "true")
    if search is not None:
        monkeypatch.setenv("SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH", search)

    # Act / Assert
    with pytest.raises(
        ValidationError, match="SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH is not"
    ):
        _ConfigLoaderSentinelOne()


def test_deep_visibility_search_alone_does_not_enable_logging(
    monkeypatch, required_env
):  # type: ignore
    """Raw-event search for Detection does not turn Logging on by itself."""
    # Arrange
    monkeypatch.setenv("SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH", "true")

    # Act
    config = _ConfigLoaderSentinelOne()

    # Assert
    assert config.logging_enabled is False  # noqa: S101


def test_logging_settings_leave_detection_settings_unchanged(
    monkeypatch, required_env
):  # type: ignore
    """Turning Logging on does not change the Detection settings."""
    # Arrange
    monkeypatch.setenv("SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH", "true")
    without_logging = _ConfigLoaderSentinelOne()
    monkeypatch.setenv("SENTINELONE_LOGGING_ENABLED", "true")

    # Act
    config = _ConfigLoaderSentinelOne()

    # Assert
    logging_fields = {"logging_enabled"}
    assert config.model_dump(exclude=logging_fields) == (  # noqa: S101
        without_logging.model_dump(exclude=logging_fields)
    )


@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
def test_blank_logging_flag_means_disabled(
    monkeypatch, required_env, blank
):  # type: ignore
    """A blank Logging flag sent by the platform is unset, so Logging is off."""
    # Arrange
    monkeypatch.setenv("SENTINELONE_LOGGING_ENABLED", blank)

    # Act
    config = _ConfigLoaderSentinelOne()

    # Assert
    assert config.logging_enabled is False  # noqa: S101


@pytest.mark.parametrize("value", [None, "", "   "], ids=["unset", "empty", "blank"])
def test_logging_max_interval_defaults_to_15_minutes(
    monkeypatch, required_env, value
):  # type: ignore
    """An unset or blank Logging max interval is 15 minutes."""
    # Arrange
    if value is not None:
        monkeypatch.setenv("SENTINELONE_LOGGING_MAX_INTERVAL", value)

    # Act
    config = _ConfigLoaderSentinelOne()

    # Assert
    assert config.logging_max_interval == timedelta(minutes=15)  # noqa: S101


@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "enabled"])
def test_logging_settings_left_empty_in_yaml_use_their_defaults(enabled):
    """A config.yml key without a value (null) is unset."""
    # Arrange
    settings = {
        "SENTINELONE_API_KEY": "fake-api-key",
        "enable_deep_visibility_search": enabled,
        "logging_enabled": enabled,
        "logging_max_interval": None,
    }

    # Act
    config = _ConfigLoaderSentinelOne.model_validate(settings)

    # Assert
    assert config.logging_enabled is enabled  # noqa: S101
    assert config.logging_max_interval == timedelta(minutes=15)  # noqa: S101


@pytest.mark.parametrize(
    ("value", "expected"),
    [("PT1M", timedelta(minutes=1)), ("PT1H", timedelta(hours=1))],
    ids=["one-minute", "one-hour"],
)
def test_logging_max_interval_is_kept_up_to_one_hour(
    monkeypatch, required_env, logging_on, value, expected
):  # type: ignore
    """A Logging max interval of at most one hour is loaded as given."""
    # Arrange
    monkeypatch.setenv("SENTINELONE_LOGGING_MAX_INTERVAL", value)

    # Act
    config = _ConfigLoaderSentinelOne()

    # Assert
    assert config.logging_max_interval == expected  # noqa: S101


@pytest.mark.parametrize(
    "value", ["PT1H1S", "PT0S", "soon"], ids=["over-one-hour", "zero", "not-a-duration"]
)
def test_invalid_logging_max_interval_fails_when_logging_is_enabled(
    monkeypatch, required_env, logging_on, value
):  # type: ignore
    """Logging on: an invalid max interval stops the collector, like Detection."""
    # Arrange
    monkeypatch.setenv("SENTINELONE_LOGGING_MAX_INTERVAL", value)

    # Act / Assert
    with pytest.raises(ValidationError, match="SENTINELONE_LOGGING_MAX_INTERVAL"):
        _ConfigLoaderSentinelOne()


@pytest.mark.parametrize("flag", [None, "false"], ids=["flag-unset", "flag-false"])
@pytest.mark.parametrize("value", ["PT2H", "soon"], ids=["over-one-hour", "type"])
def test_invalid_logging_max_interval_is_ignored_when_logging_is_disabled(
    monkeypatch, required_env, caplog, flag, value
):  # type: ignore
    """Logging off: an invalid Logging setting never stops the collector."""
    # Arrange
    if flag is not None:
        monkeypatch.setenv("SENTINELONE_LOGGING_ENABLED", flag)
    monkeypatch.setenv("SENTINELONE_LOGGING_MAX_INTERVAL", value)

    # Act
    with caplog.at_level(logging.WARNING):
        config = _ConfigLoaderSentinelOne()

    # Assert
    assert config.logging_enabled is False  # noqa: S101
    assert config.logging_max_interval == timedelta(minutes=15)  # noqa: S101
    assert (  # noqa: S101
        "SENTINELONE_LOGGING_MAX_INTERVAL is invalid but "
        "SENTINELONE_LOGGING_ENABLED is not true"
    ) in caplog.text


def test_invalid_logging_flag_fails_with_the_other_logging_errors(
    monkeypatch, required_env
):  # type: ignore
    """An invalid flag may mean "on": the other Logging errors are reported too."""
    # Arrange
    monkeypatch.setenv("SENTINELONE_LOGGING_ENABLED", "maybe")
    monkeypatch.setenv("SENTINELONE_LOGGING_MAX_INTERVAL", "PT2H")

    # Act / Assert
    with pytest.raises(ValidationError) as error:
        _ConfigLoaderSentinelOne()
    message = str(error.value)
    assert "SENTINELONE_LOGGING_ENABLED" in message  # noqa: S101
    assert "SENTINELONE_LOGGING_MAX_INTERVAL" in message  # noqa: S101
