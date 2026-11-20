"""Tests for the Splunk ES configuration model."""

import logging
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


@pytest.fixture()
def logging_on(monkeypatch):  # type: ignore
    """Enable Logging on one index."""
    monkeypatch.setenv("SPLUNKES_LOGGING_ENABLED", "true")
    monkeypatch.setenv("SPLUNKES_LOGGING_INDEXES", "sysmon")


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


@pytest.mark.parametrize("value", [None, "", "   "], ids=["unset", "empty", "blank"])
def test_logging_max_interval_defaults_to_15_minutes(
    monkeypatch, required_env, value
):  # type: ignore
    """An unset or blank Logging max interval is 15 minutes."""
    # Arrange
    if value is not None:
        monkeypatch.setenv("SPLUNKES_LOGGING_MAX_INTERVAL", value)

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.logging_max_interval == timedelta(minutes=15)  # noqa: S101


@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "enabled"])
def test_logging_settings_left_empty_in_yaml_use_their_defaults(enabled):
    """A config.yml key without a value (null) is unset."""
    # Arrange
    settings = {
        "SPLUNKES_BASE_URL": "https://splunk.example.com:8089",
        "SPLUNKES_USERNAME": "admin",
        "SPLUNKES_PASSWORD": "changeme",
        "logging_enabled": enabled,
        "logging_indexes": "sysmon" if enabled else None,
        "logging_max_interval": None,
    }

    # Act
    config = _ConfigLoaderSplunkES.model_validate(settings)

    # Assert
    assert config.logging_indexes == ("sysmon" if enabled else None)  # noqa: S101
    assert config.logging_max_interval == timedelta(minutes=15)  # noqa: S101


@pytest.mark.parametrize(
    ("value", "expected"),
    [("PT1M", timedelta(minutes=1)), ("PT1H", timedelta(hours=1))],
    ids=["one-minute", "one-hour"],
)
def test_logging_max_interval_is_kept_up_to_one_hour(
    monkeypatch, required_env, value, expected
):  # type: ignore
    """A Logging max interval of at most one hour is loaded as given."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_LOGGING_MAX_INTERVAL", value)

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.logging_max_interval == expected  # noqa: S101


@pytest.mark.parametrize("value", ["PT1H1S", "PT0S"], ids=["over-one-hour", "zero"])
def test_logging_max_interval_out_of_bounds_is_rejected(
    monkeypatch, required_env, logging_on, value
):  # type: ignore
    """With Logging enabled, a max interval above one hour or not positive is rejected."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_LOGGING_MAX_INTERVAL", value)

    # Act / Assert
    with pytest.raises(ValidationError, match="SPLUNKES_LOGGING_MAX_INTERVAL"):
        _ConfigLoaderSplunkES()


INVALID_LOGGING_SETTINGS = [
    (
        "SPLUNKES_LOGGING_MAX_INTERVAL",
        "PT2H",
        "logging_max_interval",
        timedelta(minutes=15),
    ),
    (
        "SPLUNKES_LOGGING_MAX_INTERVAL",
        "soon",
        "logging_max_interval",
        timedelta(minutes=15),
    ),
]
INVALID_LOGGING_IDS = [
    "interval-bound",
    "interval-type",
]


@pytest.mark.parametrize("flag", [None, "false"], ids=["flag-unset", "flag-false"])
@pytest.mark.parametrize(
    ("variable", "value", "field", "default"),
    INVALID_LOGGING_SETTINGS,
    ids=INVALID_LOGGING_IDS,
)
def test_invalid_logging_setting_is_ignored_when_logging_is_disabled(
    monkeypatch, required_env, caplog, flag, variable, value, field, default
):  # type: ignore
    """Logging off: an invalid Logging setting never stops the collector."""
    # Arrange
    if flag is not None:
        monkeypatch.setenv("SPLUNKES_LOGGING_ENABLED", flag)
    monkeypatch.setenv(variable, value)

    # Act
    with caplog.at_level(logging.WARNING):
        config = _ConfigLoaderSplunkES()

    # Assert
    assert config.logging_enabled is False  # noqa: S101
    assert getattr(config, field) == default  # noqa: S101
    assert f"{variable} is invalid but SPLUNKES_LOGGING_ENABLED is not true" in (
        caplog.text
    )  # noqa: S101


@pytest.mark.parametrize(
    ("variable", "value", "field", "default"),
    INVALID_LOGGING_SETTINGS,
    ids=INVALID_LOGGING_IDS,
)
def test_invalid_logging_setting_fails_when_logging_is_enabled(
    monkeypatch, required_env, logging_on, variable, value, field, default
):  # type: ignore
    """Logging on: an invalid Logging setting stops the collector, like Detection."""
    # Arrange
    monkeypatch.setenv(variable, value)

    # Act / Assert
    with pytest.raises(ValidationError, match=variable):
        _ConfigLoaderSplunkES()


def test_invalid_logging_flag_fails_with_the_other_logging_errors(
    monkeypatch, required_env
):  # type: ignore
    """An invalid flag may mean "on": the other Logging errors are reported too."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_LOGGING_ENABLED", "maybe")
    monkeypatch.setenv("SPLUNKES_LOGGING_MAX_INTERVAL", "PT2H")

    # Act / Assert
    with pytest.raises(ValidationError) as error:
        _ConfigLoaderSplunkES()
    message = str(error.value)
    assert "SPLUNKES_LOGGING_ENABLED" in message  # noqa: S101
    assert "SPLUNKES_LOGGING_MAX_INTERVAL" in message  # noqa: S101


@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "enabled"])
@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
def test_blank_logging_settings_use_their_defaults_silently(
    monkeypatch, required_env, caplog, enabled, blank
):  # type: ignore
    """A blank Logging setting is unset, not invalid, whether Logging is on or off."""
    # Arrange
    if enabled:
        monkeypatch.setenv("SPLUNKES_LOGGING_ENABLED", "true")
        monkeypatch.setenv("SPLUNKES_LOGGING_INDEXES", "sysmon")
    monkeypatch.setenv("SPLUNKES_LOGGING_MAX_INTERVAL", blank)

    # Act
    with caplog.at_level(logging.WARNING):
        config = _ConfigLoaderSplunkES()

    # Assert
    assert config.logging_max_interval == timedelta(minutes=15)  # noqa: S101
    assert "is invalid" not in caplog.text  # noqa: S101


# Scenario: The retry window defaults to 20 minutes and is configurable
# (behavior contract in tests/services/test_expectation_retry_window.py).
@pytest.mark.parametrize(
    ("env_value", "expected"),
    [
        (None, timedelta(minutes=20)),
        ("", timedelta(minutes=20)),
        ("PT30M", timedelta(minutes=30)),
    ],
    ids=["unset-defaults-to-20m", "blank-defaults-to-20m", "pt30m-is-kept"],
)
def test_retry_window_defaults_to_20_minutes_and_is_configurable(
    monkeypatch, required_env, env_value, expected
):  # type: ignore
    """The detection retry window covers the risk-index ingestion lag."""
    # Arrange
    if env_value is not None:
        monkeypatch.setenv("SPLUNKES_RETRY_WINDOW", env_value)

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.retry_window == expected  # noqa: S101


# --------------
# Authentication
# --------------


@pytest.fixture()
def no_credentials(monkeypatch):  # type: ignore
    """Start from a Splunk base URL only, without any credential.

    The settings also match the field names, so a generic ``$USERNAME``,
    ``$PASSWORD`` or ``$TOKEN`` of the shell running the tests would otherwise
    act as a credential.
    """
    monkeypatch.setenv("SPLUNKES_BASE_URL", "https://splunk.example.com:8089")
    for name in (
        "SPLUNKES_USERNAME",
        "SPLUNKES_PASSWORD",
        "SPLUNKES_TOKEN",
        "username",
        "USERNAME",
        "password",
        "PASSWORD",
        "token",
        "TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)


def test_token_alone_is_enough(monkeypatch, no_credentials):  # type: ignore
    """A Splunk authentication token is a complete credential on its own."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_TOKEN", "eyJraWQiOiJzcGx1bmsuc2VjcmV0In0.payload.sig")

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.token is not None  # noqa: S101
    assert (  # noqa: S101
        config.token.get_secret_value() == "eyJraWQiOiJzcGx1bmsuc2VjcmV0In0.payload.sig"
    )
    assert config.username is None  # noqa: S101
    assert config.password is None  # noqa: S101


def test_token_is_never_shown(monkeypatch, no_credentials):  # type: ignore
    """The token is a secret: it does not appear when the settings are printed."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_TOKEN", "super-secret-token")

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert "super-secret-token" not in repr(config)  # noqa: S101
    assert "super-secret-token" not in str(config)  # noqa: S101


def test_username_and_password_still_work(monkeypatch, no_credentials):  # type: ignore
    """Username/password authentication stays supported without a token."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_USERNAME", "svc_openaev")
    monkeypatch.setenv("SPLUNKES_PASSWORD", "changeme")

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.token is None  # noqa: S101
    assert config.username == "svc_openaev"  # noqa: S101
    assert config.password is not None  # noqa: S101
    assert config.password.get_secret_value() == "changeme"  # noqa: S101


@pytest.mark.parametrize(
    "settings",
    [
        {},
        {"SPLUNKES_USERNAME": "svc_openaev"},
        {"SPLUNKES_PASSWORD": "changeme"},
    ],
    ids=["nothing", "username-only", "password-only"],
)
def test_missing_credentials_are_rejected(
    monkeypatch, no_credentials, settings
):  # type: ignore
    """Without a token, both the username and the password are required."""
    # Arrange
    for name, value in settings.items():
        monkeypatch.setenv(name, value)

    # Act / Assert
    with pytest.raises(ValidationError) as error:
        _ConfigLoaderSplunkES()
    message = str(error.value)
    assert "SPLUNKES_TOKEN" in message  # noqa: S101
    assert "SPLUNKES_USERNAME" in message  # noqa: S101
    assert "SPLUNKES_PASSWORD" in message  # noqa: S101


@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
def test_blank_credentials_of_the_unused_method_are_unset(
    monkeypatch, no_credentials, blank
):  # type: ignore
    """The catalog form sends the unused authentication method as blank values."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_TOKEN", "a-token")
    monkeypatch.setenv("SPLUNKES_USERNAME", blank)
    monkeypatch.setenv("SPLUNKES_PASSWORD", blank)

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.username is None  # noqa: S101
    assert config.password is None  # noqa: S101


@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
def test_blank_token_falls_back_to_username_and_password(
    monkeypatch, no_credentials, blank
):  # type: ignore
    """A blank token is unset: the username and password are used."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_TOKEN", blank)
    monkeypatch.setenv("SPLUNKES_USERNAME", "svc_openaev")
    monkeypatch.setenv("SPLUNKES_PASSWORD", "changeme")

    # Act
    config = _ConfigLoaderSplunkES()

    # Assert
    assert config.token is None  # noqa: S101
    assert config.username == "svc_openaev"  # noqa: S101


def test_blank_token_without_username_and_password_is_rejected(
    monkeypatch, no_credentials
):  # type: ignore
    """A blank token is not a credential."""
    # Arrange
    monkeypatch.setenv("SPLUNKES_TOKEN", "")

    # Act / Assert
    with pytest.raises(ValidationError, match="SPLUNKES_TOKEN"):
        _ConfigLoaderSplunkES()


def test_token_from_config_yml_is_accepted(no_credentials):  # type: ignore
    """In config.yml the token is set as ``splunk_es.token``."""
    # Arrange
    settings = {
        "base_url": "https://splunk.example.com:8089",
        "token": "a-token",
        "username": None,
        "password": None,
    }

    # Act
    config = _ConfigLoaderSplunkES.model_validate(settings)

    # Assert
    assert config.token is not None  # noqa: S101
    assert config.token.get_secret_value() == "a-token"  # noqa: S101
