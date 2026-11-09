"""Configuration for SplunkES integration."""

import logging
from datetime import timedelta
from typing import Optional

from pydantic import (
    Field,
    SecretStr,
    ValidationError,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticUseDefault
from src.models.configs import ConfigBaseSettings

LOG_PREFIX = "[SplunkESConfig]"

MAX_LOGGING_INTERVAL = timedelta(hours=1)


class _ConfigLoaderSplunkES(ConfigBaseSettings):
    """SplunkES API configuration settings.

    Contains connection details, timing parameters, and retry settings
    for SplunkES API integration.
    """

    model_config = {"frozen": False}

    base_url: str = Field(
        alias="SPLUNKES_BASE_URL",
        description="Base URL for the Splunk ES instance (e.g., https://splunk.company.com:8089).",
    )
    username: str = Field(
        alias="SPLUNKES_USERNAME",
        description="Username for Splunk ES authentication.",
    )
    password: SecretStr = Field(
        alias="SPLUNKES_PASSWORD",
        description="Password for Splunk ES authentication.",
    )
    alerts_index: Optional[str] = Field(
        alias="SPLUNKES_ALERTS_INDEX",
        default="notable",
        description="Index to search for alerts (default: notable, the Splunk ES "
        "notable index).",
    )
    time_window: Optional[timedelta] = Field(
        alias="SPLUNKES_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for searches when no dates provided.",
    )
    max_retry: int = Field(
        alias="SPLUNKES_MAX_RETRY",
        default=5,
        description="Maximum number of retry attempts for API calls. Combined "
        "with offset, this defines how long the collector keeps looking for a "
        "notable after an inject (default 5 x 120s covers ~10 min of detection "
        "latency: SIEM ingestion + correlation-search schedule).",
    )
    offset: timedelta = Field(
        alias="SPLUNKES_OFFSET",
        default=timedelta(seconds=120),
        description="Time waited between retry attempts, also used to extend the "
        "search window forward on each retry.",
    )
    query_template: Optional[str] = Field(
        alias="SPLUNKES_QUERY_TEMPLATE",
        default=None,
        description="SPL query template with placeholders: {alerts_index}, {source_ips}, "
        "{target_ips}, {hostnames}, {start_date}, {end_date}. "
        "Must include '| table _time' for proper alert parsing. "
        "Leave empty to use the default query.",
    )
    logging_enabled: bool = Field(
        alias="SPLUNKES_LOGGING_ENABLED",
        default=False,
        description="Search raw-event indexes to answer LOGGING expectations. "
        "Requires SPLUNKES_LOGGING_INDEXES.",
    )
    logging_indexes: Optional[str] = Field(
        alias="SPLUNKES_LOGGING_INDEXES",
        default=None,
        description="Comma-separated raw-event indexes or patterns searched for "
        "LOGGING expectations (e.g. sysmon,wineventlog). No default: required "
        "when SPLUNKES_LOGGING_ENABLED is true.",
    )
    logging_query_template: Optional[str] = Field(
        alias="SPLUNKES_LOGGING_QUERY_TEMPLATE",
        default=None,
        description="SPL template of the Logging search, to adapt it to your "
        "data (sourcetypes, data models, field names). Placeholders: {indexes}, "
        "{earliest}, {latest}, {terms}, {source_ips}, {target_ips}. Must "
        "include '| table _time, index, _raw'. Leave empty to use the built-in "
        "search.",
    )
    logging_max_interval: timedelta = Field(
        alias="SPLUNKES_LOGGING_MAX_INTERVAL",
        default=timedelta(minutes=15),
        description="Longest time between two Logging searches of the same "
        "expectation (ISO 8601, at most PT1H). Searches start every collector "
        "period and their interval doubles while nothing is found; a value "
        "below the collector period means the period.",
    )

    @field_validator(
        "alerts_index",
        "time_window",
        "query_template",
        "logging_enabled",
        "logging_indexes",
        "logging_query_template",
        mode="before",
    )
    @classmethod
    def _empty_str_to_default(cls, value: object) -> object:
        """Treat an explicitly empty/whitespace value as unset (field default).

        The platform passes an optional setting left blank in the catalog form as
        an empty env var, which ``str_min_length=1`` would reject, crash-looping
        the collector. Clearing the prefilled ``SPLUNKES_QUERY_TEMPLATE`` is the
        natural way back to the built-in query, so an empty value must mean
        "unset": ``SPLUNKES_QUERY_TEMPLATE=`` uses the built-in query,
        ``SPLUNKES_ALERTS_INDEX=`` the ``notable`` index and
        ``SPLUNKES_TIME_WINDOW=`` the one-hour window.
        """
        if isinstance(value, str) and not value.strip():
            raise PydanticUseDefault()
        return value

    @field_validator("logging_max_interval")
    @classmethod
    def _check_logging_max_interval(cls, value: timedelta) -> timedelta:
        """Keep the Logging search interval positive and at most one hour."""
        if not timedelta(0) < value <= MAX_LOGGING_INTERVAL:
            raise ValueError(
                "SPLUNKES_LOGGING_MAX_INTERVAL must be a positive duration of at "
                f"most PT1H, got {value}"
            )
        return value

    @model_validator(mode="after")
    def _require_logging_indexes(self) -> "_ConfigLoaderSplunkES":
        """Require at least one index when Logging is enabled.

        There is no default index on purpose: searching the wrong one would
        turn every LOGGING expectation into "Not Logged".

        Raises:
            ValueError: If Logging is enabled without any index.

        """
        if self.logging_enabled and not (self.logging_indexes or "").strip(", "):
            raise ValueError(
                "SPLUNKES_LOGGING_ENABLED is true but SPLUNKES_LOGGING_INDEXES "
                "is empty: set the raw-event indexes to search, e.g. "
                "SPLUNKES_LOGGING_INDEXES=sysmon,wineventlog"
            )
        return self

    # Defined last on purpose: it wraps the other validators of these fields.
    @field_validator("logging_max_interval", mode="wrap")
    @classmethod
    def _ignore_invalid_logging_setting_when_disabled(
        cls, value: object, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> object:
        """Fail on an invalid Logging setting only when Logging is enabled.

        Enabled, an invalid setting stops the collector at startup, like an
        invalid Detection setting: the mistake is seen at once. Disabled, it
        must not stop Detection: it is ignored with a warning and its default
        is used. A blank value or a YAML key without a value means unset.

        Raises:
            ValidationError: If the setting is invalid and Logging is enabled,
                or the Logging flag itself is invalid.

        """
        field = cls.model_fields[info.field_name]  # type: ignore[index]
        # Blank, or a YAML key without a value: unset. Handled here, since
        # pydantic does not apply PydanticUseDefault through a wrap validator.
        if value is None or (isinstance(value, str) and not value.strip()):
            return field.get_default(call_default_factory=True)
        try:
            return handler(value)
        except ValidationError as e:
            # Missing: the flag itself is invalid and already fails the config.
            if info.data.get("logging_enabled", True) is not False:
                raise
            logging.getLogger(__name__).warning(
                f"{LOG_PREFIX} {field.alias} is invalid but SPLUNKES_LOGGING_ENABLED "
                f"is not true: it is ignored ({e.errors()[0]['msg']})"
            )
            return field.get_default(call_default_factory=True)
