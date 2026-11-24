"""Configuration for SentinelOne integration."""

import logging
from datetime import timedelta

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

LOG_PREFIX = "[SentinelOneConfig]"

MAX_LOGGING_INTERVAL = timedelta(hours=1)


class _ConfigLoaderSentinelOne(ConfigBaseSettings):
    """SentinelOne API configuration settings.

    Contains connection details, timing parameters, and retry settings
    for SentinelOne API integration.
    """

    base_url: str | None = Field(
        alias="SENTINELONE_BASE_URL",
        default="https://api.sentinelone.com",
        description="URL for the SentinelOne API.",
    )
    api_key: SecretStr = Field(
        alias="SENTINELONE_API_KEY",
        description="API Key for the SentinelOne API.",
    )
    time_window: timedelta = Field(
        alias="SENTINELONE_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for SentinelOne threat searches when no date signatures are provided (ISO 8601 format).",
    )
    retry_window: timedelta = Field(
        alias="SENTINELONE_RETRY_WINDOW",
        default=timedelta(minutes=10),
        description="How long after the first attempt an unresolved expectation is re-attempted on every collector cycle, before one final attempt emits the verdict (ISO 8601 format).",
    )
    expectation_batch_size: int = Field(
        alias="SENTINELONE_EXPECTATION_BATCH_SIZE",
        default=50,
        description="Number of expectations to process in each batch for batch-based processing.",
    )
    enable_deep_visibility_search: bool = Field(
        alias="SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH",
        default=False,
        description=(
            "Allow the collector to search raw events (Deep Visibility on "
            "self-hosted, Event Search on SaaS). Used to validate static-engine "
            "detections, and required by SENTINELONE_LOGGING_ENABLED. Needs the "
            "Deep Visibility permission and licence."
        ),
    )
    enable_alerts: bool = Field(
        alias="SENTINELONE_ENABLE_ALERTS",
        default=True,
        description=(
            "Also correlate SentinelOne Unified Alerts (Singularity alerts "
            "GraphQL API), not only Threats. Behavioral / STAR / AI detections "
            "(e.g. Potential Mimikatz Execution) surface as Unified Alerts and "
            "never as Threats, so this is required to validate them. SaaS only; "
            "ignored on self-hosted instances."
        ),
    )
    deep_visibility_lookback: timedelta = Field(
        alias="SENTINELONE_DEEP_VISIBILITY_LOOKBACK",
        default=timedelta(days=1),
        description=(
            "Lookback window (ISO 8601 duration, e.g. PT1H / P1D) for the Deep "
            "Visibility / SDL file-event pivot query. Decoupled from the threat "
            "window: a file can be dropped or executed long before the alert that "
            "references it is raised, so the event query pivots on the file SHA1 and "
            "reaches back this far from now. Keep it within the account's Deep "
            "Visibility retention (30/90/180/365 days)."
        ),
    )
    logging_enabled: bool = Field(
        alias="SENTINELONE_LOGGING_ENABLED",
        default=False,
        description="Search raw events to answer LOGGING expectations. "
        "Requires SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH.",
    )
    logging_max_interval: timedelta = Field(
        alias="SENTINELONE_LOGGING_MAX_INTERVAL",
        default=timedelta(minutes=15),
        description="Longest time between two Logging searches of the same "
        "expectation (ISO 8601, at most PT1H). Searches start every collector "
        "period and their interval doubles while nothing is found; a value "
        "below the collector period means the period.",
    )

    @field_validator("logging_enabled", mode="before")
    @classmethod
    def _empty_str_to_default(cls, value: object) -> object:
        """Treat an empty value as unset, so the default applies.

        The platform sends an optional setting left blank in the catalog form
        as an empty environment variable. Without this, a blank Logging flag
        would stop the collector at every start.
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
                "SENTINELONE_LOGGING_MAX_INTERVAL must be a positive duration of "
                f"at most PT1H, got {value}"
            )
        return value

    @model_validator(mode="after")
    def _require_deep_visibility_search(self) -> "_ConfigLoaderSentinelOne":
        """Require raw-event search when Logging is enabled.

        Logging searches raw events, and the Deep Visibility search setting is
        what allows the collector to do that. Stopping at startup shows the
        mistake at once, instead of a collector that never answers LOGGING.

        Raises:
            ValueError: If Logging is enabled while raw-event search is not.

        """
        if self.logging_enabled and not self.enable_deep_visibility_search:
            raise ValueError(
                "SENTINELONE_LOGGING_ENABLED is true but "
                "SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH is not: Logging "
                "searches raw events, so set both to true (the token needs the "
                "Deep Visibility permission)"
            )
        return self

    # Defined last on purpose: it wraps the other validators of this field.
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
                f"{LOG_PREFIX} {field.alias} is invalid but "
                "SENTINELONE_LOGGING_ENABLED is not true: it is ignored "
                f"({e.errors()[0]['msg']})"
            )
            return field.get_default(call_default_factory=True)
