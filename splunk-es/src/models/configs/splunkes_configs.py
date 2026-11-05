"""Configuration for SplunkES integration."""

import logging
import string
from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_core import PydanticUseDefault
from src.models.configs import ConfigBaseSettings

LOG_PREFIX = "[SplunkESConfig]"

# Placeholders a custom Logging query template can use. The query builder
# fills every one of them (see services/logging_query.py).
LOGGING_TEMPLATE_PLACEHOLDERS = frozenset(
    {
        "indexes",
        "earliest",
        "latest",
        "terms",
        "source_ips",
        "target_ips",
        "rank_cases",
        "max_rows",
    }
)


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
        "{earliest}, {latest}, {terms}, {source_ips}, {target_ips}, "
        "{rank_cases}, {max_rows}. Must return oaev_event_epoch, index and "
        "_raw. Leave empty to use the built-in search.",
    )
    logging_max_rows: int = Field(
        alias="SPLUNKES_LOGGING_MAX_ROWS",
        default=50,
        ge=1,
        le=1000,
        description="Maximum number of raw events read per LOGGING search "
        "(1 to 1000, default 50).",
    )

    @field_validator(
        "alerts_index",
        "time_window",
        "query_template",
        "logging_enabled",
        "logging_indexes",
        "logging_query_template",
        "logging_max_rows",
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

    @field_validator("logging_query_template", mode="after")
    @classmethod
    def _check_logging_query_template(cls, value: Optional[str]) -> Optional[str]:
        """Reject a Logging template with an unknown placeholder, at startup.

        Raises:
            ValueError: If the template uses a placeholder the builder does
                not fill, or has an unpaired brace.

        """
        if value is None:
            return value
        parsed = string.Formatter().parse(value)
        used = {name for _, name, _, _ in parsed if name is not None}
        unknown = used - LOGGING_TEMPLATE_PLACEHOLDERS
        if unknown:
            raise ValueError(
                f"Unknown placeholders in SPLUNKES_LOGGING_QUERY_TEMPLATE: "
                f"{sorted(unknown)}. Allowed: {sorted(LOGGING_TEMPLATE_PLACEHOLDERS)}"
            )
        return value

    @model_validator(mode="after")
    def _check_logging_indexes(self) -> "_ConfigLoaderSplunkES":
        """Require at least one index when Logging is enabled.

        There is no default index on purpose: searching the wrong one would
        turn every LOGGING expectation into "Not Logged".

        Raises:
            ValueError: If Logging is enabled without any index.

        """
        if self.logging_enabled and not self.logging_indexes:
            raise ValueError(
                "SPLUNKES_LOGGING_ENABLED is true but SPLUNKES_LOGGING_INDEXES "
                "is empty: set the raw-event indexes to search, e.g. "
                "SPLUNKES_LOGGING_INDEXES=sysmon,wineventlog"
            )
        if not self.logging_enabled and self.logging_indexes:
            logging.getLogger(__name__).info(
                f"{LOG_PREFIX} SPLUNKES_LOGGING_INDEXES is set but "
                "SPLUNKES_LOGGING_ENABLED is not true: the indexes are ignored"
            )
        return self
