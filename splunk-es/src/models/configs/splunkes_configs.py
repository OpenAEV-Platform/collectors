"""Configuration for SplunkES integration."""

from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr, field_validator
from pydantic_core import PydanticUseDefault
from src.models.configs import ConfigBaseSettings


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

    @field_validator("alerts_index", "time_window", "query_template", mode="before")
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
