"""Configuration for SplunkES integration."""

from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr

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
        default="main",
        description="Index to search for alerts (default: _notable).",
    )
    time_window: Optional[timedelta] = Field(
        alias="SPLUNKES_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for searches when no dates provided.",
    )
    max_retry: int = Field(
        alias="SPLUNKES_MAX_RETRY",
        default=3,
        description="Maximum number of retry attempts for API calls.",
    )
    offset: timedelta = Field(
        alias="SPLUNKES_OFFSET",
        default=timedelta(seconds=30),
        description="Time offset between retry attempts.",
    )
