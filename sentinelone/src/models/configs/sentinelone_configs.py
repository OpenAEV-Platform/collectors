"""Configuration for SentinelOne integration."""

from datetime import timedelta

from pydantic import Field, SecretStr
from src.models.configs import ConfigBaseSettings


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
    offset: timedelta = Field(
        alias="SENTINELONE_OFFSET",
        default=timedelta(minutes=1),
        description="Duration to wait before each API call attempt. This offset accounts for event ingestion delay in SentinelOne (ISO 8601 format).",
    )
    max_retry: int = Field(
        alias="SENTINELONE_MAX_RETRY",
        default=5,
        description="Maximum number of retry attempts after the initial API call fails or returns no results.",
    )
