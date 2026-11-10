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
        description="Enable deep visibility search for SentinelOne threat searches.",
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
    disable_strict_end_date: bool = Field(
        alias="SENTINELONE_DISABLE_STRICT_END_DATE",
        default=False,
        description="Disable ignoring OpenAEV expectations without a proper end dates.",
    )
