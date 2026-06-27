"""Configuration for LogRhythm SIEM integration."""

from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr, model_validator
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderLogRhythm(ConfigBaseSettings):
    """LogRhythm Search API configuration settings.

    Contains connection details, authentication, and timing parameters for the
    LogRhythm Search API integration.
    """

    model_config = {"frozen": False}

    base_url: str = Field(
        alias="LOGRHYTHM_BASE_URL",
        default="https://logrhythm.company.com:8501",
        description="Base URL of the LogRhythm API gateway (hosting lr-search-api).",
    )
    token: Optional[SecretStr] = Field(
        alias="LOGRHYTHM_TOKEN",
        default=None,
        description="LogRhythm API bearer token (preferred). Sent as 'Authorization: Bearer'.",
    )
    username: Optional[str] = Field(
        alias="LOGRHYTHM_USERNAME",
        default=None,
        description="Username for HTTP basic authentication (used when no token is set).",
    )
    password: Optional[SecretStr] = Field(
        alias="LOGRHYTHM_PASSWORD",
        default=None,
        description="Password for HTTP basic authentication.",
    )
    query_event_manager: bool = Field(
        alias="LOGRHYTHM_QUERY_EVENT_MANAGER",
        default=True,
        description="Whether to query the Event Manager (events) in addition to raw logs.",
    )
    max_msgs: int = Field(
        alias="LOGRHYTHM_MAX_MSGS",
        default=100,
        description="Maximum number of messages to query per search.",
    )
    console_url: Optional[str] = Field(
        alias="LOGRHYTHM_CONSOLE_URL",
        default=None,
        description="LogRhythm Web Console URL used to build trace links (defaults to base_url).",
    )
    verify_ssl: bool = Field(
        alias="LOGRHYTHM_VERIFY_SSL",
        default=True,
        description="Whether to verify the LogRhythm TLS certificate.",
    )
    time_window: Optional[timedelta] = Field(
        alias="LOGRHYTHM_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for searches when no dates are provided.",
    )
    max_retry: int = Field(
        alias="LOGRHYTHM_MAX_RETRY",
        default=3,
        description="Maximum number of retry attempts for API calls.",
    )
    offset: timedelta = Field(
        alias="LOGRHYTHM_OFFSET",
        default=timedelta(seconds=30),
        description="Time offset between retry attempts.",
    )
    search_timeout: timedelta = Field(
        alias="LOGRHYTHM_SEARCH_TIMEOUT",
        default=timedelta(minutes=5),
        description="Maximum time to wait for a search task to complete.",
    )
    poll_interval: timedelta = Field(
        alias="LOGRHYTHM_POLL_INTERVAL",
        default=timedelta(seconds=5),
        description="Interval between search result status polls.",
    )

    @model_validator(mode="after")
    def _validate_auth(self) -> "_ConfigLoaderLogRhythm":
        """Ensure either a token or a username/password pair is configured.

        Returns:
            The validated configuration instance.

        Raises:
            ValueError: If no usable authentication method is configured.

        """
        if not self.token and not (self.username and self.password):
            raise ValueError(
                "LogRhythm authentication requires either LOGRHYTHM_TOKEN or both "
                "LOGRHYTHM_USERNAME and LOGRHYTHM_PASSWORD"
            )
        return self
