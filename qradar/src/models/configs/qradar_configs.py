"""Configuration for IBM QRadar integration."""

from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr, model_validator
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderQRadar(ConfigBaseSettings):
    """IBM QRadar API configuration settings.

    Contains connection details, authentication, the Ariel data source, and
    timing parameters for the QRadar REST API integration.
    """

    model_config = {"frozen": False}

    base_url: str = Field(
        alias="QRADAR_BASE_URL",
        default="https://qradar.company.com",
        description="Base URL of the QRadar console (e.g., https://qradar.company.com).",
    )
    token: Optional[SecretStr] = Field(
        alias="QRADAR_TOKEN",
        default=None,
        description="QRadar authorized service token (preferred). Sent in the SEC header.",
    )
    username: Optional[str] = Field(
        alias="QRADAR_USERNAME",
        default=None,
        description="Username for HTTP basic authentication (used when no token is set).",
    )
    password: Optional[SecretStr] = Field(
        alias="QRADAR_PASSWORD",
        default=None,
        description="Password for HTTP basic authentication.",
    )
    api_version: str = Field(
        alias="QRADAR_API_VERSION",
        default="20.0",
        description="QRadar REST API version sent in the Version header.",
    )
    data_source: str = Field(
        alias="QRADAR_DATA_SOURCE",
        default="events",
        description="Ariel data source to query (events or flows).",
    )
    console_url: Optional[str] = Field(
        alias="QRADAR_CONSOLE_URL",
        default=None,
        description="QRadar console URL used to build trace links (defaults to base_url).",
    )
    verify_ssl: bool = Field(
        alias="QRADAR_VERIFY_SSL",
        default=True,
        description="Whether to verify the QRadar TLS certificate.",
    )
    time_window: Optional[timedelta] = Field(
        alias="QRADAR_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for searches when no dates are provided.",
    )
    max_retry: int = Field(
        alias="QRADAR_MAX_RETRY",
        default=3,
        description="Maximum number of retry attempts for API calls.",
    )
    offset: timedelta = Field(
        alias="QRADAR_OFFSET",
        default=timedelta(seconds=30),
        description="Time offset between retry attempts.",
    )
    search_timeout: timedelta = Field(
        alias="QRADAR_SEARCH_TIMEOUT",
        default=timedelta(minutes=5),
        description="Maximum time to wait for an Ariel search to complete.",
    )
    poll_interval: timedelta = Field(
        alias="QRADAR_POLL_INTERVAL",
        default=timedelta(seconds=5),
        description="Interval between Ariel search status polls.",
    )

    @model_validator(mode="after")
    def _validate_auth(self) -> "_ConfigLoaderQRadar":
        """Ensure either a token or a username/password pair is configured.

        Returns:
            The validated configuration instance.

        Raises:
            ValueError: If no usable authentication method is configured.

        """
        if not self.token and not (self.username and self.password):
            raise ValueError(
                "QRadar authentication requires either QRADAR_TOKEN or both "
                "QRADAR_USERNAME and QRADAR_PASSWORD"
            )
        return self
