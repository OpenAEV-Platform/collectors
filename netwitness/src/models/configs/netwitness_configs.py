"""Configuration for NetWitness integration."""

from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr, model_validator
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderNetWitness(ConfigBaseSettings):
    """NetWitness Core SDK configuration settings.

    Contains connection details, authentication, and timing parameters for the
    NetWitness Core SDK query API integration.
    """

    model_config = {"frozen": False}

    base_url: str = Field(
        alias="NETWITNESS_BASE_URL",
        default="https://netwitness.company.com:50103",
        description="Base URL of a NetWitness Core service (e.g., Broker on port 50103).",
    )
    token: Optional[SecretStr] = Field(
        alias="NETWITNESS_TOKEN",
        default=None,
        description="Bearer token for the NetWitness Platform API (optional).",
    )
    username: Optional[str] = Field(
        alias="NETWITNESS_USERNAME",
        default=None,
        description="Username for HTTP basic authentication to the Core SDK.",
    )
    password: Optional[SecretStr] = Field(
        alias="NETWITNESS_PASSWORD",
        default=None,
        description="Password for HTTP basic authentication.",
    )
    max_results: int = Field(
        alias="NETWITNESS_MAX_RESULTS",
        default=100,
        description="Maximum number of sessions to return per query.",
    )
    console_url: Optional[str] = Field(
        alias="NETWITNESS_CONSOLE_URL",
        default=None,
        description="NetWitness console URL used to build trace links (defaults to base_url).",
    )
    verify_ssl: bool = Field(
        alias="NETWITNESS_VERIFY_SSL",
        default=True,
        description="Whether to verify the NetWitness TLS certificate.",
    )
    time_window: Optional[timedelta] = Field(
        alias="NETWITNESS_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for searches when no dates are provided.",
    )
    max_retry: int = Field(
        alias="NETWITNESS_MAX_RETRY",
        default=3,
        description="Maximum number of retry attempts for API calls.",
    )
    offset: timedelta = Field(
        alias="NETWITNESS_OFFSET",
        default=timedelta(seconds=30),
        description="Time offset between retry attempts.",
    )

    @model_validator(mode="after")
    def _validate_auth(self) -> "_ConfigLoaderNetWitness":
        """Ensure either a token or a username/password pair is configured.

        Returns:
            The validated configuration instance.

        Raises:
            ValueError: If no usable authentication method is configured.

        """
        if not self.token and not (self.username and self.password):
            raise ValueError(
                "NetWitness authentication requires either NETWITNESS_TOKEN or both "
                "NETWITNESS_USERNAME and NETWITNESS_PASSWORD"
            )
        return self
