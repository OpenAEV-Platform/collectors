"""Configuration for Elastic Security integration."""

from datetime import timedelta
from typing import Optional

from pydantic import Field, FilePath, SecretStr, model_validator
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderElastic(ConfigBaseSettings):
    """Elastic Security API configuration settings.

    Contains connection details, authentication, timing parameters, and retry
    settings for the Elasticsearch integration.
    """

    model_config = {"frozen": False}

    base_url: str = Field(
        alias="ELASTIC_BASE_URL",
        default="https://localhost:9200",
        description="Base URL of the Elasticsearch API (e.g., https://elastic.company.com:9200).",
    )
    api_key: Optional[SecretStr] = Field(
        alias="ELASTIC_API_KEY",
        default=None,
        description="Elasticsearch API key (preferred). When set, it is used instead of username/password.",
    )
    username: Optional[str] = Field(
        alias="ELASTIC_USERNAME",
        default=None,
        description="Username for HTTP basic authentication (used when no API key is set).",
    )
    password: Optional[SecretStr] = Field(
        alias="ELASTIC_PASSWORD",
        default=None,
        description="Password for HTTP basic authentication.",
    )
    client_cert: Optional[FilePath] = Field(
        alias="ELASTIC_CLIENT_CERT",
        default=None,
        description=(
            "Path to the PEM-encoded X.509 client certificate used for PKI "
            "realm authentication (used when neither an API key nor "
            "username/password is set). May also contain the private key."
        ),
    )
    client_key: Optional[FilePath] = Field(
        alias="ELASTIC_CLIENT_KEY",
        default=None,
        description=(
            "Path to the unencrypted PEM-encoded private key of the client "
            "certificate. Not needed when the key is bundled in the "
            "certificate file."
        ),
    )
    ca_cert: Optional[FilePath] = Field(
        alias="ELASTIC_CA_CERT",
        default=None,
        description=(
            "Path to a PEM-encoded CA bundle used to verify the Elasticsearch "
            "TLS certificate (e.g. an internal PKI). Ignored when verify_ssl "
            "is false."
        ),
    )
    alerts_index: Optional[str] = Field(
        alias="ELASTIC_ALERTS_INDEX",
        default=".alerts-security.alerts-*",
        description="Index or index pattern to search for detection alerts.",
    )
    kibana_url: Optional[str] = Field(
        alias="ELASTIC_KIBANA_URL",
        default=None,
        description=(
            "Kibana base URL used to build trace links. When unset, base_url "
            "is reused with its port rewritten to 5601; set this explicitly "
            "when Kibana is not reachable at that location (e.g. behind a "
            "reverse proxy or with no port in base_url)."
        ),
    )
    time_window: Optional[timedelta] = Field(
        alias="ELASTIC_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for searches when no dates are provided.",
    )
    max_retry: int = Field(
        alias="ELASTIC_MAX_RETRY",
        default=3,
        description="Maximum number of retry attempts for API calls.",
    )
    offset: timedelta = Field(
        alias="ELASTIC_OFFSET",
        default=timedelta(seconds=30),
        description="Time offset between retry attempts.",
    )
    verify_ssl: bool = Field(
        alias="ELASTIC_VERIFY_SSL",
        default=True,
        description="Whether to verify the Elasticsearch TLS certificate.",
    )

    @model_validator(mode="after")
    def _validate_auth(self) -> "_ConfigLoaderElastic":
        """Ensure an API key, a username/password pair or a client certificate is configured.

        Returns:
            The validated configuration instance.

        Raises:
            ValueError: If no usable authentication method is configured, or
                if the client certificate settings are inconsistent.

        """
        if self.client_key and not self.client_cert:
            raise ValueError(
                "ELASTIC_CLIENT_KEY requires ELASTIC_CLIENT_CERT to be set"
            )
        if self.client_cert and not self.base_url.lower().startswith("https://"):
            raise ValueError(
                "PKI authentication (ELASTIC_CLIENT_CERT) requires an https:// "
                "ELASTIC_BASE_URL"
            )
        if (
            not self.api_key
            and not (self.username and self.password)
            and not self.client_cert
        ):
            raise ValueError(
                "Elastic authentication requires either ELASTIC_API_KEY, both "
                "ELASTIC_USERNAME and ELASTIC_PASSWORD, or ELASTIC_CLIENT_CERT"
            )
        return self
