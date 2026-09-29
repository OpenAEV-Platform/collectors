"""Configuration for Elastic Security integration."""

from datetime import timedelta
from enum import StrEnum
from typing import Any, Optional

from pydantic import Field, FilePath, SecretStr, field_validator, model_validator
from src.models.configs import ConfigBaseSettings


class ElasticAuthType(StrEnum):
    """Supported Elasticsearch authentication methods."""

    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"  # noqa: S105
    PKI = "PKI"


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
    auth_type: Optional[ElasticAuthType] = Field(
        alias="ELASTIC_AUTH_TYPE",
        default=None,
        description=(
            "Authentication method: API_KEY, PASSWORD (basic auth) or PKI "
            "(client certificate). When unset, it is inferred from the "
            "configured credentials (API key, then username/password, then "
            "client certificate)."
        ),
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
            "realm authentication (ELASTIC_AUTH_TYPE=PKI). Also presented for "
            "mutual TLS with the other methods. May contain the private key."
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

    @field_validator("auth_type", mode="before")
    @classmethod
    def _normalize_auth_type(cls, value: Any) -> Any:
        """Accept the authentication type case-insensitively.

        Args:
            value: Raw configured value.

        Returns:
            The upper-cased value when it is a string, the value otherwise.

        """
        return value.strip().upper() if isinstance(value, str) else value

    def resolved_auth_type(self) -> ElasticAuthType | None:
        """Return the configured authentication type, inferring it when unset.

        Returns:
            The explicit auth_type, or the first method with credentials
            configured (API key, username/password, client certificate), or
            None when nothing is configured.

        """
        if self.auth_type:
            return self.auth_type
        if self.api_key:
            return ElasticAuthType.API_KEY
        if self.username and self.password:
            return ElasticAuthType.PASSWORD
        if self.client_cert:
            return ElasticAuthType.PKI
        return None

    @model_validator(mode="after")
    def _validate_auth(self) -> "_ConfigLoaderElastic":
        """Ensure the credentials required by the authentication type are configured.

        Returns:
            The validated configuration instance.

        Raises:
            ValueError: If no usable authentication method is configured, if
                the selected method lacks its credentials, or if the client
                certificate settings are inconsistent.

        """
        if self.client_key and not self.client_cert:
            raise ValueError(
                "ELASTIC_CLIENT_KEY requires ELASTIC_CLIENT_CERT to be set"
            )
        if self.client_cert and not self.base_url.lower().startswith("https://"):
            raise ValueError(
                "A client certificate (ELASTIC_CLIENT_CERT) requires an https:// "
                "ELASTIC_BASE_URL"
            )

        auth_type = self.resolved_auth_type()
        if auth_type is None:
            raise ValueError(
                "Elastic authentication requires either ELASTIC_API_KEY, both "
                "ELASTIC_USERNAME and ELASTIC_PASSWORD, or ELASTIC_CLIENT_CERT"
            )
        if auth_type is ElasticAuthType.API_KEY and not self.api_key:
            raise ValueError("ELASTIC_AUTH_TYPE=API_KEY requires ELASTIC_API_KEY")
        if auth_type is ElasticAuthType.PASSWORD and not (
            self.username and self.password
        ):
            raise ValueError(
                "ELASTIC_AUTH_TYPE=PASSWORD requires ELASTIC_USERNAME and "
                "ELASTIC_PASSWORD"
            )
        if auth_type is ElasticAuthType.PKI and not self.client_cert:
            raise ValueError("ELASTIC_AUTH_TYPE=PKI requires ELASTIC_CLIENT_CERT")
        return self
