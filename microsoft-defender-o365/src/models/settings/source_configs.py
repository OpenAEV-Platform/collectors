"""Configuration for Microsoft Defender for Office 365 business integration."""

from pydantic import (
    Field,
    HttpUrl,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import SettingsConfigDict
from src.models.settings import ConfigBaseSettings


class _ConfigLoaderSource(ConfigBaseSettings):
    """Source configuration settings.

    Contains authentication, connection, and rate-limiting parameters for the
    Microsoft Defender for Office 365 source integration.
    """

    model_config = SettingsConfigDict(
        **{**ConfigBaseSettings.model_config, "loc_by_alias": False},
    )

    tenant_id: str = Field(
        description="Azure AD (Entra ID) tenant identifier used to authenticate against "
        "Microsoft Graph.",
    )
    client_id: str = Field(
        description="Azure AD application (client) identifier used to authenticate against "
        "Microsoft Graph.",
    )
    use_certificate_auth: bool = Field(
        default=False,
        description="Whether to authenticate using a client certificate instead of a client "
        "secret.",
    )
    client_secret: SecretStr | None = Field(
        default=None,
        description="Azure AD application client secret. Required unless "
        "use_certificate_auth is enabled.",
    )
    client_cert_data: SecretStr | None = Field(
        default=None,
        description="PEM encoded private key of the client certificate registered on the Entra ID application. Required when use_certificate_auth is enabled.",
    )
    client_cert_thumbprint: SecretStr | None = Field(
        default=None,
        description="SHA-1 thumbprint of the client certificate registered on the Entra ID application. Required when use_certificate_auth is enabled.",
    )
    client_cert_passphrase: SecretStr | None = Field(
        default=None,
        description="Passphrase protecting the client certificate private key. Only needed when the private key is encrypted.",
    )
    base_url: HttpUrl = Field(
        default=HttpUrl("https://graph.microsoft.com/v1.0"),
        description="Base URL for the Microsoft Graph API.",
    )
    filter_service_source: str = Field(
        default="microsoftDefenderForOffice365",
        description="Value used to filter Microsoft Graph security alerts down to those "
        "produced by Microsoft Defender for Office 365.",
    )
    rate_limit_requests_per_minute: int = Field(
        default=150,
        ge=1,
        description="Maximum number of Microsoft Graph API requests issued per minute.",
    )
    max_fetch_retries: int = Field(
        default=5,
        ge=0,
        description="Maximum number of retries when fetching data from Microsoft Graph "
        "fails transiently.",
    )

    @field_validator("client_cert_data", mode="before")
    @classmethod
    def _normalize_client_cert_data(cls, value: object) -> object:
        """Unescape PEM material coming from environment variables."""

        def normalize(raw: str | None) -> str | None:
            if raw is None:
                return None
            cleaned = raw.strip()
            if not cleaned:
                return None
            return cleaned.replace("\\n", "\n")

        if isinstance(value, SecretStr):
            normalized = normalize(value.get_secret_value())
            return None if normalized is None else SecretStr(normalized)
        if isinstance(value, str):
            return normalize(value)
        return value

    @field_validator("client_cert_thumbprint", mode="before")
    @classmethod
    def _normalize_client_cert_thumbprint(cls, value: object) -> object:
        """Strip separators from the thumbprint and validate its shape."""

        def normalize(raw: str | None) -> str | None:
            if raw is None:
                return None
            cleaned = raw.replace(":", "").replace(" ", "").strip().upper()
            return cleaned or None

        if isinstance(value, SecretStr):
            normalized = normalize(value.get_secret_value())
            return None if normalized is None else SecretStr(normalized)
        if isinstance(value, str):
            return normalize(value)
        return value

    @field_validator("client_secret")
    @classmethod
    def _validate_client_secret(
        cls, value: SecretStr | None, info: ValidationInfo
    ) -> SecretStr | None:
        """Require client_secret when certificate auth mode is not enabled.

        Args:
            value: The provided client_secret value, if any.
            info: Pydantic validation info, exposing already-validated field values.

        Returns:
            The validated value.

        Raises:
            ValueError: If certificate auth mode is disabled and no client secret was
                provided.

        """
        use_cert = bool(info.data.get("use_certificate_auth"))
        if use_cert:
            return value
        if value is None or not value.get_secret_value().strip():
            raise ValueError(
                "client_secret is required when use_certificate_auth is false"
            )
        return value

    @model_validator(mode="after")
    def _validate_certificate_requirements(self) -> "_ConfigLoaderSource":
        if not self.use_certificate_auth:
            return self

        if (
            not self.client_cert_data
            or not self.client_cert_data.get_secret_value().strip()
        ):
            raise ValueError(
                "client_cert_data is required when use_certificate_auth is true"
            )

        thumbprint = (
            self.client_cert_thumbprint.get_secret_value()
            if self.client_cert_thumbprint
            else ""
        )
        if not thumbprint:
            raise ValueError(
                "client_cert_thumbprint is required when use_certificate_auth is true"
            )
        if len(thumbprint) != 40 or any(
            ch not in "0123456789ABCDEF" for ch in thumbprint
        ):
            raise ValueError(
                "client_cert_thumbprint must be a 40-character hexadecimal SHA-1 thumbprint"
            )

        return self
