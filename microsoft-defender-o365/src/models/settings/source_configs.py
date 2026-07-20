"""Configuration for Microsoft Defender for Office 365 business integration."""

from pydantic import Field, HttpUrl, SecretStr, ValidationInfo, field_validator
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
    client_cert_path: str | None = Field(
        default=None,
        description="Filesystem path to the client certificate. Required when "
        "use_certificate_auth is enabled.",
    )
    client_cert_thumbprint: str | None = Field(
        default=None,
        description="Thumbprint of the client certificate. Required when "
        "use_certificate_auth is enabled.",
    )
    base_url: HttpUrl = Field(
        default="https://graph.microsoft.com/v1.0",
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

    @field_validator("client_cert_path")
    @classmethod
    def _validate_client_cert_path(
        cls, value: str | None, info: ValidationInfo
    ) -> str | None:
        """Require client_cert_path when certificate auth mode is enabled.

        Args:
            value: The provided client_cert_path value, if any.
            info: Pydantic validation info, exposing already-validated field values.

        Returns:
            The validated value.

        Raises:
            ValueError: If certificate auth mode is enabled and no path was provided.

        """
        if info.data.get("use_certificate_auth") and not value:
            raise ValueError(
                "client_cert_path is required when use_certificate_auth is enabled"
            )
        return value

    @field_validator("client_cert_thumbprint")
    @classmethod
    def _validate_client_cert_thumbprint(
        cls, value: str | None, info: ValidationInfo
    ) -> str | None:
        """Require client_cert_thumbprint when certificate auth mode is enabled.

        Args:
            value: The provided client_cert_thumbprint value, if any.
            info: Pydantic validation info, exposing already-validated field values.

        Returns:
            The validated value.

        Raises:
            ValueError: If certificate auth mode is enabled and no thumbprint was provided.

        """
        if info.data.get("use_certificate_auth") and not value:
            raise ValueError(
                "client_cert_thumbprint is required when use_certificate_auth is enabled"
            )
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
        if not info.data.get("use_certificate_auth") and not value:
            raise ValueError(
                "client_secret is required when use_certificate_auth is disabled"
            )
        return value
