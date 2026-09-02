from datetime import timedelta

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_microsoft_entra",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Microsoft Entra",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="microsoft_entra/img/icon-microsoft-entra.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    microsoft_entra_tenant_id: str = Field(
        description="Azure Active Directory tenant ID for Microsoft Entra.",
    )
    microsoft_entra_client_id: str = Field(
        description="Azure AD application (client) ID for Microsoft Entra.",
    )
    microsoft_entra_use_certificate_auth: bool = Field(
        default=False,
        description="Whether to authenticate using a client certificate instead of a client secret.",
    )
    microsoft_entra_client_secret: SecretStr | None = Field(
        default=None,
        description="Azure AD application client secret for Microsoft Entra. Required unless microsoft_entra_use_certificate_auth is enabled.",
    )
    microsoft_entra_client_cert_data: SecretStr | None = Field(
        default=None,
        description="PEM encoded private key of the client certificate registered on the Entra ID application. Required when microsoft_entra_use_certificate_auth is enabled.",
    )
    microsoft_entra_client_cert_thumbprint: SecretStr | None = Field(
        default=None,
        description="SHA-1 thumbprint of the client certificate registered on the Entra ID application. Required when microsoft_entra_use_certificate_auth is enabled.",
    )
    microsoft_entra_client_cert_passphrase: SecretStr | None = Field(
        default=None,
        description="Passphrase protecting the client certificate private key. Only needed when the private key is encrypted.",
    )
    include_external: bool = Field(
        default=False,
        description="Include user with #EXT# in principal name.",
    )

    @field_validator("microsoft_entra_client_cert_data", mode="before")
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

    @field_validator("microsoft_entra_client_cert_thumbprint", mode="before")
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

    @field_validator("microsoft_entra_client_secret")
    @classmethod
    def _validate_client_secret_requirement(
        cls, value: SecretStr | None, info: ValidationInfo
    ) -> SecretStr | None:
        use_cert = bool(info.data.get("microsoft_entra_use_certificate_auth"))
        if use_cert:
            return value
        if value is None or not value.get_secret_value().strip():
            raise ValueError(
                "microsoft_entra_client_secret is required when microsoft_entra_use_certificate_auth is false"
            )
        return value

    @model_validator(mode="after")
    def _validate_certificate_requirements(self) -> "CollectorConfigOverride":
        if not self.microsoft_entra_use_certificate_auth:
            return self

        if (
            not self.microsoft_entra_client_cert_data
            or not self.microsoft_entra_client_cert_data.get_secret_value().strip()
        ):
            raise ValueError(
                "microsoft_entra_client_cert_data is required when microsoft_entra_use_certificate_auth is true"
            )

        thumbprint = (
            self.microsoft_entra_client_cert_thumbprint.get_secret_value()
            if self.microsoft_entra_client_cert_thumbprint
            else ""
        )
        if not thumbprint:
            raise ValueError(
                "microsoft_entra_client_cert_thumbprint is required when microsoft_entra_use_certificate_auth is true"
            )
        if len(thumbprint) != 40 or any(
            ch not in "0123456789ABCDEF" for ch in thumbprint
        ):
            raise ValueError(
                "microsoft_entra_client_cert_thumbprint must be a 40-character hexadecimal SHA-1 thumbprint"
            )

        return self
