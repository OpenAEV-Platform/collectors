import re
from datetime import timedelta

from pydantic import Field, SecretStr, ValidationInfo, field_validator
from pyoaev.configuration import ConfigLoaderCollector

SHA1_THUMBPRINT_LENGTH = 40


def normalize_pem(value: str | None) -> str | None:
    """Normalize a PEM blob supplied through an environment variable or a config file.

    Environment variables cannot carry real newlines, so PEM material is usually
    provided with literal ``\\n`` escape sequences. A PEM document only contains
    base64 characters, dashes and newlines, so a backslash can never be part of the
    payload: unescaping is therefore unambiguous and safe.

    Args:
        value: The raw PEM text, if any.

    Returns:
        The normalized PEM text, or None when nothing usable was provided.

    """
    if value is None:
        return None
    text = value.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    text = text.strip()
    if not text:
        return None
    return f"{text}\n"


def normalize_thumbprint(value: str | None) -> str | None:
    """Normalize a certificate thumbprint into the bare hexadecimal form MSAL expects.

    Tooling renders thumbprints inconsistently: the Azure portal shows a bare
    hexadecimal string, ``openssl x509 -fingerprint`` uses colons, and the Windows
    certificate manager inserts spaces. MSAL feeds the value straight into
    ``binascii.a2b_hex``, which only accepts bare hexadecimal, so separators are
    stripped here to avoid an opaque failure at token acquisition time.

    Args:
        value: The raw thumbprint, if any.

    Returns:
        The normalized lowercase hexadecimal thumbprint, or None when not provided.

    Raises:
        ValueError: If the thumbprint is not a 40 character SHA-1 hexadecimal string.

    """
    if value is None:
        return None
    cleaned = re.sub(r"[\s:\-]", "", value).strip().lower()
    if not cleaned:
        return None
    if not re.fullmatch(r"[0-9a-f]+", cleaned):
        raise ValueError(
            "microsoft_azure_client_cert_thumbprint must be a hexadecimal SHA-1 "
            "certificate thumbprint"
        )
    if len(cleaned) != SHA1_THUMBPRINT_LENGTH:
        raise ValueError(
            "microsoft_azure_client_cert_thumbprint must be a 40 character SHA-1 "
            "thumbprint; MSAL certificate credentials in PEM form do not support "
            "SHA-256 thumbprints"
        )
    return cleaned


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_microsoft_azure",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Microsoft Azure",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="microsoft_azure/img/icon-microsoft-azure.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(minutes=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    microsoft_azure_tenant_id: str = Field(
        description="Azure Active Directory tenant ID for Microsoft Sentinel.",
    )
    microsoft_azure_client_id: str = Field(
        description="Azure AD application (client) ID for Microsoft Sentinel.",
    )

    # Declared before the credential fields so that their validators can read it
    # through ValidationInfo.data.
    microsoft_azure_use_certificate_auth: bool = Field(
        default=False,
        description="Whether to authenticate using a client certificate instead of a "
        "client secret.",
    )

    microsoft_azure_client_secret: SecretStr | None = Field(
        default=None,
        description="Azure AD application client secret for Microsoft Azure. "
        "Required unless microsoft_azure_use_certificate_auth is enabled.",
    )

    microsoft_azure_client_cert_data: SecretStr | None = Field(
        default=None,
        description="PEM encoded private key of the client certificate registered on "
        "the Entra ID application. Required when "
        "microsoft_azure_use_certificate_auth is enabled.",
    )
    microsoft_azure_client_cert_thumbprint: SecretStr | None = Field(
        default=None,
        description="SHA-1 thumbprint of the client certificate registered on the "
        "Entra ID application. Required when "
        "microsoft_azure_use_certificate_auth is enabled.",
    )
    microsoft_azure_client_cert_passphrase: SecretStr | None = Field(
        default=None,
        description="Passphrase protecting the client certificate private key. Only "
        "needed when the private key is encrypted.",
    )

    microsoft_azure_subscription_id: str = Field(
        description="Azure subscription ID containing the virtual machines to collect.",
    )
    microsoft_azure_resource_groups: str = Field(
        description="Comma-separated Azure resource groups containing the virtual machines to collect.",
    )

    @field_validator("microsoft_azure_client_cert_data", mode="before")
    @classmethod
    def _normalize_client_cert_data(cls, value: object) -> object:
        """Unescape PEM material coming from environment variables."""
        if isinstance(value, SecretStr):
            normalized = normalize_pem(value.get_secret_value())
            return None if normalized is None else SecretStr(normalized)
        if isinstance(value, str):
            return normalize_pem(value)
        return value

    @field_validator("microsoft_azure_client_cert_thumbprint", mode="before")
    @classmethod
    def _normalize_client_cert_thumbprint(cls, value: object) -> object:
        """Strip separators from the thumbprint and validate its shape."""
        if isinstance(value, SecretStr):
            normalized = normalize_thumbprint(value.get_secret_value())
            return None if normalized is None else SecretStr(normalized)
        if isinstance(value, str):
            return normalize_thumbprint(value)
        return value

    @field_validator("microsoft_azure_client_secret")
    @classmethod
    def _validate_client_secret(
        cls, value: SecretStr | None, info: ValidationInfo
    ) -> SecretStr | None:
        """Require a client secret unless certificate authentication is enabled.

        This preserves the historical behaviour for every deployment that does not
        opt into certificate authentication: the client secret stays mandatory.

        Args:
            value: The provided client secret, if any.
            info: Pydantic validation info, exposing already-validated field values.

        Returns:
            The validated value.

        Raises:
            ValueError: If certificate auth is disabled and no client secret was given.

        """
        if not info.data.get("microsoft_azure_use_certificate_auth") and not value:
            raise ValueError(
                "microsoft_azure_client_secret is required when "
                "microsoft_azure_use_certificate_auth is disabled"
            )
        return value

    @field_validator("microsoft_azure_client_cert_data")
    @classmethod
    def _validate_client_cert_data(
        cls, value: SecretStr | None, info: ValidationInfo
    ) -> SecretStr | None:
        """Require the certificate private key when certificate auth is enabled.

        Args:
            value: The provided PEM private key, if any.
            info: Pydantic validation info, exposing already-validated field values.

        Returns:
            The validated value.

        Raises:
            ValueError: If certificate auth is enabled and no private key was given.

        """
        if info.data.get("microsoft_azure_use_certificate_auth") and not value:
            raise ValueError(
                "microsoft_azure_client_cert_data is required when "
                "microsoft_azure_use_certificate_auth is enabled"
            )
        return value

    @field_validator("microsoft_azure_client_cert_thumbprint")
    @classmethod
    def _validate_client_cert_thumbprint(
        cls, value: SecretStr | None, info: ValidationInfo
    ) -> SecretStr | None:
        """Require the certificate thumbprint when certificate auth is enabled.

        Args:
            value: The provided thumbprint, if any.
            info: Pydantic validation info, exposing already-validated field values.

        Returns:
            The validated value.

        Raises:
            ValueError: If certificate auth is enabled and no thumbprint was given.

        """
        if info.data.get("microsoft_azure_use_certificate_auth") and not value:
            raise ValueError(
                "microsoft_azure_client_cert_thumbprint is required when "
                "microsoft_azure_use_certificate_auth is enabled"
            )
        return value
