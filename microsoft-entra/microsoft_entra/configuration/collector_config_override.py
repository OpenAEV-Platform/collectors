from datetime import timedelta

from pydantic import Field, SecretStr
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
    microsoft_entra_client_secret: SecretStr = Field(
        description="Azure AD application client secret for Microsoft Entra.",
    )
    include_external: bool = Field(
        default=False,
        description="Include user with #EXT# in principal name.",
    )
