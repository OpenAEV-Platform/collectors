from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_microsoft_defender",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Microsoft Defender",
        description="Collector display name",
    )
    platform: str | None = Field(
        default="EDR",
        description="Platform type for the collector (e.g., EDR, SIEM, etc.).",
    )
    icon_filepath: str | None = Field(
        default="microsoft_defender/img/icon-microsoft-defender.png",
        description="Path to the icon file",
    )
    microsoft_defender_tenant_id: str = Field(
        alias="MICROSOFT_DEFENDER_TENANT_ID",
        description="Azure Active Directory tenant ID for Microsoft Defender.",
    )
    microsoft_defender_client_id: str = Field(
        alias="MICROSOFT_DEFENDER_CLIENT_ID",
        description="Azure AD application (client) ID for Microsoft Defender.",
    )
    microsoft_defender_client_secret: SecretStr = Field(
        alias="MICROSOFT_DEFENDER_CLIENT_SECRET",
        description="Azure AD application client secret for Microsoft Defender.",
    )
