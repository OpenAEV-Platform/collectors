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
    icon_filepath: str | None = Field(
        default="microsoft-defender/img/icon-microsoft-defender.png",
        description="Path to the icon file",
    )
    microsoft_defender_tenant_id: str = Field(
        description="Azure Active Directory tenant ID for Microsoft Defender.",
    )
    microsoft_defender_client_id: str = Field(
        description="Azure AD application (client) ID for Microsoft Defender.",
    )
    microsoft_defender_client_secret: SecretStr = Field(
        description="Azure AD application client secret for Microsoft Defender.",
    )
