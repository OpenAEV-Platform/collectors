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
    platform_description: str | None = Field(
        default=(
            "Microsoft Defender for Endpoint, the Microsoft endpoint detection and "
            "response (EDR) platform. Automatically registered by the Microsoft "
            "Defender collector, which matches Defender alerts to validate "
            "prevention and detection expectations."
        ),
        description="Description applied to the security platform auto-created by the collector.",
    )
    platform_tags: list[str] | None = Field(
        default=["edr", "microsoft"],
        description="Tag names applied to the security platform auto-created by the collector.",
    )
    icon_filepath: str | None = Field(
        default="microsoft_defender/img/icon-microsoft-defender.png",
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
