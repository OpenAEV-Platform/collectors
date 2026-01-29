from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_microsoft_sentinel",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Microsoft Sentinel Collector",
        description="Collector display name",
    )
    platform: str | None = Field(
        default="SIEM",
        description="Platform type for the collector (e.g., EDR, SIEM, etc.).",
    )
    icon_filepath: str | None = Field(
        default="microsoft_sentinel/img/icon-microsoft-sentinel.png",
        description="Path to the icon file",
    )
    microsoft_sentinel_tenant_id: str = Field(
        description="Azure Active Directory tenant ID for Microsoft Sentinel.",
    )
    microsoft_sentinel_client_id: str = Field(
        description="Azure AD application (client) ID for Microsoft Sentinel.",
    )
    microsoft_sentinel_client_secret: SecretStr = Field(
        description="Azure AD application client secret for Microsoft Sentinel.",
    )
    microsoft_sentinel_subscription_id: str = Field(
        description="Azure subscription ID containing the Sentinel workspace.",
    )
    microsoft_sentinel_workspace_id: str = Field(
        description="Log Analytics workspace ID used by Microsoft Sentinel.",
    )
    microsoft_sentinel_resource_group: str = Field(
        description="Azure resource group containing the Sentinel workspace.",
    )
    microsoft_sentinel_edr_collectors: str = Field(
        description=(
            "Comma-separated list of EDR collectors enabled for "
            "Microsoft Sentinel (e.g. defender, crowdstrike)."
        ),
    )
