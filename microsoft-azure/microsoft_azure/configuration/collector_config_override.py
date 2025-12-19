from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderCollector


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
    microsoft_azure_tenant_id: str = Field(
        description="Azure Active Directory tenant ID for Microsoft Sentinel.",
    )
    microsoft_azure_client_id: str = Field(
        description="Azure AD application (client) ID for Microsoft Sentinel.",
    )

    microsoft_azure_client_secret: SecretStr = Field(
        description="Azure AD application client secret for Microsoft Sentinel.",
    )

    microsoft_azure_subscription_id: str = Field(
        description="Azure subscription ID containing the Sentinel workspace.",
    )
    microsoft_azure_resource_groups: str = Field(
        description="Azure resource group containing the Sentinel workspace.",
    )
