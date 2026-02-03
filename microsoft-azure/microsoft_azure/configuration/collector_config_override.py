from datetime import timedelta

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
    period: timedelta | None = Field(
        default=timedelta(minutes=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    microsoft_azure_tenant_id: str = Field(
        alias="MICROSOFT_AZURE_TENANT_ID",
        description="Azure Active Directory tenant ID for Microsoft Sentinel.",
    )
    microsoft_azure_client_id: str = Field(
        alias="MICROSOFT_AZURE_CLIENT_ID",
        description="Azure AD application (client) ID for Microsoft Sentinel.",
    )
    microsoft_azure_client_secret: SecretStr = Field(
        alias="MICROSOFT_AZURE_CLIENT_SECRET",
        description="Azure AD application client secret for Microsoft Sentinel.",
    )
    microsoft_azure_subscription_id: str = Field(
        alias="MICROSOFT_AZURE_SUBSCRIPTION_ID",
        description="Azure subscription ID containing the Sentinel workspace.",
    )
    microsoft_azure_resource_groups: str = Field(
        alias="MICROSOFT_AZURE_RESOURCE_GROUPS",
        description="Azure resource group containing the Sentinel workspace.",
    )
