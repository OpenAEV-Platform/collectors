from datetime import timedelta

from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_microsoft_intune",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Microsoft Intune",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="microsoft_intune/img/icon-microsoft-intune.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    microsoft_intune_tenant_id: str = Field(
        alias="MICROSOFT_INTUNE_TENANT_ID",
        description="Azure Active Directory tenant ID for Microsoft Intune.",
    )
    microsoft_intune_client_id: str = Field(
        alias="MICROSOFT_INTUNE_CLIENT_ID",
        description="Azure AD application (client) ID for Microsoft Intune.",
    )
    microsoft_intune_client_secret: SecretStr = Field(
        alias="MICROSOFT_INTUNE_CLIENT_SECRET",
        description="Azure AD application client secret for Microsoft Intune.",
    )
    microsoft_intune_device_filter: str = Field(
        alias="MICROSOFT_INTUNE_DEVICE_FILTER",
        description="OData filter for device selection",
    )
    microsoft_intune_device_groups: str = Field(
        alias="MICROSOFT_INTUNE_DEVICE_GROUPS",
        description="Comma-separated list of device group names or IDs",
    )
