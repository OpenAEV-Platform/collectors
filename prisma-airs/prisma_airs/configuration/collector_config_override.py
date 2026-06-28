from datetime import timedelta

from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_prisma_airs", description="Collector unique identifier"
    )
    name: str = Field(
        default="Palo Alto Prisma AIRS", description="Collector display name"
    )
    platform: str | None = Field(
        default="LLM_FIREWALL",
        description="Security platform type registered for this collector.",
    )
    icon_filepath: str | None = Field(
        default="prisma_airs/img/icon-prisma-airs.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(seconds=120),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    base_url: str | None = Field(
        default="https://service.api.aisecurity.paloaltonetworks.com",
        description="Prisma AIRS region-specific Scan API base URL.",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description="Prisma AIRS API key (sent as the x-pan-token header).",
    )
    ai_profile: str | None = Field(
        default=None, description="Prisma AIRS AI security profile name to apply."
    )
