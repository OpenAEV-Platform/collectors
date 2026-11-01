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
    platform_description: str | None = Field(
        default=(
            "Palo Alto Networks Prisma AIRS, the AI runtime security platform "
            "scanning LLM prompts and responses for threats. Automatically "
            "registered by the Prisma AIRS collector, which matches scan verdicts "
            "to validate AI prevention and detection expectations."
        ),
        description="Description applied to the security platform auto-created by the collector.",
    )
    platform_tags: list[str] | None = Field(
        default=["llm-firewall", "palo-alto"],
        description="Tag names applied to the security platform auto-created by the collector.",
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
