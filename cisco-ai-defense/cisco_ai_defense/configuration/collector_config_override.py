from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_cisco_ai_defense", description="Collector unique identifier"
    )
    name: str = Field(default="Cisco AI Defense", description="Collector display name")
    platform: str | None = Field(
        default="LLM_FIREWALL",
        description="Security platform type registered for this collector.",
    )
    icon_filepath: str | None = Field(
        default="cisco_ai_defense/img/icon-cisco-ai-defense.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(seconds=120),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    base_url: str | None = Field(
        default=None,
        description="Cisco AI Defense inspection API base URL (region/tenant specific).",
    )
    api_key: str | None = Field(default=None, description="Cisco AI Defense API key.")
    auth_header: str | None = Field(
        default="X-Cisco-AI-Defense-Api-Key",
        description="HTTP header used to carry the API key.",
    )
