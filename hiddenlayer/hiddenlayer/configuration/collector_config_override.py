from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_hiddenlayer", description="Collector unique identifier"
    )
    name: str = Field(default="HiddenLayer AIDR", description="Collector display name")
    platform: str | None = Field(
        default="LLM_FIREWALL",
        description="Security platform type registered for this collector.",
    )
    platform_description: str | None = Field(
        default=(
            "HiddenLayer AIDR, the AI detection and response platform monitoring "
            "interactions with AI models. Automatically registered by the "
            "HiddenLayer collector, which matches AIDR detections to validate AI "
            "prevention and detection expectations."
        ),
        description="Description applied to the security platform auto-created by the collector.",
    )
    platform_tags: list[str] | None = Field(
        default=["llm-firewall", "hiddenlayer"],
        description="Tag names applied to the security platform auto-created by the collector.",
    )
    icon_filepath: str | None = Field(
        default="hiddenlayer/img/icon-hiddenlayer.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(seconds=120),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    base_url: str | None = Field(
        default="https://api.us.hiddenlayer.ai",
        description="HiddenLayer API base URL (SaaS region or self-hosted AIDR container).",
    )
    auth_url: str | None = Field(
        default="https://auth.hiddenlayer.ai/oauth2/token",
        description="OAuth2 token endpoint (SaaS).",
    )
    client_id: str | None = Field(
        default=None, description="HiddenLayer API client id (omit for self-hosted)."
    )
    client_secret: str | None = Field(
        default=None,
        description="HiddenLayer API client secret (omit for self-hosted).",
    )
