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
