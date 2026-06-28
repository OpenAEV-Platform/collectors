from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_prompt_security", description="Collector unique identifier"
    )
    name: str = Field(default="Prompt Security", description="Collector display name")
    platform: str | None = Field(
        default="LLM_FIREWALL",
        description="Security platform type registered for this collector.",
    )
    icon_filepath: str | None = Field(
        default="prompt_security/img/icon-prompt-security.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(seconds=120),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    base_url: str | None = Field(
        default=None,
        description="Prompt Security tenant base URL (e.g. https://<tenant>.prompt.security).",
    )
    app_id: str | None = Field(
        default=None, description="Prompt Security application id / API key."
    )
    auth_header: str | None = Field(
        default="APP-ID",
        description="HTTP header used to carry the application id / API key.",
    )
