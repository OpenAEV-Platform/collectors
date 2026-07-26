from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_lakera_guard", description="Collector unique identifier"
    )
    name: str = Field(default="Lakera Guard", description="Collector display name")
    platform: str | None = Field(
        default="LLM_FIREWALL",
        description="Security platform type registered for this collector.",
    )
    platform_description: str | None = Field(
        default=(
            "Lakera Guard, the AI security platform screening LLM prompts for "
            "injections and unsafe content. Automatically registered by the Lakera "
            "Guard collector, which matches screening results to validate AI "
            "prevention and detection expectations."
        ),
        description="Description applied to the security platform auto-created by the collector.",
    )
    platform_tags: list[str] | None = Field(
        default=["llm-firewall", "lakera"],
        description="Tag names applied to the security platform auto-created by the collector.",
    )
    icon_filepath: str | None = Field(
        default="lakera_guard/img/icon-lakera-guard.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(seconds=120),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    base_url: str | None = Field(
        default="https://api.lakera.ai/v2",
        description="Lakera Guard API base URL.",
    )
    api_key: str | None = Field(default=None, description="Lakera Guard API key.")
    project_id: str | None = Field(
        default=None,
        description="Optional Lakera project id selecting the policy to apply.",
    )
    blocking_policy: bool = Field(
        default=True,
        description=(
            "Whether the targeted Lakera policy blocks flagged prompts. When true a "
            "flagged prompt counts as PREVENTION; set false for detect/monitor-only policies."
        ),
    )
