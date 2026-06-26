from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_ai_guardrail",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="AI Guardrail",
        description="Collector display name",
    )
    platform: str | None = Field(
        default="LLM_FIREWALL",
        description="Security platform type registered for this collector (LLM_FIREWALL or AI_GATEWAY).",
    )
    icon_filepath: str | None = Field(
        default="ai_guardrail/img/icon-ai-guardrail.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(seconds=60),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    # Guardrail backend configuration
    provider: str = Field(
        default="generic",
        description="AI defense provider: 'generic', 'lakera' or 'nemo'.",
    )
    events_url: str | None = Field(
        default=None,
        description=(
            "URL of the guardrail/firewall events API queryable by the per-inject marker. The AI "
            "gateway/firewall in front of the model must log each request's X-OAEV-Inject-Marker so "
            "decisions can be retrieved here."
        ),
    )
    api_key: str | None = Field(
        default=None,
        description="API key / token for the guardrail events API (sent as a bearer token).",
    )
    lookback_minutes: int = Field(
        default=60,
        description="How far back to query guardrail events for a marker.",
    )
    marker_param: str = Field(
        default="marker",
        description="Query parameter name used to filter guardrail events by the inject marker.",
    )
    flagged_field: str = Field(
        default="flagged",
        description="Boolean field in a guardrail event meaning the attack was detected/flagged.",
    )
    blocked_field: str = Field(
        default="blocked",
        description="Boolean field in a guardrail event meaning the attack was blocked/prevented.",
    )
