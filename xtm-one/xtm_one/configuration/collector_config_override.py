from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_xtm_one", description="Collector unique identifier"
    )
    name: str = Field(default="XTM One", description="Collector display name")
    icon_filepath: str | None = Field(
        default="xtm_one/img/icon-xtm-one.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    xtm_one_url: str | None = Field(
        default=None,
        description="Base URL of the XTM One platform (e.g. https://xtm-one.example.com).",
    )
    xtm_one_token: str | None = Field(
        default=None,
        description="XTM One API key (fcp-...) used to read the agents and models catalog.",
    )
    xtm_one_api_key_variable: str | None = Field(
        default="XTM_ONE_API_KEY",
        description=(
            "Name of the injector environment variable holding the credential the AI "
            "red team injector uses to reach XTM One at execution time. The secret "
            "value itself is never stored on the AI target."
        ),
    )
    include_bare_models: bool = Field(
        default=False,
        description=(
            "When true, also create an AI target for each bare LLM model exposed by "
            "XTM One (in addition to the agents)."
        ),
    )
    agent_tags: str | None = Field(
        default=None,
        description=(
            "Comma-separated list of XTM One agent tags to scope on. Empty means all "
            "agents are collected."
        ),
    )
