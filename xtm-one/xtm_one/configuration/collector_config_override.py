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
    platform: str | None = Field(
        default="LLM_FIREWALL",
        description=(
            "Security platform type registered for this collector so XTM One appears in "
            "the OpenAEV inventory as a security platform (like any EDR/XDR collector) and "
            "detection/prevention expectation results are attributed to it. XTM One acts as "
            "an AI defense that flags prompt injections, hence LLM_FIREWALL by default. "
            "Accepted values: EDR, XDR, SIEM, SOAR, NDR, ISPM, LLM_FIREWALL, AI_GATEWAY."
        ),
    )
    period: timedelta | None = Field(
        default=timedelta(minutes=5),
        description=(
            "Duration between two scheduled runs of the collector (ISO 8601 format). "
            "Expectation validation runs on every cycle, so this is effectively the "
            "expectation-matching cadence; the agent import is additionally throttled "
            "by import_period."
        ),
    )
    import_period: timedelta | None = Field(
        default=timedelta(hours=1),
        description=(
            "Minimum duration between two imports of the XTM One agents/models "
            "catalog (ISO 8601 format). The import runs on the first cycle and then "
            "only when this much time has elapsed since the previous import; set it "
            "lower than or equal to the collector period to import on every cycle."
        ),
    )
    xtm_one_url: str | None = Field(
        default=None,
        description="Base URL of the XTM One platform (e.g. https://xtm-one.example.com).",
    )
    xtm_one_token: str | None = Field(
        default=None,
        description=(
            "XTM One API key (fcp-...) used to read the agents and models catalog and "
            "the security audit log, and written onto each seeded AI target so the "
            "injector can authenticate to XTM One directly. Reading the audit log to "
            "validate detection expectations requires this key to belong to an XTM One "
            "administrator."
        ),
    )
    validate_expectations: bool = Field(
        default=True,
        description=(
            "When true, the collector also validates AI detection/prevention "
            "expectations by matching XTM One 'Prompt injection detected' security "
            "events to the AI red team injects that triggered them. Requires the XTM "
            "One token to have administrator access to the audit log."
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
