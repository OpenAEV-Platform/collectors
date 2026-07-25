from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_tanium_threat_response",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Tanium Threat Response",
        description="Collector display name",
    )
    platform: str | None = Field(
        default="EDR",
        description="Platform type for the collector (e.g., EDR, SIEM, etc.).",
    )
    platform_description: str | None = Field(
        default=(
            "Tanium Threat Response, the Tanium endpoint detection and response "
            "(EDR) module. Automatically registered by the Tanium Threat Response "
            "collector, which matches Tanium alerts to validate prevention and "
            "detection expectations."
        ),
        description="Description applied to the security platform auto-created by the collector.",
    )
    platform_tags: list[str] | None = Field(
        default=["edr", "tanium"],
        description="Tag names applied to the security platform auto-created by the collector.",
    )
    icon_filepath: str | None = Field(
        default="tanium_threat_response/img/icon-tanium.png",
        description="Path to the icon file",
    )
    tanium_url: str = Field(
        description="URL of your Tanium instance.",
    )
    tanium_url_console: str = Field(
        description="URL of your Tanium console instance.",
    )
    tanium_token: SecretStr = Field(
        description="API Token.",
    )
    tanium_ssl_verify: str = Field(
        default="true",
        description="Verify the Tanium server TLS certificate",
    )
