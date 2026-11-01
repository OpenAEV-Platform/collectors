from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):

    icon_filepath: str | None = Field(
        default="crowdstrike/img/icon-crowdstrike.png",
        description="Path to the icon file",
    )
    platform: str | None = Field(
        default="EDR",
        description="Platform type for the collector (e.g., EDR, SIEM, etc.).",
    )
    platform_description: str | None = Field(
        default=(
            "CrowdStrike Falcon, the CrowdStrike endpoint detection and response "
            "(EDR) platform. Automatically registered by the CrowdStrike collector, "
            "which matches Falcon alerts to validate prevention and detection "
            "expectations."
        ),
        description="Description applied to the security platform auto-created by the collector.",
    )
    platform_tags: list[str] | None = Field(
        default=["edr", "crowdstrike"],
        description="Tag names applied to the security platform auto-created by the collector.",
    )
