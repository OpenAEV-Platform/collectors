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
