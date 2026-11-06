from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):

    name: str = Field(default="OpenAEV Scenarios", description="Name of the collector.")

    icon_filepath: str | None = Field(
        default="scenarios/img/icon-scenarios.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(hours=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
