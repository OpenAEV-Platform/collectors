from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):

    icon_filepath: str | None = Field(
        default="openaev/img/icon-openaev.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(days=7),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    author: str | None = Field(
        default=None,
        description="Optional author override for this collector's payloads and "
        "contracts. When absent, the platform attributes them to the collector's name.",
    )
