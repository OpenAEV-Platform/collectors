from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_mitre_attack",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="MITRE ATT&CK",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="mitre_attack/img/icon-mitre-attack.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(days=7),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
