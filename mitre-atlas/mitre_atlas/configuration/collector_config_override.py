from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_mitre_atlas",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="MITRE ATLAS",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="mitre_atlas/img/icon-mitre-atlas.png",
        description="Path to the icon file",
    )
    period: timedelta | None = Field(
        default=timedelta(days=7),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    stix_url: str | None = Field(
        default=None,
        description=(
            "Override URL of the MITRE ATLAS STIX bundle to ingest. Defaults to the official "
            "mitre-atlas/atlas-navigator-data STIX export when unset."
        ),
    )
