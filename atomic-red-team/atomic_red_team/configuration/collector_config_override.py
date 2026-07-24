from datetime import timedelta

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_atomic_red_team",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Atomic Red Team",
        description="Collector display name",
    )
    period: timedelta | None = Field(
        default=timedelta(days=7),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    icon_filepath: str | None = Field(
        default="atomic_red_team/img/icon-atomic-red-team.png",
        description="Path to the icon file",
    )
    author: str | None = Field(
        # Explicit author declaration (example of the override mechanism): the
        # value matches the collector's name here, which is also what the
        # platform would fall back to if the field were left unset.
        default="Atomic Red Team",
        description="Author attributed to this collector's payloads and contracts. "
        "When unset, the platform attributes them to the collector's name.",
    )
