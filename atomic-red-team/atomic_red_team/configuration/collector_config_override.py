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
    icon_filepath: str | None = Field(
        default="atomic_red_team/img/icon-atomic-red-team.png",
        description="Path to the icon file",
    )
