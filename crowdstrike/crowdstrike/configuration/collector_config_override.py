from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector

class CollectorConfigOverride(ConfigLoaderCollector):

    icon_filepath: str | None = Field(
        default="crowdstrike/img/icon-crowdstrike.png",
        description="Path to the icon file",
    )
