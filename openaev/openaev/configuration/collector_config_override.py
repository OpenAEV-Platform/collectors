from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):

    icon_filepath: str | None = Field(
        default="openaev/img/icon-openaev.png",
        description="Path to the icon file",
    )
