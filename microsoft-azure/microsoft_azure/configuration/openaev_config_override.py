from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV


class OpenaevConfigOverride(ConfigLoaderOAEV):
    url: str = Field(
        default=" ",
        description="Openaev url",
    )
    token: str = Field(
        default=" ",
        description="Openaev token",
    )
