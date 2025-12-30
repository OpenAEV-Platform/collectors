from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV


class OpenaevConfigOverride(ConfigLoaderOAEV):
    url: str = Field(
        description="Openaev url",
    )
    token: str = Field(
        description="Openaev token",
    )
