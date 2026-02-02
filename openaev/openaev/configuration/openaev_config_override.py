from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV


class OpenaevConfigOverride(ConfigLoaderOAEV):
    url_prefix: str = Field(
        default="https://raw.githubusercontent.com/OpenAEV-Platform/payloads/refs/heads/main/",
        description="URL prefix to look for the content.",
    )
    import_only_native: bool = Field(
        default=False,
        description="Only import native datasets.",
    )
