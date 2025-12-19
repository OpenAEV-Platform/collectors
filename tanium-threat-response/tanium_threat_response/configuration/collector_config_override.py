from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class CollectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        default="openaev_tanium_threat_response",
        description="Collector unique identifier",
    )
    name: str = Field(
        default="Tanium Threat Response",
        description="Collector display name",
    )
    icon_filepath: str | None = Field(
        default="tanium_threat_response/img/icon-tanium.png",
        description="Path to the icon file",
    )
    tanium_url: str = Field(
        description="URL of your Tanium instance.",
    )
    tanium_url_console: str = Field(
        description="URL of your Tanium console instance.",
    )
    tanium_token: str = Field(
        description="API Token.",
    )
    tanium_ssl_verify: str = Field(
        description="Verify the Tanium server TLS certificate",
    )
