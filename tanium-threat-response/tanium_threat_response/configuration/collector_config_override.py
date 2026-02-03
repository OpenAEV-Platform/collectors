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
    platform: str | None = Field(
        default="EDR",
        description="Platform type for the collector (e.g., EDR, SIEM, etc.).",
    )
    icon_filepath: str | None = Field(
        default="tanium_threat_response/img/icon-tanium.png",
        description="Path to the icon file",
    )
    tanium_url: str = Field(
        alias="TANIUM_URL",
        description="URL of your Tanium instance.",
    )
    tanium_url_console: str = Field(
        alias="TANIUM_URL_CONSOLE",
        description="URL of your Tanium console instance.",
    )
    tanium_token: str = Field(
        alias="TANIUM_TOKEN",
        description="API Token.",
    )
    tanium_ssl_verify: str = Field(
        alias="TANIUM_SSL_VERIFY",
        description="Verify the Tanium server TLS certificate",
    )
