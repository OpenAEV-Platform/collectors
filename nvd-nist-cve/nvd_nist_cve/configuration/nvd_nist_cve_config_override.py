from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class NvdNistCveConfigOverride(BaseSettings):
    """Nvd Nist CVE API configuration settings."""

    model_config = {"frozen": False}

    api_key: SecretStr = Field(
        description="The nvd nst cve API key.",
        default="ab68bc7e-77be-4117-bbf7-683a2ba7c604",
    )
    api_base_url: str = Field(
        description="The base URL for the nvd nst cve APIs. ",
        default="https://services.nvd.nist.gov/rest/json",
    )
    start_year: str = Field(
        description="The nvd nst cve start year. ",
        default="2019",
    )
