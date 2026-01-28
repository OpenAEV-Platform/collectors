from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class NvdNistCveConfigOverride(BaseSettings):
    """Nvd Nist CVE API configuration settings."""

    model_config = {"frozen": False}

    api_key: SecretStr = Field(
        default=SecretStr(""),
        description="The NVD API key.",
    )
    api_base_url: str = Field(
        description="The base URL for the NVD APIs. ",
        default="https://services.nvd.nist.gov/rest/json",
    )
    start_year: str = Field(
        description="The earliest year from which to start fetching CVEs.",
        default="2019",
    )
