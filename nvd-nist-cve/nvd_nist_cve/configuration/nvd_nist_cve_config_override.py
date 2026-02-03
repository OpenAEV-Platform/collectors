from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class NvdNistCveConfigOverride(BaseSettings):
    """Nvd Nist CVE API configuration settings."""

    model_config = {"frozen": False}

    api_key: SecretStr = Field(
        alias="NVD_NIST_CVE_API_BASE_URL",
        default=SecretStr(""),
        description="The NVD API key.",
    )
    api_base_url: str = Field(
        alias="NVD_NIST_CVE_API_KEY",
        description="The base URL for the NVD APIs. ",
        default="https://services.nvd.nist.gov/rest/json",
    )
    start_year: str = Field(
        alias="NVD_NIST_CVE_START_YEAR",
        description="The earliest year from which to start fetching CVEs.",
        default="2019",
    )
