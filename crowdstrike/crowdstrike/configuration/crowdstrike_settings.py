from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class CrowdstrikeSettings(BaseSettings):
    """CrowdStrike API configuration settings."""

    model_config = {"frozen": False}

    client_id: str = Field(
        description="The CrowdStrike API client ID.",
    )
    client_secret: SecretStr = Field(
        description="The CrowdStrike API client secret.",
    )
    api_base_url: str = Field(
        description="The base URL for the CrowdStrike APIs. ",
    )
    ui_base_url: str = Field(
        default="https://falcon.us-2.crowdstrike.com",
        description="The base URL for the CrowdStrike UI you use to see your alerts.",
    )
