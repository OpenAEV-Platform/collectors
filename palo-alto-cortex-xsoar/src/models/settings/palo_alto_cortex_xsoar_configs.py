"""Configuration for PaloAltoCortexXSOAR integration."""

from datetime import timedelta
from typing import Literal

from pydantic import Field, HttpUrl, SecretStr
from src.models.settings import ConfigBaseSettings


class ConfigLoaderPaloAltoCortexXSOAR(ConfigBaseSettings):
    """PaloAltoCortexXSOAR API configuration settings.

    Contains connection details, timing parameters, and retry settings
    for PaloAltoCortexXSOAR API integration.
    """

    api_url: HttpUrl = Field(
        alias="PALO_ALTO_CORTEX_XSOAR_API_URL",
        description="The API URL is the base URL associated with each tenant.",
    )

    api_key: SecretStr = Field(
        alias="PALO_ALTO_CORTEX_XSOAR_API_KEY",
        description="The API Key for XSOAR authentication.",
    )

    api_key_id: int = Field(
        alias="PALO_ALTO_CORTEX_XSOAR_API_KEY_ID",
        description="The API Key ID for XSOAR authentication.",
    )

    api_key_type: Literal["standard", "advanced"] = Field(
        alias="PALO_ALTO_CORTEX_XSOAR_API_KEY_TYPE",
        default="standard",
        description="The API Key type for XSOAR authentication.",
    )

    time_window: timedelta = Field(
        alias="PALO_ALTO_CORTEX_XSOAR_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for PaloAltoCortexXSOAR alert searches when no date signatures are provided (ISO 8601 format).",
    )
