"""Configuration for PaloAltoCortexXSOAR integration."""

from datetime import timedelta
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from src.models.settings import ConfigBaseSettings


class ConfigLoaderPaloAltoCortexXSOAR(ConfigBaseSettings):
    """PaloAltoCortexXSOAR API configuration settings.

    Contains connection details, timing parameters, and retry settings
    for PaloAltoCortexXSOAR API integration.
    """

    api_url: str = Field(
        alias="PALO_ALTO_CORTEX_XSOAR_API_URL",
        description="The API URL is the base host associated with each tenant (without scheme).",
    )

    @field_validator("api_url")
    @classmethod
    def strip_scheme(cls, v: str) -> str:
        """Strip any URL scheme from the API URL to keep only the hostname."""
        for scheme in ("https://", "http://"):
            if v.startswith(scheme):
                v = v[len(scheme) :]
        return v.rstrip("/")

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
