"""Configuration for PaloAltoCortexXDR integration."""

from datetime import timedelta
from typing import Literal

from pydantic import Field, SecretStr
from src.models.authentication import AuthenticationType
from src.models.settings import ConfigBaseSettings


class _ConfigLoaderPaloAltoCortexXDR(ConfigBaseSettings):
    """PaloAltoCortexXDR API configuration settings.

    Contains connection details, timing parameters, and retry settings
    for PaloAltoCortexXDR API integration.
    """

    fqdn: str = Field(
        alias="PALO_ALTO_CORTEX_XDR_FQDN",
        description="The FQDN is a unique host and domain name associated with each tenant.",
    )
    api_key: SecretStr = Field(
        alias="PALO_ALTO_CORTEX_XDR_API_KEY",
        description="The API Key is your unique identifier used as the Authorization:{key} header required for authenticating API calls.",
    )
    api_key_id: int = Field(
        alias="PALO_ALTO_CORTEX_XDR_API_KEY_ID",
        description="The API Key ID is your unique token used to authenticate the API Key.",
    )
    api_key_type: Literal[AuthenticationType.STANDARD, AuthenticationType.ADVANCED] = (
        Field(
            alias="PALO_ALTO_CORTEX_XDR_API_KEY_TYPE",
            default="standard",
            description="The type of API Key, either 'standard' or 'advanced'.",
        )
    )
    time_window: timedelta = Field(
        alias="PALO_ALTO_CORTEX_XDR_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for PaloAltoCortexXDR alert searches when no date signatures are provided (ISO 8601 format).",
    )
