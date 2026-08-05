"""Base class for global config models."""

from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, HttpUrl, PlainSerializer, field_validator
from src.models.settings import ConfigBaseSettings

LogLevel = Literal["debug", "info", "warning", "error", "critical"]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
]


class _ConfigLoaderOAEV(ConfigBaseSettings):
    """OpenAEV/OpenAEV platform configuration settings.

    Contains URL and authentication token for connecting to the OpenAEV platform.
    """

    url: HttpUrlToString = Field(
        description="The OpenAEV platform URL.",
    )
    token: str = Field(
        description="The token for the OpenAEV platform.",
    )
    tenant_id: UUID | None = Field(
        default=None,
        description="Identifier of the tenant within the OpenAEV platform. Used in multi-tenant environments to scope "
        "API requests and ensure data isolation between different tenants.",
    )


class _ConfigLoaderCollector(ConfigBaseSettings):
    """Base collector configuration settings.

    Contains common collector settings including identification, logging,
    scheduling, and platform information.
    """

    id: str
    name: str

    platform: str | None = Field(
        default="EDR",
        description="Platform type for the collector (e.g., EDR, SIEM, etc.).",
    )
    log_level: LogLevel | None = Field(
        default="error",
        description="Determines the verbosity of the logs.",
    )
    period: timedelta | None = Field(
        default=timedelta(minutes=2),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    icon_filepath: str | None = Field(
        default="src/img/microsoft-defender-o365-logo.png",
        description="Path to the icon file of the collector.",
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def to_lower(cls, value: str) -> str:
        try:
            return value.lower()
        except AttributeError:
            return value
