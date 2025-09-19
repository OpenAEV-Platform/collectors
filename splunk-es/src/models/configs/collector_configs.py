"""Base class for global config models."""

from datetime import timedelta
from typing import Annotated, Literal

from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
)
from src.models.configs import ConfigBaseSettings

LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "error"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
]


class _ConfigLoaderOAEV(ConfigBaseSettings):
    """OpenBAS/OpenAEV platform configuration settings.

    Contains URL and authentication token for connecting to the OpenBAS platform.
    """

    url: HttpUrlToString = Field(
        alias="OPENBAS_URL",
        description="The OpenAEV platform URL.",
    )
    token: str = Field(
        alias="OPENBAS_TOKEN",
        description="The token for the OpenAEV platform.",
    )


class _ConfigLoaderCollector(ConfigBaseSettings):
    """Base collector configuration settings.

    Contains common collector settings including identification, logging,
    scheduling, and platform information.
    """

    id: str
    name: str

    platform: str | None = Field(
        alias="COLLECTOR_PLATFORM",
        default="SIEM",
        description="Platform type for the collector (e.g., EDR, SIEM, etc.).",
    )
    log_level: LogLevelToLower | None = Field(
        alias="COLLECTOR_LOG_LEVEL",
        default="error",
        description="Determines the verbosity of the logs.",
    )
    period: timedelta | None = Field(
        alias="COLLECTOR_PERIOD",
        default=timedelta(minutes=1),
        description="Duration between two scheduled runs of the collector (ISO 8601 format).",
    )
    icon_filepath: str | None = Field(
        alias="COLLECTOR_ICON_FILEPATH",
        default="src/img/splunk-logo.png",
        description="Path to the icon file of the collector.",
    )
