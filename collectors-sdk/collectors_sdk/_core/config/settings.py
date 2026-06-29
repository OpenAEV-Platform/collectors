"""Configuration base classes for collectors."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal

from pydantic import Field, HttpUrl, PlainSerializer
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = [
    "ConfigBaseSettings",
    "ConfigLoaderOAEV",
    "ConfigLoaderCollector",
    "ConfigLoaderCustom",
]

LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "error"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
]


class ConfigBaseSettings(BaseSettings):
    """Base class for all collector configuration models.

    Provides frozen immutability, env nesting, and string stripping.
    """

    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=1,
        frozen=True,
        str_strip_whitespace=True,
        str_min_length=1,
        extra="ignore",
        validate_by_name=True,
        validate_by_alias=True,
    )


class ConfigLoaderOAEV(ConfigBaseSettings):
    """OpenAEV platform connection settings."""

    url: HttpUrlToString = Field(
        alias="OPENAEV_URL",
        description="The OpenAEV platform URL.",
    )
    token: str = Field(
        alias="OPENAEV_TOKEN",
        description="The token for the OpenAEV platform.",
    )


class ConfigLoaderCollector(ConfigBaseSettings):
    """Base collector configuration settings."""

    id: str = Field(description="Unique identifier for this collector instance.")
    name: str = Field(description="Name of the collector.")
    platform: str | None = Field(
        alias="COLLECTOR_PLATFORM",
        default="EDR",
        description="Platform type (e.g., EDR, SIEM).",
    )
    log_level: LogLevelToLower | None = Field(
        alias="COLLECTOR_LOG_LEVEL",
        default="error",
        description="Log verbosity level.",
    )
    period: timedelta | None = Field(
        alias="COLLECTOR_PERIOD",
        default=timedelta(minutes=2),
        description="Duration between scheduled runs (ISO 8601).",
    )
    icon_filepath: str | None = Field(
        alias="COLLECTOR_ICON_FILEPATH",
        default="src/img/template-logo.png",
        description="Path to the collector icon file.",
    )


class ConfigLoaderCustom(ConfigBaseSettings):
    """Custom integration configuration settings."""

    key: str | None = Field(
        alias="CUSTOM_KEY",
        default="value",
        description="Example key-value configuration.",
    )
    time_window: timedelta = Field(
        alias="CUSTOM_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for threat searches (ISO 8601).",
    )
    expectation_batch_size: int = Field(
        alias="CUSTOM_EXPECTATION_BATCH_SIZE",
        default=50,
        description="Expectations per batch.",
    )
