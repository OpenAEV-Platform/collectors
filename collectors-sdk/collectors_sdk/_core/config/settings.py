"""Configuration base classes for collectors."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl, PlainSerializer
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)
from xtm_oaev_sdk import SettingsLoader

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


class ConfigLoaderOAEV(BaseModel):
    """OpenAEV platform connection settings (nested under 'openaev:' in config.yml)."""

    url: HttpUrlToString = Field(description="The OpenAEV platform URL.")
    token: str = Field(description="The token for the OpenAEV platform.")


class ConfigLoaderCollector(BaseModel):
    """Collector identity settings (nested under 'collector:' in config.yml)."""

    id: str = Field(description="Unique identifier for this collector instance.")
    name: str = Field(description="Name of the collector.")
    platform: str | None = Field(
        default="EDR",
        description="Platform type (e.g., EDR, SIEM).",
    )
    log_level: LogLevelToLower | None = Field(
        default="error",
        description="Log verbosity level.",
    )
    period: timedelta | None = Field(
        default=timedelta(minutes=2),
        description="Duration between scheduled runs (ISO 8601).",
    )
    icon_filepath: str | None = Field(
        default="src/img/template-logo.png",
        description="Path to the collector icon file.",
    )


class ConfigLoaderCustom(BaseModel):
    """Custom integration configuration — subclass for your collector's needs."""

    key: str | None = Field(
        default="value",
        description="Example key-value configuration.",
    )
    time_window: timedelta = Field(
        default=timedelta(hours=1),
        description="Time window for threat searches (ISO 8601).",
    )
    expectation_batch_size: int = Field(
        default=50,
        description="Expectations per batch.",
    )


class ConfigBaseSettings(SettingsLoader):
    """Top-level config loader reading env vars + config.yml.

    Loads nested YAML sections into typed sub-models.
    Subclass this in your collector to add custom config sections.
    """

    openaev: ConfigLoaderOAEV = Field(description="OpenAEV platform connection.")
    collector: ConfigLoaderCollector = Field(description="Collector identity.")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Resolution priority: init kwargs > env vars > YAML > .env > defaults."""
        _main_path = os.curdir

        settings_cls.model_config["env_file"] = f"{_main_path}/../.env"

        if not settings_cls.model_config.get("yaml_file"):
            if Path(f"{_main_path}/config.yml").is_file():
                settings_cls.model_config["yaml_file"] = f"{_main_path}/config.yml"
            elif Path(f"{_main_path}/../config.yml").is_file():
                settings_cls.model_config["yaml_file"] = f"{_main_path}/../config.yml"

        yaml_path = settings_cls.model_config.get("yaml_file") or ""
        if Path(yaml_path).is_file():
            return (
                init_settings,
                env_settings,
                YamlConfigSettingsSource(settings_cls),
            )

        env_file_path = settings_cls.model_config.get("env_file") or ""
        if Path(env_file_path).is_file():
            return (
                init_settings,
                env_settings,
                dotenv_settings,
            )
        return (init_settings, env_settings)
