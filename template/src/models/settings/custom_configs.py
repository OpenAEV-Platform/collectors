"""Configuration for custom integration."""

from datetime import timedelta

from pydantic import Field
from src.models.settings import ConfigBaseSettings


class _ConfigLoaderCustom(ConfigBaseSettings):
    """Custom API configuration settings.

    Contains connection details, timing parameters, and retry settings
    for custom API integration.
    """

    key: str | None = Field(
        alias="CUSTOM_KEY",
        default="value",
        description="key value example for configuration.",
    )
    time_window: timedelta = Field(
        alias="CUSTOM_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for Template threat searches when no date signatures are provided (ISO 8601 format).",
    )
    expectation_batch_size: int = Field(
        alias="CUSTOM_EXPECTATION_BATCH_SIZE",
        default=50,
        description="Number of expectations to process in each batch for batch-based processing.",
    )
