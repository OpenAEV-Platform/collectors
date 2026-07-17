"""Configuration for custom integration."""

from datetime import timedelta

from pydantic import Field
from src.models.settings import ConfigBaseSettings


class _ConfigLoaderSource(ConfigBaseSettings):
    """Source configuration settings.

    Contains connection details, timing parameters, and retry settings
    for source integration.
    """

    key: str | None = Field(
        alias="SOURCE_KEY",
        default="value",
        description="key value example for configuration.",
    )
    time_window: timedelta = Field(
        alias="SOURCE_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for Microsoft Defender for Office 365 threat searches when no date signatures are provided (ISO 8601 format).",
    )
    expectation_batch_size: int = Field(
        alias="SOURCE_EXPECTATION_BATCH_SIZE",
        default=50,
        description="Number of expectations to process in each batch for batch-based processing.",
    )
