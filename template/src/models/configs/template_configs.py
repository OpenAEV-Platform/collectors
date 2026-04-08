"""Configuration for Template integration."""

from datetime import timedelta

from pydantic import Field
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderTemplate(ConfigBaseSettings):
    """Template API configuration settings.

    Contains connection details, timing parameters, and retry settings
    for Template API integration.
    """

    key: str | None = Field(
        alias="TEMPLATE_KEY",
        default="value",
        description="key value example for configuration.",
    )
    time_window: timedelta = Field(
        alias="TEMPLATE_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for Template threat searches when no date signatures are provided (ISO 8601 format).",
    )
    expectation_batch_size: int = Field(
        alias="TEMPLATE_EXPECTATION_BATCH_SIZE",
        default=50,
        description="Number of expectations to process in each batch for batch-based processing.",
    )
