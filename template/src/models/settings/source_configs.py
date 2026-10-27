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
        description="Time window for Template threat searches when no date signatures are provided (ISO 8601 format).",
    )
    expectation_batch_size: int = Field(
        alias="SOURCE_EXPECTATION_BATCH_SIZE",
        default=50,
        description="Number of expectations to process in each batch for batch-based processing.",
    )
    retry_window: timedelta = Field(
        default=timedelta(minutes=10),
        description="How long after the recorded end date an unresolved expectation is re-attempted on every collector cycle, before one final attempt emits the verdict (ISO 8601 format) - if the end date is not available, the start date is used with a factor 1.5 on the retry window (until the end date is available)"
    )
