"""Configuration for HTTPLogwatcher integration."""

from datetime import timedelta
from pathlib import Path

from pydantic import Field

from src.models.settings import ConfigBaseSettings


class ConfigLoaderHTTPLogwatcher(ConfigBaseSettings):
    """HTTPLogwatcher configuration settings.

    Contains folderpath and filepaths details
    for HTTPLogwatcher integration.
    """

    logs_folder_path: Path = Field(
        alias="HTTP_LOGWATCHER_LOGS_FOLDER_PATH",
        description="The folderpath leading to the folder used to store access.log and errors.log"
    )
    time_window: timedelta = Field(
        alias="HTTP_LOGWATCHER_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for HTTP Logwatcher log parser when no date signatures are provided (ISO 8601 format).",
    )
