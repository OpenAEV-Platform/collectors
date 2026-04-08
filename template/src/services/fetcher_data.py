"""Template Data Fetcher."""

import logging
from datetime import datetime

from .exception import (
    TemplateFetcherError,
    TemplateValidationError,
)
from .model_data import TemplateData

LOG_PREFIX = "[TemplateDataFetcher]"


class FetcherData:
    """Fetcher for Template data using time-window based queries."""

    def __init__(self) -> None:
        """Initialize the Threat fetcher."""
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} Data fetcher initialized")

    def fetch_data_for_time_window(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
    ) -> list[TemplateData]:
        """Fetch all data for a given time window.

        Args:
            start_time: Start time as datetime object.
            end_time: End time as datetime object.
            limit: Maximum number of threats to fetch.

        Returns:
            List of TemplateData objects.

        Raises:
            TemplateFetcherError: If fetcher fails.
            TemplateValidationError: If parameters are invalid.

        """
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise TemplateValidationError(
                "start_time and end_time must be datetime objects"
            )

        if start_time >= end_time:
            raise TemplateValidationError("start_time must be before end_time")

        if limit <= 0:
            raise TemplateValidationError("limit must be positive")

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching data for time window: {start_time} to {end_time}"
            )

            data = [TemplateData()]
            # to fill with the relevant data according to your collector

            self.logger.info(f"{LOG_PREFIX} Fetched {len(data)} data for time window")
            return data

        except Exception as e:
            raise TemplateFetcherError(
                f"Error fetching data for time window: {e}"
            ) from e
