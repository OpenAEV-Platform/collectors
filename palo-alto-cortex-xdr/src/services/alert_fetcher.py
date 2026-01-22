"""PaloAltoCortexXDR Alert Fetcher."""

import logging
from datetime import datetime

from requests.exceptions import (
    ConnectionError,
    RequestException,
    Timeout,
)
from src.models.alert import Alert
from src.services.client_api import PaloAltoCortexXDRClientAPI
from src.services.exception import (
    PaloAltoCortexXDRAPIError,
    PaloAltoCortexXDRNetworkError,
    PaloAltoCortexXDRValidationError,
)

LOG_PREFIX = "[AlertFetcher]"


class AlertFetcher:
    """Fetcher for PaloAltoCortexXDR alert data using time-window based queries."""

    def __init__(self, client_api: PaloAltoCortexXDRClientAPI) -> None:
        if client_api is None:
            raise PaloAltoCortexXDRValidationError("client_api cannot be None")

        self.logger = logging.getLogger(__name__)
        self.client_api = client_api
        self.logger.debug(f"{LOG_PREFIX} Alert fetcher initialized")

    def fetch_alerts_for_time_window(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[Alert]:
        """Fetch all alerts for a given time window.

        Args:
            start_time: Start time as datetime object.
            end_time: End time as datetime object.

        Returns:
            List of PaloAltoCortexXDRAlert objects.

        Raises:
            PaloAltoCortexXDRAPIError: If API call fails.
            PaloAltoCortexXDRValidationError: If parameters are invalid.

        """
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise PaloAltoCortexXDRValidationError(
                "start_time and end_time must be datetime objects"
            )

        if start_time >= end_time:
            raise PaloAltoCortexXDRValidationError("start_time must be before end_time")

        try:
            start_timestamp = int(start_time.timestamp())
            end_timestamp = int(end_time.timestamp())

            alerts = self.client_api.get_alerts(
                start_time=start_timestamp, end_time=end_timestamp
            )

            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(alerts)} alerts for time window"
            )
            return alerts

        except (ConnectionError, Timeout) as e:
            raise PaloAltoCortexXDRNetworkError(
                f"Network error fetching alerts for time window: {e}"
            ) from e
        except RequestException as e:
            raise PaloAltoCortexXDRAPIError(
                f"HTTP request failed fetching alerts for time window: {e}"
            ) from e
        except Exception as e:
            raise PaloAltoCortexXDRAPIError(
                f"Error fetching alerts for time window: {e}"
            ) from e
