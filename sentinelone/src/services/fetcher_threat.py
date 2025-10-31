"""SentinelOne Threat Fetcher."""

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError,
    RequestException,
    Timeout,
)

from .exception import (
    SentinelOneAPIError,
    SentinelOneNetworkError,
    SentinelOneValidationError,
)
from .model_threat import SentinelOneThreat, SentinelOneThreatsResponse

if TYPE_CHECKING:
    from .client_api import SentinelOneClientAPI

LOG_PREFIX = "[SentinelOneThreatFetcher]"


class FetcherThreat:
    """Fetcher for SentinelOne threat data using time-window based queries."""

    def __init__(self, client_api: "SentinelOneClientAPI") -> None:
        """Initialize the Threat fetcher.

        Args:
            client_api: SentinelOne API client instance.

        Raises:
            SentinelOneValidationError: If client_api is None.

        """
        if client_api is None:
            raise SentinelOneValidationError("client_api cannot be None")

        self.logger = logging.getLogger(__name__)
        self.client_api = client_api
        self.logger.debug(f"{LOG_PREFIX} Threat fetcher initialized")

    def fetch_threats_for_time_window(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
    ) -> list[SentinelOneThreat]:
        """Fetch all threats for a given time window.

        Args:
            start_time: Start time as datetime object.
            end_time: End time as datetime object.
            limit: Maximum number of threats to fetch.

        Returns:
            List of SentinelOneThreat objects.

        Raises:
            SentinelOneAPIError: If API call fails.
            SentinelOneValidationError: If parameters are invalid.

        """
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise SentinelOneValidationError(
                "start_time and end_time must be datetime objects"
            )

        if start_time >= end_time:
            raise SentinelOneValidationError("start_time must be before end_time")

        if limit <= 0:
            raise SentinelOneValidationError("limit must be positive")

        try:
            start_time_str = self._format_timestamp_for_api(start_time)
            end_time_str = self._format_timestamp_for_api(end_time)

            endpoint = f"{self.client_api.base_url}/web/api/v2.1/threats"
            params = {
                "createdAt__gte": start_time_str,
                "createdAt__lt": end_time_str,
                "sortOrder": "desc",
                "limit": limit,
            }

            self.logger.debug(
                f"{LOG_PREFIX} Fetching threats for time window: {start_time_str} to {end_time_str}"
            )

            response = self.client_api.session.get(endpoint, params=params)
            response.raise_for_status()

            json_data = response.json()
            threats_data = json_data.get("data", [])

            response_wrapper = {"data": threats_data}
            threats_response = SentinelOneThreatsResponse.from_raw_response(
                response_wrapper
            )
            threats = threats_response.data

            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(threats)} threats for time window"
            )
            return threats

        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error fetching threats for time window: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(
                f"HTTP request failed fetching threats for time window: {e}"
            ) from e
        except Exception as e:
            raise SentinelOneAPIError(
                f"Error fetching threats for time window: {e}"
            ) from e

    def _format_timestamp_for_api(self, dt: datetime) -> str:
        """Format datetime object for SentinelOne API.

        SentinelOne API expects timestamps in format: 2018-02-27T04:49:26.257525Z

        Args:
            dt: Datetime object to format (should be timezone-aware)

        Returns:
            String formatted timestamp for SentinelOne API

        """
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        elif dt.tzinfo != timezone.utc:
            dt = dt.astimezone(timezone.utc)

        return dt.replace(tzinfo=None).isoformat() + "Z"
