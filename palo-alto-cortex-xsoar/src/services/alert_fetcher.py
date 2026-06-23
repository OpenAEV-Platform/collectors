import logging
from datetime import datetime, timezone
from typing import List

from requests.exceptions import ConnectionError, RequestException, Timeout
from src.services.client_api import PaloAltoCortexXSOARClientAPI
from src.services.exception import (
    PaloAltoCortexXSOARAPIError,
    PaloAltoCortexXSOARNetworkError,
    PaloAltoCortexXSOARValidationError,
)
from src.services.ioc_extractor import IncidentResult, extract_from_custom_fields

LOG_PREFIX = "[AlertFetcher]"

PAGE_SIZE = 100


class AlertFetcher:
    """Fetcher for PaloAltoCortexXSOAR alert data using time-window based queries."""

    def __init__(self, client_api: PaloAltoCortexXSOARClientAPI) -> None:
        if client_api is None:
            raise PaloAltoCortexXSOARValidationError("client_api cannot be None")

        self.logger = logging.getLogger(__name__)
        self.client_api = client_api
        self.logger.debug(f"{LOG_PREFIX} Alert fetcher initialized")

    def fetch_alerts_for_time_window(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> List[IncidentResult]:
        """Fetch all incidents for a given time window.

        Returns:
            List of IncidentResult with extracted indicators.
        """
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise PaloAltoCortexXSOARValidationError(
                "start_time and end_time must be datetime objects"
            )

        if start_time >= end_time:
            raise PaloAltoCortexXSOARValidationError(
                "start_time must be before end_time"
            )

        try:
            from_date = start_time.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            to_date = end_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            all_incidents = self._fetch_all_incidents(from_date, to_date)

            if not all_incidents:
                self.logger.info(f"{LOG_PREFIX} No incidents found for time window")
                return []

            self.logger.info(
                f"{LOG_PREFIX} Found {len(all_incidents)} incidents with indicators"
            )

            return all_incidents

        except (ConnectionError, Timeout) as e:
            raise PaloAltoCortexXSOARNetworkError(
                f"Network error fetching incidents for time window: {e}"
            ) from e
        except RequestException as e:
            raise PaloAltoCortexXSOARAPIError(
                f"HTTP request failed fetching incidents for time window: {e}"
            ) from e
        except Exception as e:
            raise PaloAltoCortexXSOARAPIError(
                f"Error fetching incidents for time window: {e}"
            ) from e

    def _fetch_all_incidents(
        self, from_date: str, to_date: str
    ) -> List[IncidentResult]:
        """Paginate through search_incidents and extract indicators from each incident."""
        all_incidents: List[IncidentResult] = []
        search_from = 0

        while True:
            response = self.client_api.search_incidents(
                from_date=from_date,
                to_date=to_date,
                search_from=search_from,
                search_to=search_from + PAGE_SIZE,
            )

            if response.data:
                results = extract_from_custom_fields(response.data)
                all_incidents.extend(results)

            if (
                not response.data
                or (search_from + len(response.data)) >= response.total
            ):
                break

            search_from += PAGE_SIZE

        return all_incidents
