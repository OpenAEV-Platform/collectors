import logging
from datetime import datetime
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
        """Fetch all incidents for a given time window and filter alerts by timestamp.

        After retrieving incidents from the API, each incident's alerts are filtered
        to keep only those whose detection_timestamp falls within [start_time, end_time].
        Incidents with no matching alerts are discarded.

        Returns:
            List of IncidentResult with only alerts inside the time window.
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
            if start_time.tzinfo is None:
                start_time = start_time.astimezone()
            if end_time.tzinfo is None:
                end_time = end_time.astimezone()

            from_date = start_time.isoformat(timespec="seconds").replace("+00:00", "Z")
            to_date = end_time.isoformat(timespec="seconds").replace("+00:00", "Z")

            all_incidents = self._fetch_all_incidents(from_date, to_date)

            if not all_incidents:
                self.logger.info(f"{LOG_PREFIX} No incidents found for time window")
                return []

            # Filter alerts within each incident by detection_timestamp
            filtered_incidents = self._filter_alerts_by_timestamp(
                all_incidents, start_time, end_time
            )

            self.logger.info(
                f"{LOG_PREFIX} Found {len(all_incidents)} incidents, "
                f"{len(filtered_incidents)} have alerts within [{start_time} - {end_time}]"
            )

            return filtered_incidents

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

    def _filter_alerts_by_timestamp(
        self,
        incidents: List[IncidentResult],
        start_time: datetime,
        end_time: datetime,
    ) -> List[IncidentResult]:
        """Filter each incident's alerts by detection_timestamp within [start, end].

        Uses a functional map/filter approach:
        - map: produce (original, transformed) incident pairs where transformed keeps
          only alerts in the time window
        - filter: keep transformed incidents that either still have alerts OR had no
          alert details in the original payload (legacy compatibility)

        Args:
            incidents: List of IncidentResult with raw alerts.
            start_time: Start of the time window (inclusive).
            end_time: End of the time window (inclusive).

        Returns:
            List of IncidentResult with alerts filtered to the time window.
        """
        start_ts = int(start_time.timestamp() * 1000)
        end_ts = int(end_time.timestamp() * 1000)

        def with_filtered_alerts(
            incident: IncidentResult,
        ) -> tuple[IncidentResult, IncidentResult]:
            """Return original+transformed incident with alerts in the time window."""
            transformed = incident.model_copy(
                update={
                    "alerts": [
                        alert
                        for alert in incident.alerts
                        if start_ts <= alert.detection_timestamp <= end_ts
                    ]
                }
            )
            return incident, transformed

        return list(
            map(
                lambda pair: pair[1],
                filter(
                    lambda pair: len(pair[1].alerts) > 0 or len(pair[0].alerts) == 0,
                    map(with_filtered_alerts, incidents),
                ),
            )
        )

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
