import logging
import re
from dataclasses import dataclass, field
from datetime import datetime

from requests.exceptions import ConnectionError, RequestException, Timeout
from src.models.incident import Alert
from src.services.client_api import PaloAltoCortexXSOARClientAPI
from src.services.exception import (
    PaloAltoCortexXSOARAPIError,
    PaloAltoCortexXSOARNetworkError,
    PaloAltoCortexXSOARValidationError,
)

LOG_PREFIX = "[AlertFetcher]"

PAGE_SIZE = 100

IMPLANT_PATTERN = re.compile(
    r"oaev-implant-[a-f0-9\-]+-agent-[a-f0-9\-]+", re.IGNORECASE
)


@dataclass
class FetchResult:
    alerts: list[Alert] = field(default_factory=list)
    process_names_by_alert_id: dict[str, list[str]] = field(default_factory=dict)


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
    ) -> FetchResult:
        """Fetch all alerts for a given time window.

        Returns:
            FetchResult with implant-bearing alerts and process names by alert_id.
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
            from_date = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            to_date = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

            all_alerts = self._fetch_all_alerts(from_date, to_date)

            if not all_alerts:
                self.logger.info(f"{LOG_PREFIX} No alerts found for time window")
                return FetchResult()

            relevant_alerts: list[Alert] = []
            process_names_by_alert_id: dict[str, list[str]] = {}

            for alert in all_alerts:
                implant_names = _extract_implant_names(alert)
                if implant_names:
                    relevant_alerts.append(alert)
                    process_names_by_alert_id[alert.alert_id] = implant_names

            self.logger.info(
                f"{LOG_PREFIX} Found {len(all_alerts)} alerts: "
                f"{len(relevant_alerts)} with implant names"
            )

            return FetchResult(
                alerts=relevant_alerts,
                process_names_by_alert_id=process_names_by_alert_id,
            )

        except (ConnectionError, Timeout) as e:
            raise PaloAltoCortexXSOARNetworkError(
                f"Network error fetching alerts for time window: {e}"
            ) from e
        except RequestException as e:
            raise PaloAltoCortexXSOARAPIError(
                f"HTTP request failed fetching alerts for time window: {e}"
            ) from e
        except Exception as e:
            raise PaloAltoCortexXSOARAPIError(
                f"Error fetching alerts for time window: {e}"
            ) from e

    def _fetch_all_alerts(self, from_date: str, to_date: str) -> list[Alert]:
        """Paginate through search_incidents to retrieve all alerts."""
        all_alerts: list[Alert] = []
        search_from = 0

        while True:
            response = self.client_api.search_incidents(
                from_date=from_date,
                to_date=to_date,
                search_from=search_from,
                search_to=search_from + PAGE_SIZE,
            )

            for incident in response.data:
                if incident.custom_fields and incident.custom_fields.xdralerts:
                    all_alerts.extend(incident.custom_fields.xdralerts)

            if (
                not response.data
                or (search_from + len(response.data)) >= response.total
            ):
                break

            search_from += PAGE_SIZE

        return all_alerts


def _extract_implant_names(alert: Alert) -> list[str]:
    """Extract oaev-implant filenames from alert."""
    names = set()

    if alert.actor_process_command_line:
        matches = IMPLANT_PATTERN.findall(alert.actor_process_command_line)
        names.update(matches)

    return list(names)
