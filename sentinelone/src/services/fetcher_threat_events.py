"""SentinelOne Threat Events Fetcher."""

import logging
from typing import TYPE_CHECKING, Any

from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError, RequestException, Timeout)

from .exception import (SentinelOneAPIError, SentinelOneNetworkError,
                        SentinelOneValidationError)
from .model_threat import SentinelOneThreat

if TYPE_CHECKING:
    from .client_api import SentinelOneClientAPI

LOG_PREFIX = "[SentinelOneThreatEventsFetcher]"


class FetcherThreatEvents:
    """Fetcher for SentinelOne threat events using API queries."""

    def __init__(self, client_api: "SentinelOneClientAPI") -> None:
        """Initialize the Threat Events fetcher.

        Args:
            client_api: SentinelOne API client instance.

        Raises:
            SentinelOneValidationError: If client_api is None.

        """
        if client_api is None:
            raise SentinelOneValidationError("client_api cannot be None")

        self.logger = logging.getLogger(__name__)
        self.client_api = client_api
        self.logger.debug(f"{LOG_PREFIX} Threat events fetcher initialized")

    def fetch_events_for_threat(
        self,
        threat: SentinelOneThreat,
        process_names: list[str] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch events for a specific threat filtered by process names.

        Args:
            threat: The threat to fetch events for.
            process_names: Optional list of process names to filter by.
            limit: Maximum number of events to fetch per process.

        Returns:
            List of event dictionaries.

        Raises:
            SentinelOneValidationError: If parameters are invalid.
            SentinelOneAPIError: If API call fails.

        """
        if not isinstance(threat, SentinelOneThreat):
            raise SentinelOneValidationError(
                "threat must be a SentinelOneThreat instance"
            )

        if not threat.threat_id:
            raise SentinelOneValidationError("threat must have a threat_id")

        if limit <= 0:
            raise SentinelOneValidationError("limit must be positive")

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching events for threat {threat.threat_id}, {threat}"
            )

            all_events = self._fetch_all_events_for_threat(threat, limit)

            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(all_events)} total events for threat {threat.threat_id}"
            )
            return all_events

        except (SentinelOneValidationError, SentinelOneAPIError):
            raise
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error fetching events for threat {threat.threat_id}: {e}"
            ) from e

    def _fetch_all_events_for_threat(
        self, threat: SentinelOneThreat, limit: int
    ) -> list[dict[str, Any]]:
        """Fetch all events for a threat without process name filtering.

        Args:
            threat: The threat to fetch events for.
            limit: Maximum number of events to fetch.

        Returns:
            List of event dictionaries.

        """
        try:
            endpoint = f"{self.client_api.base_url}/web/api/v2.1/threats/{threat.threat_id}/explore/events"
            params = {"limit": limit}

            self.logger.debug(
                f"{LOG_PREFIX} Making API call to fetch events for threat {threat.threat_id}"
            )

            response = self.client_api.session.get(endpoint, params=params)
            response.raise_for_status()

            json_data = response.json()
            events = json_data.get("data", [])

            self.logger.debug(
                f"{LOG_PREFIX} Retrieved {len(events)} events for threat {threat.threat_id}"
            )
            return events

        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error fetching events for threat {threat.threat_id}: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(
                f"HTTP request failed for threat {threat.threat_id}: {e}"
            ) from e
        except Exception as e:
            raise SentinelOneAPIError(
                f"Error fetching events for threat {threat.threat_id}: {e}"
            ) from e
