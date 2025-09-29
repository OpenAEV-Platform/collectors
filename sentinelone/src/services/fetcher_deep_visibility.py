"""SentinelOne Deep Visibility Fetcher.

This module provides functionality to fetch Deep Visibility events from SentinelOne
using the real API endpoints.
"""

import logging
import time
from typing import TYPE_CHECKING, Any

from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError,
    RequestException,
    Timeout,
)

from .exception import (
    SentinelOneAPIError,
    SentinelOneNetworkError,
    SentinelOneQueryError,
    SentinelOneValidationError,
)
from .model_deep_visibility import DeepVisibilityEvent, SearchCriteria, utc_now_iso

if TYPE_CHECKING:
    from .client_api import SentinelOneClientAPI

LOG_PREFIX = "[SentinelOneDeepVisibility]"


REQUEST_TIMEOUT_SECONDS = 30
SLEEP_RETRY_SECONDS = 30


class FetcherDeepVisibility:
    """Fetcher for SentinelOne Deep Visibility events."""

    def __init__(self, client_api: "SentinelOneClientAPI") -> None:
        """Initialize the Deep Visibility fetcher.

        Args:
            client_api: SentinelOne API client instance.

        Raises:
            SentinelOneValidationError: If client_api is None.

        """
        if client_api is None:
            raise SentinelOneValidationError("client_api cannot be None")

        self.logger = logging.getLogger(__name__)
        self.client_api = client_api
        self.logger.debug(f"{LOG_PREFIX} Deep Visibility fetcher initialized")

    def fetch(self, search_criteria: SearchCriteria) -> list[DeepVisibilityEvent]:
        """Fetch Deep Visibility events based on search criteria.

        Args:
            search_criteria: SearchCriteria object with query parameters.

        Returns:
            List of DeepVisibilityEvent objects.

        Raises:
            SentinelOneValidationError: If input is invalid.
            SentinelOneAPIError: If API operations fail.
            SentinelOneNetworkError: If network errors occur.

        """
        if not search_criteria:
            raise SentinelOneValidationError("search_criteria cannot be None")

        if not isinstance(search_criteria, SearchCriteria):
            raise SentinelOneValidationError(
                "search_criteria must be a SearchCriteria object"
            )

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching Deep Visibility events for process: {search_criteria.parent_process_name}"
            )

            query_response = self._init_dv_query(search_criteria)

            if not query_response:
                self.logger.debug(
                    f"{LOG_PREFIX} Query initialization failed, no events to fetch"
                )
                return []

            dv_events = self._execute_query(query_response)

            result_count = len(dv_events) if dv_events else 0
            self.logger.info(
                f"{LOG_PREFIX} Fetched {result_count} Deep Visibility events"
            )

            return dv_events if dv_events else []

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
            SentinelOneQueryError,
        ):
            raise
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SentinelOneAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SentinelOneAPIError(f"Unexpected error in fetch: {e}") from e

    def _init_dv_query(self, search_criteria: SearchCriteria) -> Any | None:
        """Initialize Deep Visibility query.

        Args:
            search_criteria: SearchCriteria object.

        Returns:
            Query response object or None.

        Raises:
            SentinelOneValidationError: If required criteria are missing.
            SentinelOneQueryError: If query initialization fails.

        """
        if not search_criteria.parent_process_name or not search_criteria.start_date:
            raise SentinelOneValidationError(
                "parent_process_name and start_date are required for Deep Visibility query"
            )

        try:
            obas_implant_id = search_criteria.parent_process_name
            start_date = search_criteria.start_date
            to_date = search_criteria.to_date or utc_now_iso()

            self.logger.debug(
                f"{LOG_PREFIX} Initializing DV query for process '{obas_implant_id}' from {start_date} to {to_date}"
            )
            return self._make_real_init_query(obas_implant_id, start_date, to_date)

        except (SentinelOneValidationError, SentinelOneQueryError):
            raise
        except Exception as e:
            raise SentinelOneQueryError(f"Error initializing DV query: {e}") from e

    def _make_real_init_query(
        self, obas_implant_id: str, start_date: str, to_date: str
    ) -> Any:
        """Make real API call to initialize Deep Visibility query.

        Args:
            obas_implant_id: Process identifier for the query.
            start_date: Start date for the query in ISO format.
            to_date: End date for the query in ISO format.

        Returns:
            Query initialization response object.

        Raises:
            SentinelOneValidationError: If query parameters are invalid.
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.
            SentinelOneQueryError: If query initialization fails.

        """
        if not all([obas_implant_id, start_date, to_date]):
            raise SentinelOneValidationError("All query parameters are required")

        try:
            endpoint = f"{self.client_api.base_url}/web/api/v2.1/dv/init-query"

            query = f'(srcProcParentName contains "{obas_implant_id}" OR srcProcName contains "{obas_implant_id}") AND eventType="Pre Execution Detection"'
            body = {
                "query": query,
                "fromDate": start_date,
                "toDate": to_date,
            }

            self.logger.debug(f"{LOG_PREFIX} Making POST request to: {endpoint}")
            self.logger.debug(f"{LOG_PREFIX} DV Query: {query}")

            response = self.client_api.session.post(
                endpoint, json=body, timeout=REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code == 200:
                json_data = response.json()
                self.logger.debug(f"{LOG_PREFIX} DV query initialization successful")

                class InitQueryResponse:
                    def __init__(self, data: dict[Any, Any]) -> None:
                        self.data = self.InitData(data.get("data", {}))

                    class InitData:
                        def __init__(self, data: dict[Any, Any]) -> None:
                            self.query_id = data.get("queryId", "")

                return InitQueryResponse(json_data)
            else:
                raise SentinelOneAPIError(
                    f"Unexpected status code: {response.status_code}"
                )

        except (SentinelOneValidationError, SentinelOneAPIError) as e:
            raise SentinelOneQueryError(f"DV query initialization failed: {e}") from e
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error making DV init query: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(
                f"HTTP request failed for DV init query: {e}"
            ) from e
        except Exception as e:
            raise SentinelOneQueryError(
                f"Unexpected error making DV init query: {e}"
            ) from e

    def _execute_query(self, query_response: Any) -> list[DeepVisibilityEvent]:
        """Execute the Deep Visibility query.

        Args:
            query_response: Response from query initialization.

        Returns:
            List of DeepVisibilityEvent objects.

        Raises:
            SentinelOneValidationError: If query response is invalid.
            SentinelOneQueryError: If query execution fails.

        """
        if not query_response or not hasattr(query_response, "data"):
            raise SentinelOneValidationError("Invalid query response, cannot execute")

        query_id = query_response.data.query_id
        if not query_id:
            raise SentinelOneValidationError("No query ID available, cannot execute")

        try:
            self.logger.debug(f"{LOG_PREFIX} Executing DV query with ID: {query_id}")
            return self._make_real_events_query(query_id)

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
        ):
            raise
        except Exception as e:
            raise SentinelOneQueryError(f"Error executing DV query: {e}") from e

    def _make_real_events_query(self, query_id: str) -> list[DeepVisibilityEvent]:
        """Make real API call to fetch Deep Visibility events.

        Args:
            query_id: Query identifier from initialization.

        Returns:
            List of DeepVisibilityEvent objects.

        Raises:
            SentinelOneValidationError: If query_id is empty.
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        if not query_id:
            raise SentinelOneValidationError("query_id cannot be empty")

        try:
            endpoint = f"{self.client_api.base_url}/web/api/v2.1/dv/events"
            params = {"queryId": query_id}

            self.logger.debug(f"{LOG_PREFIX} Making GET request to: {endpoint}")
            self.logger.debug(f"{LOG_PREFIX} Query parameters: {params}")

            response = self.client_api.session.get(
                endpoint, params=params, timeout=REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code == 200:
                json_data = response.json()
                events_data = json_data.get("data", [])

                self.logger.info(
                    f"{LOG_PREFIX} Retrieved {len(events_data)} Deep Visibility events from API"
                )

                dv_events = []
                for i, event_data in enumerate(events_data):
                    try:
                        dv_event = DeepVisibilityEvent(
                            src_proc_parent_name=event_data.get("srcProcParentName"),
                            src_proc_name=event_data.get("srcProcName"),
                            tgt_file_sha1=event_data.get("tgtFileSha1"),
                            _raw=event_data,
                        )
                        dv_events.append(dv_event)
                    except Exception as conversion_error:
                        self.logger.warning(
                            f"{LOG_PREFIX} Error converting event {i + 1}: {conversion_error}"
                        )

                self.logger.debug(
                    f"{LOG_PREFIX} Converted to {len(dv_events)} DeepVisibilityEvent objects"
                )
                return dv_events
            else:
                raise SentinelOneAPIError()

        except (SentinelOneValidationError, SentinelOneAPIError):
            raise
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error making DV events query: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(
                f"HTTP request failed for DV events query: {e}"
            ) from e
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error making DV events query: {e}"
            ) from e

    def _validate_retry_params(self, max_retry: int, offset_seconds: int) -> None:
        """Validate retry parameters.

        Args:
            max_retry: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retry.

        Raises:
            SentinelOneValidationError: If parameters are invalid.

        """
        if max_retry < 0:
            raise SentinelOneValidationError("max_retry cannot be negative")
        if offset_seconds < 0:
            raise SentinelOneValidationError("offset_seconds cannot be negative")

    def _update_search_criteria(
        self, search_criteria: SearchCriteria
    ) -> SearchCriteria:
        """Update search criteria with current timestamp for each attempt.

        Args:
            search_criteria: Original search criteria.

        Returns:
            Updated SearchCriteria with current timestamp.

        """
        return SearchCriteria(
            parent_process_name=search_criteria.parent_process_name,
            process_name=search_criteria.process_name,
            start_date=search_criteria.start_date,
            to_date=utc_now_iso(),
        )

    def _perform_single_dv_fetch_attempt(
        self, search_criteria: SearchCriteria, attempt: int, max_retry: int
    ) -> tuple[list[DeepVisibilityEvent] | None, Exception | None]:
        """Perform a single Deep Visibility fetch attempt.

        Args:
            search_criteria: SearchCriteria object with query parameters.
            attempt: Current attempt number (0-based).
            max_retry: Maximum number of retry attempts.

        Returns:
            Tuple of (events_or_None, exception_or_None).

        """
        self.logger.debug(
            f"{LOG_PREFIX} Deep Visibility attempt {attempt + 1} of {max_retry + 1}"
        )

        try:
            current_criteria = self._update_search_criteria(search_criteria)
            events = self.fetch(current_criteria)

            if events:
                self.logger.info(
                    f"{LOG_PREFIX} Deep Visibility attempt {attempt + 1}: Found {len(events)} events - success!"
                )
                return events, None
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} Deep Visibility attempt {attempt + 1}: No events found"
                )
                return None, None

        except (
            SentinelOneAPIError,
            SentinelOneNetworkError,
            SentinelOneQueryError,
        ) as e:
            self.logger.warning(
                f"{LOG_PREFIX} Deep Visibility attempt {attempt + 1} failed: {e}"
            )
            return None, e

    def _handle_retry_sleep(
        self, attempt: int, max_retry: int, offset_seconds: int
    ) -> None:
        """Handle sleep between retry attempts.

        Args:
            attempt: Current attempt number (0-based).
            max_retry: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retry.

        """
        if attempt < max_retry:
            sleep_time = offset_seconds if offset_seconds > 0 else SLEEP_RETRY_SECONDS
            self.logger.debug(
                f"{LOG_PREFIX} Waiting {sleep_time}s before retry {attempt + 2}..."
            )
            time.sleep(sleep_time)

    def fetch_with_retry(
        self,
        search_criteria: SearchCriteria,
        max_retry: int = 3,
        offset_seconds: int = 30,
    ) -> list[DeepVisibilityEvent]:
        """Fetch Deep Visibility events with retry mechanism.

        Args:
            search_criteria: SearchCriteria object with query parameters.
            max_retry: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retry.

        Returns:
            List of DeepVisibilityEvent objects.

        Raises:
            SentinelOneValidationError: If inputs are invalid.
            SentinelOneAPIError: If all retry attempts fail.

        """
        if not search_criteria:
            raise SentinelOneValidationError("search_criteria cannot be None")

        self._validate_retry_params(max_retry, offset_seconds)

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting Deep Visibility fetch with {offset_seconds}s offset and {max_retry} max retries"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Waiting {offset_seconds}s before first API call..."
            )
            time.sleep(offset_seconds)

            last_exception = None

            for attempt in range(max_retry + 1):
                events, exception = self._perform_single_dv_fetch_attempt(
                    search_criteria, attempt, max_retry
                )

                if events:
                    return events

                if exception:
                    last_exception = exception

                self._handle_retry_sleep(attempt, max_retry, offset_seconds)

            if last_exception:
                raise SentinelOneAPIError(
                    f"All Deep Visibility fetch attempts failed. Last error: {last_exception}"
                ) from last_exception
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} No Deep Visibility events found after all retry attempts"
                )
                return []

        except (SentinelOneValidationError, SentinelOneAPIError):
            raise
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error in Deep Visibility fetch_with_retry: {e}"
            ) from e
