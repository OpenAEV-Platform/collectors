"""SentinelOne Deep Visibility Fetcher for threat analysis."""

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from requests import ConnectionError, RequestException, Timeout

from .client_api import REQUEST_TIMEOUT_SECONDS, SentinelOneClientAPI
from .exception import (
    SentinelOneAPIError,
    SentinelOneNetworkError,
    SentinelOneValidationError,
)
from .utils.s1ql import dv_list, dv_string

LOG_PREFIX = "[FetcherDeepVisibility]"
MAX_STATUS_POLL_ATTEMPTS = 30


class FetcherDeepVisibility:
    """Fetcher for SentinelOne Deep Visibility data for threats."""

    # Where each Logging event value is in an event from fetch_rows, keyed by
    # LoggingEvent attribute. Only processName and parentProcessName are used
    # by Detection today: the other names are not checked on a self-hosted
    # console yet.
    LOGGING_FIELDS = {
        "event_time": "createdAt",
        "event_type": "eventType",
        "endpoint_name": "agentName",
        "event_id": "id",
        "tgt_process_name": "tgtProcName",
        "src_process_name": "processName",
        "src_parent_process_name": "parentProcessName",
        "src_ip": "srcIp",
        "dst_ip": "dstIp",
    }

    def __init__(self, client_api: SentinelOneClientAPI):
        """Initialize the Deep Visibility fetcher.

        Args:
            client_api: SentinelOne API client instance.

        """
        self.client_api = client_api
        self.logger = logging.getLogger(__name__)

    def fetch_events_for_sha1(
        self, sha1: str, start_time: datetime = None, end_time: datetime = None
    ) -> list[dict[str, Any]]:
        """Fetch Deep Visibility events for a specific SHA1.

        Args:
            sha1: SHA1 hash to search for.
            start_time: Start time for the search (optional).
            end_time: End time for the search (optional).

        Returns:
            List of event dictionaries compatible with threat events.

        Raises:
            SentinelOneValidationError: If SHA1 is invalid.
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        if not sha1 or not isinstance(sha1, str):
            raise SentinelOneValidationError("SHA1 must be a non-empty string")

        try:
            self.logger.debug(f"{LOG_PREFIX} Fetching DV events for SHA1: {sha1}")

            query_id = self._init_dv_query([sha1], start_time, end_time)

            all_events = self._execute_query(query_id)

            events = [event for event in all_events if event.get("fileSha1") == sha1]

            self.logger.info(
                f"{LOG_PREFIX} Successfully fetched {len(events)} DV events for SHA1: {sha1}"
            )
            return events

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
        ):
            raise
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error fetching DV events for SHA1 {sha1}: {e}"
            ) from e

    def fetch_events_for_batch_sha1(
        self,
        sha1_list: list[str],
        start_time: datetime = None,
        end_time: datetime = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Fetch Deep Visibility events for multiple SHA1s in a single query.

        Args:
            sha1_list: List of SHA1 hashes to search for.
            start_time: Start time for the search (optional).
            end_time: End time for the search (optional).

        Returns:
            Dictionary mapping SHA1 to list of event dictionaries.

        Raises:
            SentinelOneValidationError: If SHA1 list is invalid.
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        if not sha1_list or not isinstance(sha1_list, list):
            raise SentinelOneValidationError("sha1_list must be a non-empty list")

        valid_sha1s = [sha1 for sha1 in sha1_list if sha1 and isinstance(sha1, str)]

        if not valid_sha1s:
            self.logger.debug(f"{LOG_PREFIX} No valid SHA1s provided")
            return {}

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching DV events for {len(valid_sha1s)} SHA1s in batch"
            )

            query_id = self._init_dv_query(valid_sha1s, start_time, end_time)

            all_events = self._execute_query(query_id)

            sha1_to_events = {}
            for sha1 in valid_sha1s:
                sha1_to_events[sha1] = []

            for event in all_events:
                file_sha1 = event.get("fileSha1")
                if file_sha1 in sha1_to_events:
                    sha1_to_events[file_sha1].append(event)

            total_events = sum(len(events) for events in sha1_to_events.values())
            self.logger.info(
                f"{LOG_PREFIX} Successfully fetched {total_events} total DV events for {len(valid_sha1s)} SHA1s"
            )
            return sha1_to_events

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
        ):
            raise
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error fetching DV events for batch SHA1s: {e}"
            ) from e

    def fetch_rows(
        self, query: str, start_time: datetime, end_time: datetime
    ) -> list[dict[str, Any]]:
        """Fetch the events matching an S1QL 1.0 query inside a time window.

        Used by Logging, which builds its own query. Each event is returned as
        Deep Visibility sent it. Like the SHA1 search, only the first page of
        events is read.

        Args:
            query: S1QL 1.0 query.
            start_time: Window start.
            end_time: Window end.

        Returns:
            The raw events.

        Raises:
            SentinelOneAPIError: If the API call fails. ``status_code`` holds
                the HTTP status when SentinelOne answered with an error.
            SentinelOneNetworkError: If a network error occurs.

        """
        return self._execute_query(self._launch_query(query, start_time, end_time))

    def _launch_query(
        self, query: str, start_time: datetime, end_time: datetime
    ) -> str:
        """Start a Deep Visibility query and return its id.

        Args:
            query: S1QL 1.0 query.
            start_time: Window start.
            end_time: Window end.

        Returns:
            The query id.

        Raises:
            SentinelOneAPIError: If the call fails or returns no query id.
            SentinelOneNetworkError: If a network error occurs.

        """
        endpoint = f"{self.client_api.base_url}/web/api/v2.1/dv/init-query"
        self.logger.debug(f"{LOG_PREFIX} DV Query: {query}")
        body = {
            "query": query,
            "fromDate": self._format_timestamp_for_api(start_time),
            "toDate": self._format_timestamp_for_api(end_time),
        }
        try:
            response = self.client_api.session.post(
                endpoint, json=body, timeout=REQUEST_TIMEOUT_SECONDS
            )
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error making DV init query: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(
                f"HTTP request failed for DV init query: {e}"
            ) from e

        if response.status_code != 200:
            raise SentinelOneAPIError(
                f"DV init query failed with status {response.status_code}: "
                f"{self._parse_error_response(response)}",
                status_code=response.status_code,
            )
        try:
            data = response.json().get("data") or {}
        except (AttributeError, ValueError) as e:
            raise SentinelOneAPIError(f"DV init query returned no JSON: {e}") from e
        query_id = data.get("queryId") if isinstance(data, dict) else None
        if not query_id:
            raise SentinelOneAPIError("DV init query response is missing queryId")
        return query_id

    def _init_dv_query(
        self,
        sha1_list: list[str],
        start_time: datetime = None,
        end_time: datetime = None,
    ) -> str:
        """Start a Deep Visibility query for SHA1s and return its id.

        When Deep Visibility refuses the window because it is older than its
        retention, the window is shortened to the retention and the query is
        started again once, after a pause for the rate limit. If that second
        try fails too, its error is raised.

        Args:
            sha1_list: List of SHA1 hashes to search for.
            start_time: Start time for the search (optional).
            end_time: End time for the search (optional).

        Returns:
            The query id.

        Raises:
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - self.client_api.time_window

        if len(sha1_list) == 1:
            query_string = f"tgtFileSha1 = {dv_string(sha1_list[0])}"
        else:
            query_string = f"tgtFileSha1 in ({dv_list(sha1_list)})"

        try:
            return self._launch_query(query_string, start_time, end_time)
        except SentinelOneAPIError as e:
            retention_days = self._extract_retention_days(str(e))
            if not retention_days:
                raise

        self.logger.warning(
            f"{LOG_PREFIX} DV retention limit ({retention_days} days) exceeded. Adjusting time window and retrying..."
        )
        self.logger.info(
            f"{LOG_PREFIX} Waiting 60 seconds due to DV API rate limit before retry..."
        )
        time.sleep(60)
        adjusted_start_time = end_time - timedelta(days=retention_days - 1)
        self.logger.debug(
            f"{LOG_PREFIX} Retrying with adjusted time window: {adjusted_start_time} to {end_time}"
        )
        # One retry only: the shortened window fits the retention, so a second
        # refusal means something else is wrong, and looping would never end.
        return self._launch_query(query_string, adjusted_start_time, end_time)

    def _execute_query(self, query_id: str) -> list[dict[str, Any]]:
        """Wait for a started Deep Visibility query, then read its events.

        Args:
            query_id: Id of the started query.

        Returns:
            List of event dictionaries.

        Raises:
            SentinelOneValidationError: If there is no query id.

        """
        if not query_id:
            raise SentinelOneValidationError("No query ID available, cannot execute")

        try:
            self.logger.debug(f"{LOG_PREFIX} Executing DV query with ID: {query_id}")

            self._wait_for_query_completion(query_id)

            return self._make_real_events_query(query_id)

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
        ):
            raise
        except Exception as e:
            raise SentinelOneAPIError(f"Error executing DV query: {e}") from e

    def _wait_for_query_completion(self, query_id: str) -> None:
        """Wait for DV query to complete processing.

        Args:
            query_id: Query identifier to check status for.

        Raises:
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        if not query_id:
            raise SentinelOneValidationError("query_id cannot be empty")

        attempt = 0
        while attempt < MAX_STATUS_POLL_ATTEMPTS:
            try:
                endpoint = f"{self.client_api.base_url}/web/api/v2.1/dv/query-status"
                params = {"queryId": query_id}

                self.logger.debug(
                    f"{LOG_PREFIX} Checking query status for ID: {query_id}"
                )

                response = self.client_api.session.get(
                    endpoint, params=params, timeout=REQUEST_TIMEOUT_SECONDS
                )

                if response.status_code == 200:
                    json_data = response.json()
                    data = json_data.get("data", {})

                    progress_status = data.get("progressStatus", 0)
                    response_state = data.get("responseState", "")

                    self.logger.debug(
                        f"{LOG_PREFIX} Query status: {response_state}, Progress: {progress_status}%"
                    )

                    if response_state == "FINISHED" or progress_status >= 100:
                        self.logger.info(
                            f"{LOG_PREFIX} Query {query_id} completed (Status: {response_state}, Progress: {progress_status}%)"
                        )
                        return

                    wait_time = self._calculate_wait_time(progress_status, attempt)

                    self.logger.debug(
                        f"{LOG_PREFIX} Query still processing (Progress: {progress_status}%), waiting {wait_time}s before next check"
                    )
                    time.sleep(wait_time)

                    attempt += 1
                else:
                    error_detail = self._parse_error_response(response)
                    raise SentinelOneAPIError(
                        f"Query status check failed with status {response.status_code}: {error_detail}",
                        status_code=response.status_code,
                    )

            except SentinelOneValidationError, SentinelOneAPIError:
                raise
            except (ConnectionError, Timeout) as e:
                raise SentinelOneNetworkError(
                    f"Network error checking query status: {e}"
                ) from e
            except RequestException as e:
                raise SentinelOneAPIError(
                    f"HTTP request failed for query status: {e}"
                ) from e
            except Exception as e:
                raise SentinelOneAPIError(
                    f"Unexpected error checking query status: {e}"
                ) from e

        raise SentinelOneAPIError(
            f"Query {query_id} did not complete within {MAX_STATUS_POLL_ATTEMPTS} attempts"
        )

    def _calculate_wait_time(self, progress_status: int, attempt: int) -> int:
        """Calculate optimal wait time based on query progress and attempt number.

        Args:
            progress_status: Current progress percentage (0-100).
            attempt: Current attempt number.

        Returns:
            Wait time in seconds.

        """
        if progress_status < 10:
            base_wait = 10
        elif progress_status < 50:
            base_wait = 5
        elif progress_status < 90:
            base_wait = 3
        else:
            base_wait = 2

        backoff = min(attempt * 2, 10)

        return base_wait + backoff

    def _make_real_events_query(self, query_id: str) -> list[dict[str, Any]]:
        """Make real API call to fetch Deep Visibility events.

        Args:
            query_id: Query identifier from initialization.

        Returns:
            List of event dictionaries.

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

                self.logger.debug(
                    f"{LOG_PREFIX} Returning {len(events_data)} DV events as dict format"
                )
                return events_data
            else:
                error_detail = self._parse_error_response(response)
                raise SentinelOneAPIError(
                    f"DV events query failed with status {response.status_code}: {error_detail}",
                    status_code=response.status_code,
                )

        except SentinelOneValidationError, SentinelOneAPIError:
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

    def _parse_error_response(self, response: Any) -> str:
        """Parse error response to extract detailed error information.

        Args:
            response: HTTP response object.

        Returns:
            Detailed error message string.

        """
        try:
            if hasattr(response, "json"):
                error_data = response.json()
                errors = error_data.get("errors", [])
                if errors:
                    error_messages = []
                    for error in errors:
                        detail = error.get("detail", "")
                        title = error.get("title", "")
                        code = error.get("code", "")

                        error_msg = f"Code {code}: {title}"
                        if detail:
                            error_msg += f" - {detail}"
                        error_messages.append(error_msg)

                    return "; ".join(error_messages)

            return getattr(response, "text", str(response))

        except Exception as e:
            return f"Error parsing response: {e}"

    def _extract_retention_days(self, error_detail: str) -> int | None:
        """Extract retention period in days from error message.

        Args:
            error_detail: Error detail string from API response.

        Returns:
            Number of retention days if found, None otherwise.

        """
        try:
            match = re.search(
                r"retains data for (\d+) days?", error_detail, re.IGNORECASE
            )
            if match:
                return int(match.group(1))

            match = re.search(r"retention.*?(\d+)\s*days?", error_detail, re.IGNORECASE)
            if match:
                return int(match.group(1))

            return None

        except Exception as e:
            self.logger.debug(f"{LOG_PREFIX} Error extracting retention days: {e}")
            return None
