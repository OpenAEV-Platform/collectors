"""SentinelOne Deep Visibility Fetcher for static threat analysis."""

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from requests import ConnectionError, RequestException, Timeout

from .client_api import SentinelOneClientAPI
from .exception import (SentinelOneAPIError, SentinelOneNetworkError,
                        SentinelOneValidationError)

LOG_PREFIX = "[FetcherDeepVisibility]"
REQUEST_TIMEOUT_SECONDS = 30
MAX_STATUS_POLL_ATTEMPTS = 30


class FetcherDeepVisibility:
    """Fetcher for SentinelOne Deep Visibility data for static threats."""

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

            query_response = self._init_dv_query([sha1], start_time, end_time)

            all_events = self._execute_query(query_response)

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

            query_response = self._init_dv_query(valid_sha1s, start_time, end_time)

            all_events = self._execute_query(query_response)

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

    def _init_dv_query(
        self,
        sha1_list: list[str],
        start_time: datetime = None,
        end_time: datetime = None,
    ) -> Any:
        """Initialize Deep Visibility query for SHA1s.

        Args:
            sha1_list: List of SHA1 hashes to search for.
            start_time: Start time for the search (optional).
            end_time: End time for the search (optional).

        Returns:
            Query response object.

        Raises:
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        try:
            endpoint = f"{self.client_api.base_url}/web/api/v2.1/dv/init-query"

            if len(sha1_list) == 1:
                query_string = f'tgtFileSha1 = "{sha1_list[0]}"'
            else:
                sha1_values = '","'.join(sha1_list)
                query_string = f'tgtFileSha1 in ("{sha1_values}")'

            if end_time is None:
                end_time = datetime.now(timezone.utc)
            if start_time is None:
                start_time = end_time - self.client_api.time_window

            body = {
                "query": query_string,
                "fromDate": self._format_timestamp_for_api(start_time),
                "toDate": self._format_timestamp_for_api(end_time),
            }

            self.logger.debug(f"{LOG_PREFIX} Making POST request to: {endpoint}")
            self.logger.debug(f"{LOG_PREFIX} DV Query: {query_string}")
            self.logger.debug(f"{LOG_PREFIX} Full body payload: {body}")

            response = self.client_api.session.post(
                endpoint, json=body, timeout=REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code == 200:
                json_data = response.json()

                class InitQueryResponse:
                    def __init__(self, data: dict):
                        self.data = InitData(data.get("data", {}))

                class InitData:
                    def __init__(self, data: dict):
                        self.query_id = data.get("queryId")

                return InitQueryResponse(json_data)
            else:
                error_detail = self._parse_error_response(response)

                retention_days = self._extract_retention_days(error_detail)
                if retention_days and len(sha1_list) > 0:
                    self.logger.warning(
                        f"{LOG_PREFIX} DV retention limit ({retention_days} days) exceeded. Adjusting time window and retrying..."
                    )

                    self.logger.info(
                        f"{LOG_PREFIX} Waiting 60 seconds due to DV API rate limit before retry..."
                    )
                    time.sleep(60)

                    adjusted_end_time = end_time or datetime.now(timezone.utc)
                    adjusted_start_time = adjusted_end_time - timedelta(
                        days=retention_days - 1
                    )

                    self.logger.debug(
                        f"{LOG_PREFIX} Retrying with adjusted time window: {adjusted_start_time} to {adjusted_end_time}"
                    )

                    return self._init_dv_query(
                        sha1_list, adjusted_start_time, adjusted_end_time
                    )

                raise SentinelOneAPIError(
                    f"DV init query failed with status {response.status_code}: {error_detail}"
                )

        except SentinelOneAPIError:
            raise
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error making DV init query: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(
                f"HTTP request failed for DV init query: {e}"
            ) from e
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error making DV init query: {e}"
            ) from e

    def _execute_query(self, query_response: Any) -> list[dict[str, Any]]:
        """Execute the Deep Visibility query.

        Args:
            query_response: Response from query initialization.

        Returns:
            List of event dictionaries.

        Raises:
            SentinelOneValidationError: If query response is invalid.

        """
        if not query_response or not hasattr(query_response, "data"):
            raise SentinelOneValidationError("Invalid query response, cannot execute")

        query_id = query_response.data.query_id
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
                        f"Query status check failed with status {response.status_code}: {error_detail}"
                    )

            except (SentinelOneValidationError, SentinelOneAPIError):
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
                    f"DV events query failed with status {response.status_code}: {error_detail}"
                )

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
