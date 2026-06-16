"""LogRhythm API client for running Search API tasks."""

import logging
import time
from datetime import timedelta
from typing import Any

import requests  # type: ignore[import-untyped]
from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError,
    RequestException,
    Timeout,
)

from ..models.configs.config_loader import ConfigLoader
from .exception import (
    LogRhythmAPIError,
    LogRhythmAuthenticationError,
    LogRhythmNetworkError,
    LogRhythmQueryError,
    LogRhythmSessionError,
    LogRhythmTimeoutError,
    LogRhythmValidationError,
)
from .models import LogRhythmAlert, LogRhythmResponse, LogRhythmSearchCriteria
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[LogRhythmClientAPI]"

DEFAULT_TIME_WINDOW_HOURS = 1
REQUEST_TIMEOUT_SECONDS = 60

# LogRhythm Search API field IDs (LogQueryFilterTypeEnum)
SIP_FILTER_TYPE = 18  # Source IP
DIP_FILTER_TYPE = 19  # Destination/Impacted IP
URL_FILTER_TYPE = 42  # URL
VALUE_TYPE_STRING = 4
MSG_FILTER_TYPE = 2
FILTER_GROUP_OPERATOR_OR = 1
LAST_INTERVAL_UNIT_MINUTES = 4


class LogRhythmClientAPI:
    """LogRhythm API client for fetching events via the Search API."""

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the LogRhythm API client.

        Args:
            config: Configuration loader instance for API client settings.

        Raises:
            LogRhythmValidationError: If config is None or has invalid structure.
            LogRhythmSessionError: If session creation fails.

        """
        if config is None:
            raise LogRhythmValidationError("Config is required for API client")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.base_url = str(self.config.logrhythm.base_url).rstrip("/")
            self.token = (
                self.config.logrhythm.token.get_secret_value()
                if self.config.logrhythm.token
                else None
            )
            self.username = self.config.logrhythm.username
            self.password = (
                self.config.logrhythm.password.get_secret_value()
                if self.config.logrhythm.password
                else None
            )
            self.query_event_manager = self.config.logrhythm.query_event_manager
            self.max_msgs = self.config.logrhythm.max_msgs
            self.console_url = self.config.logrhythm.console_url
            self.offset = self.config.logrhythm.offset.total_seconds()
            self.max_retry = self.config.logrhythm.max_retry
            self.verify_ssl = self.config.logrhythm.verify_ssl
            self.search_timeout = self.config.logrhythm.search_timeout.total_seconds()
            self.poll_interval = self.config.logrhythm.poll_interval.total_seconds()
        except AttributeError as e:
            raise LogRhythmValidationError(f"Invalid config structure: {e}") from e

        if (
            hasattr(self.config.logrhythm, "time_window")
            and self.config.logrhythm.time_window
        ):
            self.time_window = self.config.logrhythm.time_window
        else:
            self.time_window = timedelta(hours=DEFAULT_TIME_WINDOW_HOURS)

        try:
            self.session = self._create_session()
            self.parent_process_parser = ParentProcessParser()
        except LogRhythmValidationError:
            raise
        except Exception as e:
            raise LogRhythmSessionError(f"Failed to create HTTP session: {e}") from e

        self.logger.info(f"{LOG_PREFIX} LogRhythm API client initialized")

    def _create_session(self) -> requests.Session:
        """Create an HTTP session with bearer-token or basic authentication.

        Returns:
            Configured requests.Session with authentication.

        Raises:
            LogRhythmValidationError: If no authentication is configured.

        """
        session = requests.Session()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password:
            session.auth = (self.username, self.password)
        else:
            raise LogRhythmValidationError(
                "Either a token or a username/password pair is required"
            )
        session.headers.update(headers)
        session.verify = self.verify_ssl
        return session

    def fetch_signatures(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> list[LogRhythmAlert]:
        """Fetch LogRhythm events based on search signatures.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.

        Returns:
            List of LogRhythmAlert objects.

        Raises:
            LogRhythmValidationError: If inputs are invalid.
            LogRhythmAPIError: If API operations fail.

        """
        self._validate_inputs(search_signatures, expectation_type)
        search_criteria = self._build_search_criteria(search_signatures)
        return self._execute_query_with_retry(search_criteria)

    def fetch_with_retry(
        self,
        search_signatures: list[dict[str, Any]],
        expectation_type: str,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[LogRhythmAlert]:
        """Fetch LogRhythm events with a retry mechanism.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).

        Returns:
            List of LogRhythmAlert objects.

        Raises:
            LogRhythmValidationError: If inputs are invalid.
            LogRhythmAPIError: If all retry attempts fail.

        """
        self._validate_inputs(search_signatures, expectation_type)
        search_criteria = self._build_search_criteria(search_signatures)
        return self._execute_query_with_retry(
            search_criteria,
            max_retries=max_retries if max_retries is not None else self.max_retry,
            offset_seconds=(
                offset_seconds if offset_seconds is not None else int(self.offset)
            ),
        )

    def _validate_inputs(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> None:
        """Validate fetch inputs.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation.

        Raises:
            LogRhythmValidationError: If inputs are invalid.

        """
        if not search_signatures:
            raise LogRhythmValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise LogRhythmValidationError(
                f"Invalid expectation_type: {expectation_type}. LogRhythm only supports 'detection'"
            )

    def _build_search_criteria(
        self, search_signatures: list[dict[str, str]]
    ) -> LogRhythmSearchCriteria:
        """Build a LogRhythmSearchCriteria object from search signatures.

        Args:
            search_signatures: List of signature dictionaries.

        Returns:
            LogRhythmSearchCriteria object.

        Raises:
            LogRhythmValidationError: If signature format is invalid.

        """
        source_ips = []
        target_ips = []
        parent_process_names = []
        start_date = None
        end_date = None

        for sig in search_signatures:
            if not isinstance(sig, dict) or "type" not in sig or "value" not in sig:
                raise LogRhythmValidationError(f"Invalid signature format: {sig}")

            sig_type = sig.get("type")
            sig_value = sig.get("value")

            if sig_type in ["source_ipv4_address", "source_ipv6_address"]:
                source_ips.append(sig_value)
            elif sig_type in ["target_ipv4_address", "target_ipv6_address"]:
                target_ips.append(sig_value)
            elif sig_type == "parent_process_name":
                parent_process_names.append(sig_value)
            elif sig_type == "start_date":
                start_date = sig_value
            elif sig_type == "end_date":
                end_date = sig_value

        return LogRhythmSearchCriteria(
            source_ips=source_ips,
            target_ips=target_ips,
            parent_process_names=parent_process_names,
            start_date=start_date,
            end_date=end_date,
        )

    def _build_filter_item(self, filter_type: int, values: list[str]) -> dict[str, Any]:
        """Build a single LogRhythm filter item for a field and its values.

        Args:
            filter_type: The LogRhythm field id (LogQueryFilterTypeEnum).
            values: The values to match (combined with OR).

        Returns:
            A filter item dictionary.

        """
        return {
            "filterItemType": 0,
            "fieldOperator": 0,
            "filterMode": 1,
            "filterType": filter_type,
            "values": [
                {
                    "filterType": filter_type,
                    "valueType": VALUE_TYPE_STRING,
                    "value": {"value": value, "matchType": 0},
                }
                for value in values
            ],
        }

    def _build_query_body(
        self, search_criteria: LogRhythmSearchCriteria, extend_end_seconds: int = 0
    ) -> dict[str, Any]:
        """Build a Search API search-task request body from search criteria.

        Args:
            search_criteria: LogRhythmSearchCriteria object.
            extend_end_seconds: Optional seconds to widen the time window on retries.

        Returns:
            The search-task request body.

        """
        filter_items: list[dict[str, Any]] = []
        if search_criteria.source_ips:
            filter_items.append(
                self._build_filter_item(SIP_FILTER_TYPE, search_criteria.source_ips)
            )
        if search_criteria.target_ips:
            filter_items.append(
                self._build_filter_item(DIP_FILTER_TYPE, search_criteria.target_ips)
            )

        url_values = []
        for parent_process_name in search_criteria.parent_process_names or []:
            uuids = self.parent_process_parser.extract_uuids_from_parent_process_name(
                parent_process_name
            )
            if uuids:
                inject_uuid, agent_uuid = uuids
                url_values.append(
                    f"/api/injects/{inject_uuid}/{agent_uuid}/executable-payload"
                )
        if url_values:
            filter_items.append(self._build_filter_item(URL_FILTER_TYPE, url_values))

        window_seconds = int(self.time_window.total_seconds()) + extend_end_seconds
        minutes = max(1, window_seconds // 60)

        return {
            "maxMsgsToQuery": self.max_msgs,
            "queryTimeout": int(self.search_timeout),
            "queryRawLog": True,
            "queryEventManager": self.query_event_manager,
            "dateCriteria": {
                "useInsertedDate": False,
                "lastIntervalValue": minutes,
                "lastIntervalUnit": LAST_INTERVAL_UNIT_MINUTES,
            },
            "queryFilter": {
                "msgFilterType": MSG_FILTER_TYPE,
                "isSavedFilter": False,
                "filterGroup": {
                    "filterItemType": 1,
                    "fieldOperator": 1,
                    "filterMode": 1,
                    "filterGroupOperator": FILTER_GROUP_OPERATOR_OR,
                    "filterItems": filter_items,
                },
            },
        }

    def _execute_query(
        self, search_criteria: LogRhythmSearchCriteria, extend_end_seconds: int = 0
    ) -> list[LogRhythmAlert]:
        """Execute a single search (create task, poll results).

        Args:
            search_criteria: LogRhythmSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to widen the time window for retries.

        Returns:
            List of LogRhythmAlert objects.

        Raises:
            LogRhythmAuthenticationError: If authentication fails.
            LogRhythmAPIError: If the API call fails.
            LogRhythmNetworkError: If a network error occurs.
            LogRhythmTimeoutError: If the search does not complete in time.
            LogRhythmQueryError: If query execution fails unexpectedly.

        """
        try:
            body = self._build_query_body(search_criteria, extend_end_seconds)
            task_id = self._create_search(body)
            return self._wait_and_get_results(task_id)
        except (
            LogRhythmAuthenticationError,
            LogRhythmAPIError,
            LogRhythmTimeoutError,
        ):
            raise
        except (ConnectionError, Timeout) as e:
            raise LogRhythmNetworkError(f"Network error during query: {e}") from e
        except RequestException as e:
            raise LogRhythmAPIError(f"HTTP request failed during query: {e}") from e
        except Exception as e:
            raise LogRhythmQueryError(f"Unexpected error executing query: {e}") from e

    def _create_search(self, body: dict[str, Any]) -> str:
        """Create a search task and return its identifier.

        Args:
            body: The search-task request body.

        Returns:
            The search TaskId.

        """
        endpoint = f"{self.base_url}/lr-search-api/actions/search-task"
        response = self.session.post(
            endpoint, json=body, timeout=REQUEST_TIMEOUT_SECONDS
        )
        self._check_response(response)
        data = response.json()
        task_id = data.get("TaskId") or data.get("taskId")
        if not task_id:
            raise LogRhythmQueryError("LogRhythm did not return a TaskId")
        return str(task_id)

    def _wait_and_get_results(self, task_id: str) -> list[LogRhythmAlert]:
        """Poll the search-result endpoint until the task completes.

        Args:
            task_id: The search TaskId.

        Returns:
            List of LogRhythmAlert objects.

        Raises:
            LogRhythmQueryError: If the search ends in an error state.
            LogRhythmTimeoutError: If the search does not complete in time.

        """
        endpoint = f"{self.base_url}/lr-search-api/actions/search-result"
        payload = {
            "TaskId": task_id,
            "PagedCriteria": {"PageNumber": 1, "PageSize": self.max_msgs},
        }
        deadline = time.monotonic() + self.search_timeout

        while time.monotonic() < deadline:
            response = self.session.post(
                endpoint, json=payload, timeout=REQUEST_TIMEOUT_SECONDS
            )
            self._check_response(response)
            data = response.json()
            status = str(data.get("TaskStatus") or data.get("taskStatus") or "")
            if status.lower() == "completed":
                return LogRhythmResponse.from_raw_response(data).results
            if status.lower() in ("failed", "error", "cancelled", "canceled"):
                raise LogRhythmQueryError(
                    f"LogRhythm search task ended with status {status}"
                )
            time.sleep(self.poll_interval)

        raise LogRhythmTimeoutError(
            f"LogRhythm search task did not complete within {self.search_timeout}s"
        )

    def _check_response(self, response: Any) -> None:
        """Validate an HTTP response status code.

        Args:
            response: The HTTP response to validate.

        Raises:
            LogRhythmAuthenticationError: If the response is a 401.
            LogRhythmAPIError: If the response is not a success status.

        """
        if response.status_code == 401:
            raise LogRhythmAuthenticationError("Authentication with LogRhythm failed")
        if response.status_code not in (200, 201):
            raise LogRhythmAPIError(
                f"LogRhythm API returned status {response.status_code}: {response.text}"
            )

    def _execute_query_with_retry(
        self,
        search_criteria: LogRhythmSearchCriteria,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[LogRhythmAlert]:
        """Execute a search with a retry mechanism.

        Args:
            search_criteria: LogRhythmSearchCriteria object with search parameters.
            max_retries: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retries.

        Returns:
            List of LogRhythmAlert objects (empty if none found after all retries).

        Raises:
            LogRhythmAPIError: If all attempts fail with an error.

        """
        retries = max_retries if max_retries is not None else self.max_retry
        offset = offset_seconds if offset_seconds is not None else int(self.offset)

        last_exception: Exception | None = None

        for attempt in range(retries + 1):
            try:
                if attempt > 0:
                    time.sleep(offset)
                    extend_seconds = offset * attempt
                else:
                    extend_seconds = 0

                alerts = self._execute_query(search_criteria, extend_seconds)
                if alerts:
                    self.logger.info(
                        f"{LOG_PREFIX} Attempt {attempt + 1}: found {len(alerts)} events"
                    )
                    return alerts
                if attempt == retries:
                    self.logger.warning(
                        f"{LOG_PREFIX} No events found after all retry attempts"
                    )
                    return []
            except (LogRhythmAuthenticationError, LogRhythmValidationError):
                raise
            except (
                LogRhythmAPIError,
                LogRhythmNetworkError,
                LogRhythmQueryError,
                LogRhythmTimeoutError,
                ConnectionError,
                Timeout,
                RequestException,
            ) as e:
                last_exception = e
                self.logger.warning(f"{LOG_PREFIX} Attempt {attempt + 1} failed: {e}")
                if attempt == retries:
                    break

        if last_exception:
            raise LogRhythmAPIError(
                f"All LogRhythm fetch attempts failed. Last error: {last_exception}"
            ) from last_exception
        return []
