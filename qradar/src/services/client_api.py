"""IBM QRadar API client for running Ariel (AQL) searches."""

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
    QRadarAPIError,
    QRadarAuthenticationError,
    QRadarNetworkError,
    QRadarQueryError,
    QRadarSessionError,
    QRadarTimeoutError,
    QRadarValidationError,
)
from .models import QRadarAlert, QRadarResponse, QRadarSearchCriteria
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[QRadarClientAPI]"

DEFAULT_TIME_WINDOW_HOURS = 1
REQUEST_TIMEOUT_SECONDS = 60
MAX_RESULTS = 100


class QRadarClientAPI:
    """IBM QRadar API client for fetching events via Ariel (AQL) searches."""

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the IBM QRadar API client.

        Args:
            config: Configuration loader instance for API client settings.

        Raises:
            QRadarValidationError: If config is None or has invalid structure.
            QRadarSessionError: If session creation fails.

        """
        if config is None:
            raise QRadarValidationError("Config is required for API client")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.base_url = str(self.config.qradar.base_url).rstrip("/")
            self.token = (
                self.config.qradar.token.get_secret_value()
                if self.config.qradar.token
                else None
            )
            self.username = self.config.qradar.username
            self.password = (
                self.config.qradar.password.get_secret_value()
                if self.config.qradar.password
                else None
            )
            self.api_version = self.config.qradar.api_version
            self.data_source = self.config.qradar.data_source or "events"
            self.console_url = self.config.qradar.console_url
            self.offset = self.config.qradar.offset.total_seconds()
            self.max_retry = self.config.qradar.max_retry
            self.verify_ssl = self.config.qradar.verify_ssl
            self.search_timeout = self.config.qradar.search_timeout.total_seconds()
            self.poll_interval = self.config.qradar.poll_interval.total_seconds()
        except AttributeError as e:
            raise QRadarValidationError(f"Invalid config structure: {e}") from e

        if (
            hasattr(self.config.qradar, "time_window")
            and self.config.qradar.time_window
        ):
            self.time_window = self.config.qradar.time_window
        else:
            self.time_window = timedelta(hours=DEFAULT_TIME_WINDOW_HOURS)

        try:
            self.session = self._create_session()
            self.parent_process_parser = ParentProcessParser()
        except QRadarValidationError:
            raise
        except Exception as e:
            raise QRadarSessionError(f"Failed to create HTTP session: {e}") from e

        self.logger.info(f"{LOG_PREFIX} IBM QRadar API client initialized")

    def _create_session(self) -> requests.Session:
        """Create an HTTP session with SEC-token or basic authentication.

        Returns:
            Configured requests.Session with authentication and version headers.

        Raises:
            QRadarValidationError: If no authentication is configured.

        """
        session = requests.Session()
        headers = {
            "Accept": "application/json",
            "Version": self.api_version,
        }
        if self.token:
            headers["SEC"] = self.token
        elif self.username and self.password:
            session.auth = (self.username, self.password)
        else:
            raise QRadarValidationError(
                "Either a token or a username/password pair is required"
            )
        session.headers.update(headers)
        session.verify = self.verify_ssl
        return session

    def fetch_signatures(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> list[QRadarAlert]:
        """Fetch IBM QRadar events based on search signatures.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.

        Returns:
            List of QRadarAlert objects.

        Raises:
            QRadarValidationError: If inputs are invalid.
            QRadarAPIError: If API operations fail.

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
    ) -> list[QRadarAlert]:
        """Fetch IBM QRadar events with a retry mechanism.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).

        Returns:
            List of QRadarAlert objects.

        Raises:
            QRadarValidationError: If inputs are invalid.
            QRadarAPIError: If all retry attempts fail.

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
            QRadarValidationError: If inputs are invalid.

        """
        if not search_signatures:
            raise QRadarValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise QRadarValidationError(
                f"Invalid expectation_type: {expectation_type}. IBM QRadar only supports 'detection'"
            )

    def _build_search_criteria(
        self, search_signatures: list[dict[str, str]]
    ) -> QRadarSearchCriteria:
        """Build a QRadarSearchCriteria object from search signatures.

        Args:
            search_signatures: List of signature dictionaries.

        Returns:
            QRadarSearchCriteria object.

        Raises:
            QRadarValidationError: If signature format is invalid.

        """
        source_ips = []
        target_ips = []
        parent_process_names = []
        start_date = None
        end_date = None

        for sig in search_signatures:
            if not isinstance(sig, dict) or "type" not in sig or "value" not in sig:
                raise QRadarValidationError(f"Invalid signature format: {sig}")

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

        return QRadarSearchCriteria(
            source_ips=source_ips,
            target_ips=target_ips,
            parent_process_names=parent_process_names,
            start_date=start_date,
            end_date=end_date,
        )

    def _build_aql(
        self, search_criteria: QRadarSearchCriteria, extend_end_seconds: int = 0
    ) -> str:
        """Build an Ariel AQL query string from search criteria.

        Args:
            search_criteria: QRadarSearchCriteria object.
            extend_end_seconds: Optional seconds to widen the time window on retries.

        Returns:
            AQL query expression.

        """
        fields = 'sourceip, destinationip, "URL", qidname, categoryname, starttime'

        conditions: list[str] = []
        for ip in search_criteria.source_ips or []:
            conditions.append(f"sourceip='{ip}'")
        for ip in search_criteria.target_ips or []:
            conditions.append(f"destinationip='{ip}'")
        for parent_process_name in search_criteria.parent_process_names or []:
            uuids = self.parent_process_parser.extract_uuids_from_parent_process_name(
                parent_process_name
            )
            if uuids:
                inject_uuid, agent_uuid = uuids
                path = f"/api/injects/{inject_uuid}/{agent_uuid}/executable-payload"
                conditions.append(f"\"URL\" LIKE '%{path}%'")

        where_clause = " OR ".join(conditions) if conditions else "1=1"

        window_seconds = int(self.time_window.total_seconds()) + extend_end_seconds
        minutes = max(1, window_seconds // 60)

        return (
            f"SELECT {fields} FROM {self.data_source} "
            f"WHERE ({where_clause}) LAST {minutes} MINUTES"
        )

    def _execute_query(
        self, search_criteria: QRadarSearchCriteria, extend_end_seconds: int = 0
    ) -> list[QRadarAlert]:
        """Execute a single Ariel search (create, poll, fetch results).

        Args:
            search_criteria: QRadarSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to widen the time window for retries.

        Returns:
            List of QRadarAlert objects.

        Raises:
            QRadarAuthenticationError: If authentication fails.
            QRadarAPIError: If the API call fails.
            QRadarNetworkError: If a network error occurs.
            QRadarTimeoutError: If the search does not complete in time.
            QRadarQueryError: If query execution fails unexpectedly.

        """
        try:
            aql = self._build_aql(search_criteria, extend_end_seconds)
            search_id = self._create_search(aql)
            self._wait_for_search(search_id)
            return self._get_results(search_id)
        except (
            QRadarAuthenticationError,
            QRadarAPIError,
            QRadarTimeoutError,
        ):
            raise
        except (ConnectionError, Timeout) as e:
            raise QRadarNetworkError(f"Network error during query: {e}") from e
        except RequestException as e:
            raise QRadarAPIError(f"HTTP request failed during query: {e}") from e
        except Exception as e:
            raise QRadarQueryError(f"Unexpected error executing query: {e}") from e

    def _create_search(self, aql: str) -> str:
        """Create an Ariel search and return its identifier.

        Args:
            aql: The AQL query expression.

        Returns:
            The Ariel search id.

        """
        endpoint = f"{self.base_url}/api/ariel/searches"
        response = self.session.post(
            endpoint,
            params={"query_expression": aql},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        self._check_response(response)
        search_id = response.json().get("search_id")
        if not search_id:
            raise QRadarQueryError("QRadar did not return a search_id")
        return str(search_id)

    def _wait_for_search(self, search_id: str) -> None:
        """Poll an Ariel search until it completes or times out.

        Args:
            search_id: The Ariel search id.

        Raises:
            QRadarQueryError: If the search ends in an error state.
            QRadarTimeoutError: If the search does not complete in time.

        """
        endpoint = f"{self.base_url}/api/ariel/searches/{search_id}"
        deadline = time.monotonic() + self.search_timeout

        while time.monotonic() < deadline:
            response = self.session.get(endpoint, timeout=REQUEST_TIMEOUT_SECONDS)
            self._check_response(response)
            status = response.json().get("status")
            if status == "COMPLETED":
                return
            if status in ("ERROR", "CANCELED"):
                raise QRadarQueryError(
                    f"Ariel search {search_id} ended with status {status}"
                )
            time.sleep(self.poll_interval)

        raise QRadarTimeoutError(
            f"Ariel search {search_id} did not complete within {self.search_timeout}s"
        )

    def _get_results(self, search_id: str) -> list[QRadarAlert]:
        """Fetch the results of a completed Ariel search.

        Args:
            search_id: The Ariel search id.

        Returns:
            List of QRadarAlert objects.

        """
        endpoint = f"{self.base_url}/api/ariel/searches/{search_id}/results"
        response = self.session.get(
            endpoint,
            headers={"Range": f"items=0-{MAX_RESULTS - 1}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        self._check_response(response)
        qradar_response = QRadarResponse.from_raw_response(
            response.json(), self.data_source
        )
        self.logger.info(
            f"{LOG_PREFIX} Retrieved {len(qradar_response.results)} events"
        )
        return qradar_response.results

    def _check_response(self, response: Any) -> None:
        """Validate an HTTP response status code.

        Args:
            response: The HTTP response to validate.

        Raises:
            QRadarAuthenticationError: If the response is a 401.
            QRadarAPIError: If the response is not a success status.

        """
        if response.status_code == 401:
            raise QRadarAuthenticationError("Authentication with QRadar failed")
        if response.status_code not in (200, 201):
            raise QRadarAPIError(
                f"QRadar API returned status {response.status_code}: {response.text}"
            )

    def _execute_query_with_retry(
        self,
        search_criteria: QRadarSearchCriteria,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[QRadarAlert]:
        """Execute an Ariel search with a retry mechanism.

        Args:
            search_criteria: QRadarSearchCriteria object with search parameters.
            max_retries: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retries.

        Returns:
            List of QRadarAlert objects (empty if none found after all retries).

        Raises:
            QRadarAPIError: If all attempts fail with an error.

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
            except (QRadarAuthenticationError, QRadarValidationError):
                raise
            except (
                QRadarAPIError,
                QRadarNetworkError,
                QRadarQueryError,
                QRadarTimeoutError,
                ConnectionError,
                Timeout,
                RequestException,
            ) as e:
                last_exception = e
                self.logger.warning(f"{LOG_PREFIX} Attempt {attempt + 1} failed: {e}")
                if attempt == retries:
                    break

        if last_exception:
            raise QRadarAPIError(
                f"All IBM QRadar fetch attempts failed. Last error: {last_exception}"
            ) from last_exception
        return []
