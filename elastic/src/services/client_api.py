"""Elastic Security API client for querying Elasticsearch detection alerts."""

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
    ElasticAPIError,
    ElasticAuthenticationError,
    ElasticNetworkError,
    ElasticQueryError,
    ElasticSessionError,
    ElasticValidationError,
)
from .models import ElasticAlert, ElasticResponse, ElasticSearchCriteria
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[ElasticClientAPI]"

DEFAULT_TIME_WINDOW_HOURS = 1
REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_RESULT_SIZE = 100


class ElasticClientAPI:
    """Elastic Security API client for fetching detection alerts via _search."""

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the Elastic Security API client.

        Args:
            config: Configuration loader instance for API client settings.

        Raises:
            ElasticValidationError: If config is None or has invalid structure.
            ElasticSessionError: If session creation fails.

        """
        if config is None:
            raise ElasticValidationError("Config is required for API client")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.base_url = str(self.config.elastic.base_url).rstrip("/")
            self.api_key = (
                self.config.elastic.api_key.get_secret_value()
                if self.config.elastic.api_key
                else None
            )
            self.username = self.config.elastic.username
            self.password = (
                self.config.elastic.password.get_secret_value()
                if self.config.elastic.password
                else None
            )
            self.alerts_index = (
                self.config.elastic.alerts_index or ".alerts-security.alerts-*"
            )
            self.offset = self.config.elastic.offset.total_seconds()
            self.max_retry = self.config.elastic.max_retry
            self.verify_ssl = self.config.elastic.verify_ssl
        except AttributeError as e:
            raise ElasticValidationError(f"Invalid config structure: {e}") from e

        if (
            hasattr(self.config.elastic, "time_window")
            and self.config.elastic.time_window
        ):
            self.time_window = self.config.elastic.time_window
        else:
            self.time_window = timedelta(hours=DEFAULT_TIME_WINDOW_HOURS)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default {DEFAULT_TIME_WINDOW_HOURS} hour"
            )

        try:
            self.session = self._create_session()
            self.parent_process_parser = ParentProcessParser()
        except ElasticValidationError:
            raise
        except Exception as e:
            raise ElasticSessionError(f"Failed to create HTTP session: {e}") from e

        self.logger.info(f"{LOG_PREFIX} Elastic Security API client initialized")

    def _create_session(self) -> requests.Session:
        """Create an HTTP session with API-key or basic authentication.

        Returns:
            Configured requests.Session with authentication.

        Raises:
            ElasticValidationError: If no authentication is configured.

        """
        session = requests.Session()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.username and self.password:
            session.auth = (self.username, self.password)
        else:
            raise ElasticValidationError(
                "Either an API key or a username/password pair is required"
            )
        session.headers.update(headers)
        session.verify = self.verify_ssl
        return session

    def fetch_signatures(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> list[ElasticAlert]:
        """Fetch Elastic Security alerts based on search signatures.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.

        Returns:
            List of ElasticAlert objects.

        Raises:
            ElasticValidationError: If inputs are invalid.
            ElasticAPIError: If API operations fail.

        """
        if not search_signatures:
            raise ElasticValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise ElasticValidationError(
                f"Invalid expectation_type: {expectation_type}. Elastic Security only supports 'detection'"
            )

        search_criteria = self._build_search_criteria(search_signatures)
        return self._execute_query_with_retry(search_criteria)

    def fetch_with_retry(
        self,
        search_signatures: list[dict[str, Any]],
        expectation_type: str,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[ElasticAlert]:
        """Fetch Elastic Security alerts with a retry mechanism.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).

        Returns:
            List of ElasticAlert objects.

        Raises:
            ElasticValidationError: If inputs are invalid.
            ElasticAPIError: If all retry attempts fail.

        """
        if not search_signatures:
            raise ElasticValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise ElasticValidationError(
                f"Invalid expectation_type: {expectation_type}. Elastic Security only supports 'detection'"
            )

        search_criteria = self._build_search_criteria(search_signatures)
        return self._execute_query_with_retry(
            search_criteria,
            max_retries=max_retries if max_retries is not None else self.max_retry,
            offset_seconds=(
                offset_seconds if offset_seconds is not None else int(self.offset)
            ),
        )

    def _build_search_criteria(
        self, search_signatures: list[dict[str, str]]
    ) -> ElasticSearchCriteria:
        """Build an ElasticSearchCriteria object from search signatures.

        Args:
            search_signatures: List of signature dictionaries.

        Returns:
            ElasticSearchCriteria object.

        Raises:
            ElasticValidationError: If signature format is invalid.

        """
        source_ips = []
        target_ips = []
        parent_process_names = []
        start_date = None
        end_date = None

        for sig in search_signatures:
            if not isinstance(sig, dict) or "type" not in sig or "value" not in sig:
                raise ElasticValidationError(f"Invalid signature format: {sig}")

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

        return ElasticSearchCriteria(
            source_ips=source_ips,
            target_ips=target_ips,
            parent_process_names=parent_process_names,
            start_date=start_date,
            end_date=end_date,
        )

    def _build_query(
        self, search_criteria: ElasticSearchCriteria, extend_end_seconds: int = 0
    ) -> dict[str, Any]:
        """Build an Elasticsearch ``_search`` query body from search criteria.

        Args:
            search_criteria: ElasticSearchCriteria object.
            extend_end_seconds: Optional seconds to widen the time window on retries.

        Returns:
            Elasticsearch query DSL as a dictionary.

        """
        should: list[dict[str, Any]] = []

        if search_criteria.source_ips:
            should.append({"terms": {"source.ip": search_criteria.source_ips}})
        if search_criteria.target_ips:
            should.append({"terms": {"destination.ip": search_criteria.target_ips}})

        for parent_process_name in search_criteria.parent_process_names or []:
            uuids = self.parent_process_parser.extract_uuids_from_parent_process_name(
                parent_process_name
            )
            if uuids:
                inject_uuid, agent_uuid = uuids
                url_path = f"/api/injects/{inject_uuid}/{agent_uuid}/executable-payload"
                should.append({"match_phrase": {"url.path": url_path}})

        window_seconds = int(self.time_window.total_seconds()) + extend_end_seconds
        bool_query: dict[str, Any] = {
            "filter": [{"range": {"@timestamp": {"gte": f"now-{window_seconds}s"}}}]
        }
        if should:
            bool_query["should"] = should
            bool_query["minimum_should_match"] = 1

        return {
            "size": DEFAULT_RESULT_SIZE,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": bool_query},
        }

    def _execute_query(
        self, search_criteria: ElasticSearchCriteria, extend_end_seconds: int = 0
    ) -> list[ElasticAlert]:
        """Execute a single Elasticsearch ``_search`` query.

        Args:
            search_criteria: ElasticSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to widen the time window for retries.

        Returns:
            List of ElasticAlert objects.

        Raises:
            ElasticAuthenticationError: If authentication fails.
            ElasticAPIError: If the API call fails.
            ElasticNetworkError: If a network error occurs.
            ElasticQueryError: If query execution fails unexpectedly.

        """
        try:
            body = self._build_query(search_criteria, extend_end_seconds)
            endpoint = f"{self.base_url}/{self.alerts_index}/_search"

            response = self.session.post(
                endpoint, json=body, timeout=REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code == 401:
                raise ElasticAuthenticationError(
                    "Authentication with Elastic Security failed"
                )
            if response.status_code != 200:
                raise ElasticAPIError(
                    f"Elastic Security API returned status {response.status_code}: {response.text}"
                )

            elastic_response = ElasticResponse.from_raw_response(response.json())
            self.logger.info(
                f"{LOG_PREFIX} Retrieved {len(elastic_response.results)} alerts"
            )
            return elastic_response.results

        except (ElasticAuthenticationError, ElasticAPIError):
            raise
        except (ConnectionError, Timeout) as e:
            raise ElasticNetworkError(f"Network error during query: {e}") from e
        except RequestException as e:
            raise ElasticAPIError(f"HTTP request failed during query: {e}") from e
        except Exception as e:
            raise ElasticQueryError(f"Unexpected error executing query: {e}") from e

    def _execute_query_with_retry(
        self,
        search_criteria: ElasticSearchCriteria,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[ElasticAlert]:
        """Execute an Elasticsearch query with a retry mechanism.

        Args:
            search_criteria: ElasticSearchCriteria object with search parameters.
            max_retries: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retries.

        Returns:
            List of ElasticAlert objects (empty if none found after all retries).

        Raises:
            ElasticAPIError: If all attempts fail with an error.

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
                        f"{LOG_PREFIX} Attempt {attempt + 1}: found {len(alerts)} alerts"
                    )
                    return alerts
                if attempt == retries:
                    self.logger.warning(
                        f"{LOG_PREFIX} No alerts found after all retry attempts"
                    )
                    return []
            except (ElasticAuthenticationError, ElasticValidationError):
                raise
            except (
                ElasticAPIError,
                ElasticNetworkError,
                ElasticQueryError,
                ConnectionError,
                Timeout,
                RequestException,
            ) as e:
                last_exception = e
                self.logger.warning(f"{LOG_PREFIX} Attempt {attempt + 1} failed: {e}")
                if attempt == retries:
                    break

        if last_exception:
            raise ElasticAPIError(
                f"All Elastic Security fetch attempts failed. Last error: {last_exception}"
            ) from last_exception
        return []
