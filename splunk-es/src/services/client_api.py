"""Splunk ES API client for making HTTP requests with proper error handling."""

import logging
import time
from datetime import timedelta
from typing import Any

import requests  # type: ignore[import-untyped]
from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError, RequestException, Timeout)

from ..models.configs.config_loader import ConfigLoader
from .exception import (SplunkESAPIError, SplunkESAuthenticationError,
                        SplunkESNetworkError, SplunkESQueryError,
                        SplunkESSessionError, SplunkESValidationError)
from .models import SplunkESAlert, SplunkESResponse, SplunkESSearchCriteria
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[SplunkESClientAPI]"


DEFAULT_TIME_WINDOW_HOURS = 1
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3


class SplunkESClientAPI:
    """Splunk ES API client for fetching alerts and data."""

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the Splunk ES API client.

        Args:
            config: Configuration loader instance for API client settings.

        Raises:
            SplunkESValidationError: If config is None or has invalid structure.
            SplunkESSessionError: If session creation fails.

        """
        if config is None:
            raise SplunkESValidationError("Config is required for API client")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.base_url = str(self.config.splunk_es.base_url).rstrip("/")
            self.username = self.config.splunk_es.username
            self.password = self.config.splunk_es.password.get_secret_value()
            self.alerts_index = self.config.splunk_es.alerts_index or "_notable"
            self.offset = self.config.splunk_es.offset.total_seconds()
            self.max_retry = self.config.splunk_es.max_retry
        except AttributeError as e:
            raise SplunkESValidationError(f"Invalid config structure: {e}") from e

        if (
            hasattr(self.config.splunk_es, "time_window")
            and self.config.splunk_es.time_window
        ):
            self.time_window = self.config.splunk_es.time_window
        else:
            self.time_window = timedelta(hours=DEFAULT_TIME_WINDOW_HOURS)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default {DEFAULT_TIME_WINDOW_HOURS} hour"
            )

        try:
            self.session = self._create_session()
            self.parent_process_parser = ParentProcessParser()
        except Exception as e:
            raise SplunkESSessionError(f"Failed to create HTTP session: {e}") from e

        self.logger.info(f"{LOG_PREFIX} Splunk ES API client initialized successfully")

    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper authentication.

        Returns:
            Configured requests.Session with authentication.

        Raises:
            SplunkESValidationError: If credentials are missing.
            SplunkESSessionError: If session configuration fails.

        """
        if not self.username or not self.password:
            raise SplunkESValidationError(
                "Username and password are required for session creation"
            )

        try:
            session = requests.Session()
            session.auth = (self.username, self.password)
            session.headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                }
            )
            session.timeout = REQUEST_TIMEOUT_SECONDS
            session.verify = False
            return session
        except Exception as e:
            raise SplunkESSessionError(f"Failed to configure session: {e}") from e

    def fetch_signatures(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> list[SplunkESAlert]:
        """Fetch Splunk ES alerts based on search signatures.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If inputs are invalid.
            SplunkESAPIError: If API operations fail.

        """
        if not search_signatures:
            raise SplunkESValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise SplunkESValidationError(
                f"Invalid expectation_type: {expectation_type}. Splunk ES only supports 'detection'"
            )

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching signatures for {expectation_type} expectation with {len(search_signatures)} signatures"
            )

            search_criteria = self._build_search_criteria(search_signatures)

            self.logger.debug(f"{LOG_PREFIX} Executing Splunk ES query with retry...")
            alerts = self._execute_splunk_query_with_retry(search_criteria)

            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(alerts)} alerts from Splunk ES"
            )
            return alerts

        except (SplunkESValidationError, SplunkESAPIError, SplunkESAuthenticationError):
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SplunkESAPIError(f"Unexpected error fetching signatures: {e}") from e

    def _build_search_criteria(
        self, search_signatures: list[dict[str, str]]
    ) -> SplunkESSearchCriteria:
        """Build SplunkESSearchCriteria object from search signatures.

        Args:
            search_signatures: List of signature dictionaries.

        Returns:
            SplunkESSearchCriteria object.

        Raises:
            SplunkESValidationError: If signature format is invalid.

        """
        try:
            self.logger.debug(
                f"{LOG_PREFIX} Building search criteria from {len(search_signatures)} signatures"
            )

            source_ips = []
            target_ips = []
            parent_process_names = []
            start_date = None
            end_date = None

            for sig in search_signatures:
                if not isinstance(sig, dict) or "type" not in sig or "value" not in sig:
                    raise SplunkESValidationError(f"Invalid signature format: {sig}")

                sig_type = sig.get("type")
                sig_value = sig.get("value")
                self.logger.debug(
                    f"{LOG_PREFIX} Processing signature: {sig_type}={sig_value}"
                )

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

            if not start_date and not end_date:
                self.logger.info(
                    f"{LOG_PREFIX} No date signatures provided, will use time_window in query: {self.time_window}"
                )

            criteria = SplunkESSearchCriteria(
                source_ips=source_ips,
                target_ips=target_ips,
                parent_process_names=parent_process_names,
                start_date=start_date,
                end_date=end_date,
            )

            self.logger.debug(
                f"{LOG_PREFIX} Built search criteria: source_ips={len(source_ips)}, target_ips={len(target_ips)}, "
                f"parent_process_names={len(parent_process_names)}, date_range={start_date} to {end_date}"
            )
            return criteria

        except SplunkESValidationError:
            raise
        except Exception as e:
            raise SplunkESValidationError(
                f"Failed to build search criteria: {e}"
            ) from e

    def _execute_splunk_query(
        self, search_criteria: SplunkESSearchCriteria, extend_end_seconds: int = 0
    ) -> list[SplunkESAlert]:
        """Execute Splunk ES query based on search criteria.

        Args:
            search_criteria: SplunkESSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If search criteria is invalid.
            SplunkESQueryError: If query execution fails.
            SplunkESAuthenticationError: If authentication fails.
            SplunkESAPIError: If API call fails.

        """
        if not search_criteria:
            raise SplunkESValidationError("search_criteria cannot be None")

        try:
            spl_query = self._build_spl_query(search_criteria, extend_end_seconds)

            self.logger.debug(f"{LOG_PREFIX} Executing SPL query: {spl_query}")

            endpoint = f"{self.base_url}/services/search/jobs"

            params = {
                "search": f"search {spl_query}",
                "exec_mode": "oneshot",
                "output_mode": "json",
                "count": "0",
            }

            response = self.session.post(
                endpoint, data=params, timeout=REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code == 401:
                raise SplunkESAuthenticationError(
                    "Authentication with Splunk ES failed"
                )
            elif response.status_code != 200:
                raise SplunkESAPIError(
                    f"Splunk ES API returned status {response.status_code}: {response.text}"
                )

            response_data = response.json()
            splunk_response = SplunkESResponse.from_raw_response(response_data)

            self.logger.info(
                f"{LOG_PREFIX} Retrieved {len(splunk_response.results)} alerts from Splunk ES"
            )
            return splunk_response.results

        except (
            SplunkESValidationError,
            SplunkESQueryError,
            SplunkESAuthenticationError,
            SplunkESAPIError,
        ):
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during query: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed during query: {e}") from e
        except Exception as e:
            raise SplunkESQueryError(f"Unexpected error executing query: {e}") from e

    def _execute_splunk_query_with_retry(
        self, search_criteria: SplunkESSearchCriteria
    ) -> list[SplunkESAlert]:
        """Execute Splunk ES query with retry mechanism.

        Args:
            search_criteria: SplunkESSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If search criteria is invalid.
            SplunkESQueryError: If query execution fails after all retries.
            SplunkESAuthenticationError: If authentication fails.
            SplunkESAPIError: If API call fails after all retries.

        """
        if not search_criteria:
            raise SplunkESValidationError("search_criteria cannot be None")

        self.logger.info(
            f"{LOG_PREFIX} Starting Splunk ES fetch with {self.offset}s offset and {self.max_retry} max retries"
        )

        last_exception = None

        for attempt in range(self.max_retry + 1):
            try:
                self.logger.debug(
                    f"{LOG_PREFIX} Splunk ES query attempt {attempt + 1} of {self.max_retry + 1}"
                )

                if attempt > 0:
                    sleep_time = int(self.offset)
                    self.logger.debug(
                        f"{LOG_PREFIX} Waiting {sleep_time}s before retry {attempt + 1}..."
                    )
                    time.sleep(sleep_time)
                    extend_seconds = sleep_time * attempt
                else:
                    extend_seconds = 0

                alerts = self._execute_splunk_query(search_criteria, extend_seconds)

                if alerts:
                    self.logger.info(
                        f"{LOG_PREFIX} Splunk ES attempt {attempt + 1}: Found {len(alerts)} alerts - success!"
                    )
                    return alerts
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} Splunk ES attempt {attempt + 1}: No alerts found"
                    )
                    if attempt == self.max_retry:
                        self.logger.warning(
                            f"{LOG_PREFIX} No alerts found after all retry attempts"
                        )
                        return []

            except (SplunkESAuthenticationError, SplunkESValidationError) as e:
                raise e
            except (
                SplunkESAPIError,
                SplunkESNetworkError,
                SplunkESQueryError,
                ConnectionError,
                Timeout,
                RequestException,
            ) as e:
                last_exception = e
                self.logger.warning(
                    f"{LOG_PREFIX} Splunk ES attempt {attempt + 1} failed: {e}"
                )
                if attempt == self.max_retry:
                    break

        if last_exception:
            raise SplunkESAPIError(
                f"All Splunk ES fetch attempts failed. Last error: {last_exception}"
            ) from last_exception
        else:
            self.logger.warning(
                f"{LOG_PREFIX} No alerts found after all retry attempts"
            )
            return []

    def fetch_with_retry(
        self,
        search_signatures: list[dict[str, Any]],
        expectation_type: str,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[SplunkESAlert]:
        """Fetch Splunk ES alerts with retry mechanism.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If inputs are invalid.
            SplunkESAPIError: If all retry attempts fail.

        """
        if not search_signatures:
            raise SplunkESValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise SplunkESValidationError(
                f"Invalid expectation_type: {expectation_type}. Splunk ES only supports 'detection'"
            )

        if max_retries is None:
            max_retries = self.max_retry
        if offset_seconds is None:
            offset_seconds = int(self.offset)

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting fetch with retry: max_retries={max_retries}, offset={offset_seconds}s"
            )

            search_criteria = self._build_search_criteria(search_signatures)

            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    self.logger.debug(
                        f"{LOG_PREFIX} Fetch attempt {attempt + 1} of {max_retries + 1}"
                    )

                    if attempt > 0:
                        self.logger.debug(
                            f"{LOG_PREFIX} Waiting {offset_seconds}s before retry {attempt + 1}..."
                        )
                        time.sleep(offset_seconds)
                        extend_seconds = offset_seconds * attempt
                    else:
                        extend_seconds = 0

                    alerts = self._execute_splunk_query(search_criteria, extend_seconds)

                    if alerts:
                        self.logger.info(
                            f"{LOG_PREFIX} Fetch attempt {attempt + 1}: Found {len(alerts)} alerts - success!"
                        )
                        return alerts
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Fetch attempt {attempt + 1}: No alerts found"
                        )

                except (SplunkESAuthenticationError, SplunkESValidationError) as e:
                    raise e
                except (
                    SplunkESAPIError,
                    SplunkESNetworkError,
                    SplunkESQueryError,
                    ConnectionError,
                    Timeout,
                    RequestException,
                ) as e:
                    last_exception = e
                    self.logger.warning(
                        f"{LOG_PREFIX} Fetch attempt {attempt + 1} failed: {e}"
                    )

            if last_exception:
                raise SplunkESAPIError(
                    f"All fetch attempts failed. Last error: {last_exception}"
                ) from last_exception
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} No alerts found after all retry attempts"
                )
                return []

        except (SplunkESValidationError, SplunkESAPIError, SplunkESAuthenticationError):
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SplunkESAPIError(f"Unexpected error in fetch_with_retry: {e}") from e

    def _build_spl_query(
        self, search_criteria: SplunkESSearchCriteria, extend_end_seconds: int = 0
    ) -> str:
        """Build SPL query from search criteria.

        Args:
            search_criteria: SplunkESSearchCriteria object.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            SPL query string.

        Raises:
            SplunkESValidationError: If criteria is invalid.

        """
        try:
            query_parts = []

            if self.alerts_index:
                query_parts.append(f"index={self.alerts_index}")

            and_conditions = []
            ip_conditions = []

            if search_criteria.source_ips:
                src_fields = ["src_ip", "src", "source_ip", "client_ip"]
                src_parts = []
                for ip in search_criteria.source_ips:
                    for field in src_fields:
                        src_parts.append(f"{field}={ip}")
                if src_parts:
                    ip_conditions.extend(src_parts)

            if search_criteria.target_ips:
                dst_fields = [
                    "dst_ip",
                    "dest",
                    "dest_ip",
                    "destination_ip",
                    "server_ip",
                ]
                dst_parts = []
                for ip in search_criteria.target_ips:
                    for field in dst_fields:
                        dst_parts.append(f"{field}={ip}")
                if dst_parts:
                    ip_conditions.extend(dst_parts)

            if ip_conditions:
                and_conditions.append(f"({' OR '.join(ip_conditions)})")

            url_path_conditions = []
            if search_criteria.parent_process_names:
                for parent_process_name in search_criteria.parent_process_names:
                    uuids = self.parent_process_parser.extract_uuids_from_parent_process_name(
                        parent_process_name
                    )
                    if uuids:
                        inject_uuid, agent_uuid = uuids
                        url_path_query = (
                            self.parent_process_parser.build_url_path_search_query(
                                inject_uuid, agent_uuid
                            )
                        )
                        if url_path_query:
                            url_path_conditions.append(url_path_query)
                            self.logger.debug(
                                f"{LOG_PREFIX} Added URL path condition for parent process: {url_path_query}"
                            )

            if url_path_conditions:
                and_conditions.append(f"({' OR '.join(url_path_conditions)})")

            if and_conditions:
                query_parts.append(f"({' AND '.join(and_conditions)})")

            time_window_seconds = int(self.time_window.total_seconds())
            earliest_seconds = time_window_seconds + extend_end_seconds
            query_parts.append(f"earliest=-{earliest_seconds}s")
            self.logger.debug(
                f"{LOG_PREFIX} Using time window: -{earliest_seconds}s (base: {time_window_seconds}s + extend: {extend_end_seconds}s)"
            )

            if query_parts:
                base_query = " ".join(query_parts)
            else:
                base_query = f"index={self.alerts_index}" if self.alerts_index else "*"

            full_query = (
                f"{base_query} | table _time, src_ip, src, source_ip, client_ip, "
                f"dst_ip, dest, dest_ip, destination_ip, server_ip, signature, "
                f"rule_name, event_type, severity, url_path, url, path, query, _raw | sort -_time"
            )

            self.logger.debug(f"{LOG_PREFIX} Built SPL query: {full_query}")
            return full_query

        except Exception as e:
            raise SplunkESValidationError(f"Failed to build SPL query: {e}") from e
