"""NetWitness API client for querying the Core SDK with NWQL."""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests  # type: ignore[import-untyped]
from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError,
    RequestException,
    Timeout,
)

from ..models.configs.config_loader import ConfigLoader
from .exception import (
    NetWitnessAPIError,
    NetWitnessAuthenticationError,
    NetWitnessNetworkError,
    NetWitnessQueryError,
    NetWitnessSessionError,
    NetWitnessValidationError,
)
from .models import NetWitnessAlert, NetWitnessResponse, NetWitnessSearchCriteria
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[NetWitnessClientAPI]"

DEFAULT_TIME_WINDOW_HOURS = 1
REQUEST_TIMEOUT_SECONDS = 60
NW_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class NetWitnessClientAPI:
    """NetWitness API client for fetching sessions via the Core SDK query API."""

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the NetWitness API client.

        Args:
            config: Configuration loader instance for API client settings.

        Raises:
            NetWitnessValidationError: If config is None or has invalid structure.
            NetWitnessSessionError: If session creation fails.

        """
        if config is None:
            raise NetWitnessValidationError("Config is required for API client")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.base_url = str(self.config.netwitness.base_url).rstrip("/")
            self.token = (
                self.config.netwitness.token.get_secret_value()
                if self.config.netwitness.token
                else None
            )
            self.username = self.config.netwitness.username
            self.password = (
                self.config.netwitness.password.get_secret_value()
                if self.config.netwitness.password
                else None
            )
            self.max_results = self.config.netwitness.max_results
            self.console_url = self.config.netwitness.console_url
            self.offset = self.config.netwitness.offset.total_seconds()
            self.max_retry = self.config.netwitness.max_retry
            self.verify_ssl = self.config.netwitness.verify_ssl
        except AttributeError as e:
            raise NetWitnessValidationError(f"Invalid config structure: {e}") from e

        if (
            hasattr(self.config.netwitness, "time_window")
            and self.config.netwitness.time_window
        ):
            self.time_window = self.config.netwitness.time_window
        else:
            self.time_window = timedelta(hours=DEFAULT_TIME_WINDOW_HOURS)

        try:
            self.session = self._create_session()
            self.parent_process_parser = ParentProcessParser()
        except NetWitnessValidationError:
            raise
        except Exception as e:
            raise NetWitnessSessionError(f"Failed to create HTTP session: {e}") from e

        self.logger.info(f"{LOG_PREFIX} NetWitness API client initialized")

    def _create_session(self) -> requests.Session:
        """Create an HTTP session with basic or bearer-token authentication.

        Returns:
            Configured requests.Session with authentication.

        Raises:
            NetWitnessValidationError: If no authentication is configured.

        """
        session = requests.Session()
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password:
            session.auth = (self.username, self.password)
        else:
            raise NetWitnessValidationError(
                "Either a token or a username/password pair is required"
            )
        session.headers.update(headers)
        session.verify = self.verify_ssl
        return session

    def fetch_signatures(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> list[NetWitnessAlert]:
        """Fetch NetWitness sessions based on search signatures.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.

        Returns:
            List of NetWitnessAlert objects.

        Raises:
            NetWitnessValidationError: If inputs are invalid.
            NetWitnessAPIError: If API operations fail.

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
    ) -> list[NetWitnessAlert]:
        """Fetch NetWitness sessions with a retry mechanism.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).

        Returns:
            List of NetWitnessAlert objects.

        Raises:
            NetWitnessValidationError: If inputs are invalid.
            NetWitnessAPIError: If all retry attempts fail.

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
            NetWitnessValidationError: If inputs are invalid.

        """
        if not search_signatures:
            raise NetWitnessValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise NetWitnessValidationError(
                f"Invalid expectation_type: {expectation_type}. NetWitness only supports 'detection'"
            )

    def _build_search_criteria(
        self, search_signatures: list[dict[str, str]]
    ) -> NetWitnessSearchCriteria:
        """Build a NetWitnessSearchCriteria object from search signatures.

        Args:
            search_signatures: List of signature dictionaries.

        Returns:
            NetWitnessSearchCriteria object.

        Raises:
            NetWitnessValidationError: If signature format is invalid.

        """
        source_ips = []
        target_ips = []
        parent_process_names = []
        start_date = None
        end_date = None

        for sig in search_signatures:
            if not isinstance(sig, dict) or "type" not in sig or "value" not in sig:
                raise NetWitnessValidationError(f"Invalid signature format: {sig}")

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

        return NetWitnessSearchCriteria(
            source_ips=source_ips,
            target_ips=target_ips,
            parent_process_names=parent_process_names,
            start_date=start_date,
            end_date=end_date,
        )

    def _build_query(
        self, search_criteria: NetWitnessSearchCriteria, extend_end_seconds: int = 0
    ) -> str:
        """Build an NWQL query string from search criteria.

        Args:
            search_criteria: NetWitnessSearchCriteria object.
            extend_end_seconds: Optional seconds to widen the time window on retries.

        Returns:
            The NWQL query expression.

        """
        fields = "time,ip.src,ip.dst,url,service,alert"

        conditions: list[str] = []
        for ip in search_criteria.source_ips or []:
            conditions.append(f"ip.src={ip}")
        for ip in search_criteria.target_ips or []:
            conditions.append(f"ip.dst={ip}")
        for parent_process_name in search_criteria.parent_process_names or []:
            uuids = self.parent_process_parser.extract_uuids_from_parent_process_name(
                parent_process_name
            )
            if uuids:
                inject_uuid, agent_uuid = uuids
                path = f"/api/injects/{inject_uuid}/{agent_uuid}/executable-payload"
                conditions.append(f"url contains '{path}'")

        match_clause = " || ".join(conditions) if conditions else "ip.src exists"

        end = datetime.now(timezone.utc)
        window = self.time_window + timedelta(seconds=extend_end_seconds)
        start = end - window
        time_clause = (
            f'time="{start.strftime(NW_TIME_FORMAT)}"'
            f'-"{end.strftime(NW_TIME_FORMAT)}"'
        )

        return f"select {fields} where {time_clause} && ({match_clause})"

    def _execute_query(
        self, search_criteria: NetWitnessSearchCriteria, extend_end_seconds: int = 0
    ) -> list[NetWitnessAlert]:
        """Execute a single NetWitness Core SDK query.

        Args:
            search_criteria: NetWitnessSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to widen the time window for retries.

        Returns:
            List of NetWitnessAlert objects.

        Raises:
            NetWitnessAuthenticationError: If authentication fails.
            NetWitnessAPIError: If the API call fails.
            NetWitnessNetworkError: If a network error occurs.
            NetWitnessQueryError: If query execution fails unexpectedly.

        """
        try:
            query = self._build_query(search_criteria, extend_end_seconds)
            endpoint = f"{self.base_url}/sdk"
            params = {
                "msg": "query",
                "query": query,
                "force-content-type": "application/json",
                "size": self.max_results,
            }
            response = self.session.get(
                endpoint, params=params, timeout=REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code == 401:
                raise NetWitnessAuthenticationError(
                    "Authentication with NetWitness failed"
                )
            if response.status_code != 200:
                raise NetWitnessAPIError(
                    f"NetWitness API returned status {response.status_code}: {response.text}"
                )

            netwitness_response = NetWitnessResponse.from_raw_response(response.json())
            self.logger.info(
                f"{LOG_PREFIX} Retrieved {len(netwitness_response.results)} sessions"
            )
            return netwitness_response.results

        except (NetWitnessAuthenticationError, NetWitnessAPIError):
            raise
        except (ConnectionError, Timeout) as e:
            raise NetWitnessNetworkError(f"Network error during query: {e}") from e
        except RequestException as e:
            raise NetWitnessAPIError(f"HTTP request failed during query: {e}") from e
        except Exception as e:
            raise NetWitnessQueryError(f"Unexpected error executing query: {e}") from e

    def _execute_query_with_retry(
        self,
        search_criteria: NetWitnessSearchCriteria,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[NetWitnessAlert]:
        """Execute a NetWitness query with a retry mechanism.

        Args:
            search_criteria: NetWitnessSearchCriteria object with search parameters.
            max_retries: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retries.

        Returns:
            List of NetWitnessAlert objects (empty if none found after all retries).

        Raises:
            NetWitnessAPIError: If all attempts fail with an error.

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
                        f"{LOG_PREFIX} Attempt {attempt + 1}: found {len(alerts)} sessions"
                    )
                    return alerts
                if attempt == retries:
                    self.logger.warning(
                        f"{LOG_PREFIX} No sessions found after all retry attempts"
                    )
                    return []
            except (NetWitnessAuthenticationError, NetWitnessValidationError):
                raise
            except (
                NetWitnessAPIError,
                NetWitnessNetworkError,
                NetWitnessQueryError,
                ConnectionError,
                Timeout,
                RequestException,
            ) as e:
                last_exception = e
                self.logger.warning(f"{LOG_PREFIX} Attempt {attempt + 1} failed: {e}")
                if attempt == retries:
                    break

        if last_exception:
            raise NetWitnessAPIError(
                f"All NetWitness fetch attempts failed. Last error: {last_exception}"
            ) from last_exception
        return []
