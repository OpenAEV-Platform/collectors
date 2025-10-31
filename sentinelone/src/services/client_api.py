"""SentinelOne API client for making HTTP requests with proper error handling."""

import logging
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
    SentinelOneAPIError,
    SentinelOneNetworkError,
    SentinelOneSessionError,
    SentinelOneValidationError,
)
from .fetcher_deep_visibility import FetcherDeepVisibility
from .fetcher_threat import FetcherThreat
from .model_deep_visibility import DeepVisibilityEvent, SearchCriteria, utc_now_iso
from .model_threat import SentinelOneThreat

LOG_PREFIX = "[SentinelOneClientAPI]"


DEFAULT_TIME_WINDOW_DAYS = 1
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3


class SentinelOneClientAPI:
    """SentinelOne API client for fetching signatures and data."""

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the SentinelOne API client.

        Args:
            config: Configuration loader instance for API client settings.

        Raises:
            SentinelOneValidationError: If config is None or has invalid structure.
            SentinelOneSessionError: If session creation or fetcher initialization fails.

        """
        if config is None:
            raise SentinelOneValidationError("Config is required for API client")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.base_url = str(self.config.sentinelone.base_url).rstrip("/")
            self.api_key = self.config.sentinelone.api_key.get_secret_value()
            self.offset = self.config.sentinelone.offset.total_seconds()
            self.max_retry = self.config.sentinelone.max_retry
        except AttributeError as e:
            raise SentinelOneValidationError(f"Invalid config structure: {e}") from e

        if (
            hasattr(self.config.sentinelone, "time_window")
            and self.config.sentinelone.time_window
        ):
            self.time_window = self.config.sentinelone.time_window
        else:
            self.time_window = timedelta(days=DEFAULT_TIME_WINDOW_DAYS)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default {DEFAULT_TIME_WINDOW_DAYS} day"
            )

        try:
            self.session = self._create_session()
        except Exception as e:
            raise SentinelOneSessionError(f"Failed to create HTTP session: {e}") from e

        self.logger.debug(
            f"{LOG_PREFIX} Initializing SentinelOne API client components..."
        )
        try:
            self.dv_fetcher = FetcherDeepVisibility(self)
            self.threat_fetcher = FetcherThreat(self)
        except Exception as e:
            raise SentinelOneSessionError(f"Failed to initialize fetchers: {e}") from e

        self.logger.info(
            f"{LOG_PREFIX} SentinelOne API client initialized successfully"
        )

    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper headers.

        Returns:
            Configured requests.Session with authentication headers.

        Raises:
            SentinelOneValidationError: If API key is missing.
            SentinelOneSessionError: If session configuration fails.

        """
        if not self.api_key:
            raise SentinelOneValidationError("API key is required for session creation")

        try:
            session = requests.Session()
            session.headers.update(
                {
                    "Authorization": f"ApiToken {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
            )

            session.timeout = REQUEST_TIMEOUT_SECONDS
            return session
        except Exception as e:
            raise SentinelOneSessionError(f"Failed to configure session: {e}") from e

    def fetch_signatures(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> list[DeepVisibilityEvent | SentinelOneThreat]:
        """Fetch SentinelOne data based on search signatures.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.

        Returns:
            Combined sentinelone_data (dv_events + threats).

        Raises:
            SentinelOneValidationError: If inputs are invalid.
            SentinelOneAPIError: If API operations fail.

        """
        if not search_signatures:
            raise SentinelOneValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection", "prevention"}:
            raise SentinelOneValidationError(
                f"Invalid expectation_type: {expectation_type}"
            )

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching signatures for {expectation_type} expectation with {len(search_signatures)} signatures"
            )

            search_criteria = self._build_search_criteria(search_signatures)

            self.logger.debug(f"{LOG_PREFIX} Fetching Deep Visibility events...")
            dv_events = self.dv_fetcher.fetch_with_retry(
                search_criteria, self.max_retry, int(self.offset)
            )
            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(dv_events)} Deep Visibility events from SentinelOne"
            )

            sentinelone_data = dv_events

            if dv_events:
                self.logger.debug(
                    f"{LOG_PREFIX} Fetching related threats for {expectation_type} expectation..."
                )
                threats = self.threat_fetcher.fetch_with_retry(
                    dv_events, self.max_retry, int(self.offset)
                )
                self.logger.info(
                    f"{LOG_PREFIX} Fetched {len(threats)} threats from SentinelOne"
                )
                sentinelone_data = dv_events + threats  # type: ignore[operator]
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} No Deep Visibility events found, skipping threat fetching"
                )

            self.logger.info(
                f"{LOG_PREFIX} Total SentinelOne data items returned: {len(sentinelone_data)}"
            )
            return sentinelone_data  # type: ignore[return-value]

        except (SentinelOneValidationError, SentinelOneAPIError):
            raise
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SentinelOneAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error fetching signatures: {e}"
            ) from e

    def _build_search_criteria(
        self, search_signatures: list[dict[str, str]]
    ) -> SearchCriteria:
        """Build SearchCriteria object from search signatures.

        Args:
            search_signatures: List of signature dictionaries.

        Returns:
            SearchCriteria object.

        Raises:
            SentinelOneValidationError: If signature format is invalid.

        """
        try:
            self.logger.debug(
                f"{LOG_PREFIX} Building search criteria from {len(search_signatures)} signatures"
            )

            parent_process_name = None
            start_date = None
            end_date = None

            for sig in search_signatures:
                if not isinstance(sig, dict) or "type" not in sig or "value" not in sig:
                    raise SentinelOneValidationError(f"Invalid signature format: {sig}")

                sig_type = sig.get("type")
                sig_value = sig.get("value")
                self.logger.debug(
                    f"{LOG_PREFIX} Processing signature: {sig_type}={sig_value}"
                )

                if sig_type == "parent_process_name":
                    parent_process_name = sig_value
                elif sig_type == "start_date":
                    start_date = sig_value
                elif sig_type == "end_date":
                    end_date = sig_value

            if not start_date and not end_date:
                end_date = utc_now_iso()
                start_date = (datetime.now(timezone.utc) - self.time_window).replace(
                    tzinfo=None
                ).isoformat() + "Z"
                self.logger.info(
                    f"{LOG_PREFIX} No date signatures provided, using default time window: {self.time_window}"
                )
                self.logger.debug(
                    f"{LOG_PREFIX} Date range: {start_date} to {end_date}"
                )

            criteria = SearchCriteria(
                parent_process_name=parent_process_name,
                start_date=start_date,
                to_date=end_date,
            )

            self.logger.debug(
                f"{LOG_PREFIX} Built search criteria: parent_process_name={parent_process_name}, date_range={start_date} to {end_date}"
            )
            return criteria

        except SentinelOneValidationError:
            raise
        except Exception as e:
            raise SentinelOneValidationError(
                f"Failed to build search criteria: {e}"
            ) from e

    def _validate_and_set_retry_defaults(
        self, max_retries: int | None, offset_seconds: int | None
    ) -> tuple[int, int]:
        """Validate and set default values for retry parameters.

        Args:
            max_retries: Maximum number of retry attempts or None for default.
            offset_seconds: Seconds to wait between retries or None for default.

        Returns:
            Tuple of (max_retries, offset_seconds).

        Raises:
            SentinelOneValidationError: If parameters are invalid.

        """
        if max_retries is None:
            max_retries = self.max_retry
        if offset_seconds is None:
            offset_seconds = int(self.offset)

        if max_retries < 0:
            raise SentinelOneValidationError("max_retries cannot be negative")
        if offset_seconds < 0:
            raise SentinelOneValidationError("offset_seconds cannot be negative")

        return max_retries, offset_seconds

    def _fetch_dv_events_with_retry(
        self, search_criteria: SearchCriteria, max_retries: int, offset_seconds: int
    ) -> list[DeepVisibilityEvent]:
        """Fetch Deep Visibility events with retry mechanism.

        Args:
            search_criteria: SearchCriteria object with search parameters.
            max_retries: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retries.

        Returns:
            List of DeepVisibilityEvent objects.

        """
        self.logger.debug(f"{LOG_PREFIX} Fetching Deep Visibility events with retry...")
        return self.dv_fetcher.fetch_with_retry(
            search_criteria, max_retries, offset_seconds
        )

    def _fetch_threats_if_needed(
        self,
        dv_events: list[DeepVisibilityEvent],
        max_retries: int,
        offset_seconds: int,
    ) -> list[SentinelOneThreat]:
        """Fetch threats if Deep Visibility events are available.

        Args:
            dv_events: List of DeepVisibilityEvent objects.
            max_retries: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retries.

        Returns:
            List of SentinelOneThreat objects.

        """
        if dv_events:
            self.logger.debug(f"{LOG_PREFIX} Fetching related threats with retry...")
            return self.threat_fetcher.fetch_with_retry(
                dv_events, max_retries, offset_seconds
            )
        else:
            self.logger.debug(f"{LOG_PREFIX} No Deep Visibility events found")
            return []

    def fetch_with_retry(
        self,
        search_criteria: SearchCriteria,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[DeepVisibilityEvent | SentinelOneThreat]:
        """Fetch SentinelOne data with retry mechanism using dedicated fetchers.

        Args:
            search_criteria: SearchCriteria object with search parameters.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).

        Returns:
            Combined list of DeepVisibilityEvent and SentinelOneThreat objects.

        Raises:
            SentinelOneValidationError: If inputs are invalid.
            SentinelOneAPIError: If all retry attempts fail.

        """
        if search_criteria is None:
            raise SentinelOneValidationError("search_criteria cannot be None")

        try:
            max_retries, offset_seconds = self._validate_and_set_retry_defaults(
                max_retries, offset_seconds
            )

            self.logger.info(
                f"{LOG_PREFIX} Starting fetch with retry: max_retries={max_retries}, offset={offset_seconds}s"
            )

            dv_events = self._fetch_dv_events_with_retry(
                search_criteria, max_retries, offset_seconds
            )

            threats = self._fetch_threats_if_needed(
                dv_events, max_retries, offset_seconds
            )

            sentinelone_data = dv_events + threats

            self.logger.info(
                f"{LOG_PREFIX} Fetch with retry completed: {len(sentinelone_data)} total items"
            )
            return sentinelone_data

        except (SentinelOneValidationError, SentinelOneAPIError):
            raise
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error during retry fetch: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(f"HTTP request failed during retry: {e}") from e
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error in fetch_with_retry: {e}"
            ) from e
