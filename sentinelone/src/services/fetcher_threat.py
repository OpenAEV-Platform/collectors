"""SentinelOne Threat Fetcher.

This module provides functionality to fetch threat data from SentinelOne
based on Deep Visibility events using real API calls.
"""

import logging
import time
from typing import TYPE_CHECKING

from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError,
    RequestException,
    Timeout,
)

from .exception import (
    SentinelOneAPIError,
    SentinelOneNetworkError,
    SentinelOneValidationError,
)
from .model_deep_visibility import DeepVisibilityEvent
from .model_threat import SentinelOneThreat

if TYPE_CHECKING:
    from .client_api import SentinelOneClientAPI

LOG_PREFIX = "[SentinelOneThreatFetcher]"


SLEEP_RETRY_SECONDS = 30


class FetcherThreat:
    """Fetcher for SentinelOne threat data."""

    def __init__(self, client_api: "SentinelOneClientAPI") -> None:
        """Initialize the Threat fetcher.

        Args:
            client_api: SentinelOne API client instance.

        Raises:
            SentinelOneValidationError: If client_api is None.

        """
        if client_api is None:
            raise SentinelOneValidationError("client_api cannot be None")

        self.logger = logging.getLogger(__name__)
        self.client_api = client_api
        self.logger.debug(f"{LOG_PREFIX} Threat fetcher initialized")

    def fetch(self, dv_events: list[DeepVisibilityEvent]) -> list[SentinelOneThreat]:
        """Fetch threat data based on Deep Visibility events.

        Args:
            dv_events: List of DeepVisibilityEvent objects.

        Returns:
            List of SentinelOneThreat objects.

        Raises:
            SentinelOneValidationError: If input is invalid.
            SentinelOneAPIError: If API operations fail.
            SentinelOneNetworkError: If network errors occur.

        """
        if not dv_events:
            self.logger.debug(
                f"{LOG_PREFIX} No Deep Visibility events provided, returning empty list"
            )
            return []

        if not isinstance(dv_events, list):
            raise SentinelOneValidationError("dv_events must be a list")

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Processing {len(dv_events)} Deep Visibility events for threat data"
            )
            threats = []

            file_hashes = self._extract_file_hashes(dv_events)

            if file_hashes:
                self.logger.debug(
                    f"{LOG_PREFIX} Extracted {len(file_hashes)} unique file hashes"
                )

                for i, file_hash in enumerate(file_hashes, 1):
                    self.logger.debug(
                        f"{LOG_PREFIX} Fetching threats for hash {i}/{len(file_hashes)}: {file_hash}"
                    )
                    threat_data = self._fetch_threats_by_hash(file_hash)
                    if threat_data:
                        self.logger.debug(
                            f"{LOG_PREFIX} Found {len(threat_data)} threats for hash {file_hash}"
                        )
                        threats.extend(threat_data)
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} No threats found for hash {file_hash}"
                        )
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} No file hashes extracted from Deep Visibility events"
                )

            result_count = len(threats)
            self.logger.info(
                f"{LOG_PREFIX} Fetched {result_count} total threats from {len(file_hashes)} hashes"
            )
            return threats

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
        ):
            raise
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SentinelOneAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SentinelOneAPIError(f"Unexpected error in fetch: {e}") from e

    def _extract_file_hashes(self, dv_events: list[DeepVisibilityEvent]) -> list[str]:
        """Extract file hashes from Deep Visibility events.

        Args:
            dv_events: List of DeepVisibilityEvent objects.

        Returns:
            List of unique file hashes.

        """
        try:
            file_hashes = []

            for i, event in enumerate(dv_events):
                if not isinstance(event, DeepVisibilityEvent):
                    self.logger.warning(
                        f"{LOG_PREFIX} Event {i + 1} is not a DeepVisibilityEvent"
                    )
                    continue

                if event.tgt_file_sha1:
                    if event.tgt_file_sha1 not in file_hashes:
                        file_hashes.append(event.tgt_file_sha1)
                        self.logger.debug(
                            f"{LOG_PREFIX} Added hash from event {i + 1}: {event.tgt_file_sha1}"
                        )
                else:
                    self.logger.debug(f"{LOG_PREFIX} Event {i + 1} has no file hash")

            self.logger.debug(
                f"{LOG_PREFIX} Extracted {len(file_hashes)} unique file hashes from {len(dv_events)} DV events"
            )
            return file_hashes

        except Exception as e:
            raise SentinelOneValidationError(
                f"Error extracting file hashes: {e}"
            ) from e

    def _fetch_threats_by_hash(self, file_hash: str) -> list[SentinelOneThreat]:
        """Fetch threats by content hash.

        Args:
            file_hash: SHA1 file hash.

        Returns:
            List of SentinelOneThreat objects.

        """
        if not file_hash:
            raise SentinelOneValidationError("file_hash cannot be empty")

        if not isinstance(file_hash, str):
            raise SentinelOneValidationError("file_hash must be a string")

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching threats for content hash: {file_hash}"
            )
            return self._make_real_threats_query(file_hash)

        except (
            SentinelOneValidationError,
            SentinelOneAPIError,
            SentinelOneNetworkError,
        ):
            raise
        except Exception as e:
            raise SentinelOneAPIError(
                f"Error fetching threats by hash {file_hash}: {e}"
            ) from e

    def _make_real_threats_query(self, file_hash: str) -> list[SentinelOneThreat]:
        """Make real API call to fetch threats by content hash.

        Args:
            file_hash: SHA1 file hash to search for.

        Returns:
            List of SentinelOneThreat objects.

        Raises:
            SentinelOneAPIError: If API call fails.
            SentinelOneNetworkError: If network error occurs.

        """
        try:
            endpoint = f"{self.client_api.base_url}/web/api/v2.1/threats"
            params = {
                "contentHash__contains": file_hash,
                "sortOrder": "desc",
                "limit": 1,
            }

            self.logger.debug(f"{LOG_PREFIX} Making GET request to: {endpoint}")
            self.logger.debug(f"{LOG_PREFIX} Query parameters: {params}")

            response = self.client_api.session.get(endpoint, params=params)

            if response.status_code == 200:
                json_data = response.json()
                threats_data = json_data.get("data", [])

                self.logger.debug(
                    f"{LOG_PREFIX} Retrieved {len(threats_data)} threat records for hash {file_hash}"
                )

                threats = []
                for i, threat_data in enumerate(threats_data):
                    try:
                        threat_id = None
                        if threat_data.get("threatInfo") and threat_data[
                            "threatInfo"
                        ].get("threatId"):
                            threat_id = threat_data["threatInfo"]["threatId"]

                        if threat_id:
                            threat = SentinelOneThreat(threat_id=threat_id)
                            threat._raw = threat_data
                            threats.append(threat)
                            self.logger.debug(
                                f"{LOG_PREFIX} Created SentinelOneThreat {i + 1} with ID: {threat_id}"
                            )
                        else:
                            self.logger.debug(
                                f"{LOG_PREFIX} Threat record {i + 1} missing threat ID, skipping"
                            )
                    except Exception as conversion_error:
                        self.logger.warning(
                            f"{LOG_PREFIX} Error converting threat record {i + 1}: {conversion_error}"
                        )

                self.logger.info(
                    f"{LOG_PREFIX} Converted {len(threats)} valid threats for hash {file_hash}"
                )
                return threats
            else:
                raise SentinelOneAPIError()

        except (SentinelOneAPIError, SentinelOneNetworkError):
            raise
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error making threats query for hash {file_hash}: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(
                f"HTTP request failed for hash {file_hash}: {e}"
            ) from e
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error making threats query for hash {file_hash}: {e}"
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

    def _perform_single_fetch_attempt(
        self, dv_events: list[DeepVisibilityEvent], attempt: int, max_retry: int
    ) -> tuple[list[SentinelOneThreat] | None, Exception | None]:
        """Perform a single fetch attempt.

        Args:
            dv_events: List of DeepVisibilityEvent objects.
            attempt: Current attempt number (0-based).
            max_retry: Maximum number of retry attempts.

        Returns:
            Tuple of (threats_or_None, exception_or_None).

        """
        self.logger.debug(
            f"{LOG_PREFIX} Threat fetch attempt {attempt + 1} of {max_retry + 1}"
        )

        try:
            threats = self.fetch(dv_events)

            if threats:
                self.logger.info(
                    f"{LOG_PREFIX} Threat attempt {attempt + 1}: Found {len(threats)} threats - success!"
                )
                return threats, None
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} Threat attempt {attempt + 1}: No threats found"
                )
                return None, None

        except (SentinelOneAPIError, SentinelOneNetworkError) as e:
            self.logger.warning(
                f"{LOG_PREFIX} Threat attempt {attempt + 1} failed: {e}"
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
                f"{LOG_PREFIX} Waiting {sleep_time}s before threat retry {attempt + 2}..."
            )
            time.sleep(sleep_time)

    def fetch_with_retry(
        self,
        dv_events: list[DeepVisibilityEvent],
        max_retry: int = 3,
        offset_seconds: int = 30,
    ) -> list[SentinelOneThreat]:
        """Fetch threat data with retry mechanism.

        Args:
            dv_events: List of DeepVisibilityEvent objects.
            max_retry: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retry.

        Returns:
            List of SentinelOneThreat objects.

        Raises:
            SentinelOneValidationError: If inputs are invalid.
            SentinelOneAPIError: If all retry attempts fail.

        """
        if not dv_events:
            self.logger.debug(
                f"{LOG_PREFIX} No Deep Visibility events provided, returning empty list"
            )
            return []

        self._validate_retry_params(max_retry, offset_seconds)

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting threat fetch with {offset_seconds}s offset and {max_retry} max retries"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Waiting {offset_seconds}s before first threat API call..."
            )
            time.sleep(offset_seconds)

            last_exception = None

            for attempt in range(max_retry + 1):
                threats, exception = self._perform_single_fetch_attempt(
                    dv_events, attempt, max_retry
                )

                if threats:
                    return threats

                if exception:
                    last_exception = exception

                self._handle_retry_sleep(attempt, max_retry, offset_seconds)

            if last_exception:
                raise SentinelOneAPIError(
                    f"All threat fetch attempts failed. Last error: {last_exception}"
                ) from last_exception
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} No threats found after all retry attempts"
                )
                return []

        except (SentinelOneValidationError, SentinelOneAPIError):
            raise
        except Exception as e:
            raise SentinelOneAPIError(
                f"Unexpected error in threat fetch_with_retry: {e}"
            ) from e
