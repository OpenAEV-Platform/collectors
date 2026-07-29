"""DefenderO365DataFetcher: fetches alerts from Microsoft Graph Security API v2.

Implements DataFetcherProtocol with pagination, rate limiting, auth recovery,
and structured logging. Uses requests.Session with urllib3.Retry for
transient error handling.
"""

import logging
import time
from typing import Any

from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from src.auth.ms_graph_auth_client import MSGraphAuthClient
from src.auth.exceptions import AuthenticationError
from src.collector.types.collector import SourceConfig
from src.source.defender_o365_alert_model import DefenderO365Alert
from src.source.source_data import MicrosoftDefenderO365SourceData

LOG_PREFIX = "[DefenderO365DataFetcher]"
logger = logging.getLogger(__name__)


class DefenderO365DataFetcher:
    """Implements DataFetcherProtocol for Microsoft Defender O365 alerts.

    Fetches alerts from the Microsoft Graph Security API v2, handles
    pagination, rate limiting (HTTP 429), and auth recovery (HTTP 401).
    """

    def __init__(self, config: SourceConfig) -> None:
        """Initialize the data fetcher.

        Args:
            config: Source configuration containing authentication and
                connection parameters.
        """
        self.config = config
        self.auth_client = MSGraphAuthClient(config)
        self._build_session()

    def _build_session(self) -> None:
        """Build requests.Session with urllib3 Retry adapter."""
        self.session = Session()
        retries = Retry(
            total=self.config.max_fetch_retries,
            allowed_methods=["GET"],
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=0.5,
            backoff_jitter=0.2,
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _build_url(self, path: str) -> str:
        """Build a full URL from the configured base_url and a path.

        Args:
            path: The API path to append to the base URL.

        Returns:
            The full URL string.
        """
        base = str(self.config.base_url).rstrip("/")
        return f"{base}{path}"

    def _build_filter_params(self) -> dict[str, str]:
        """Build OData filter parameters from config.

        Returns:
            Dict with $filter parameter for serviceSource.
        """
        return {
            "$filter": f"serviceSource eq '{self.config.filter_service_source}'",
        }

    def fetch_data(self) -> list[MicrosoftDefenderO365SourceData]:
        """Retrieve all Defender O365 alerts from the Graph Security API.

        Follows @odata.nextLink pagination until no next page exists.
        Handles HTTP 429 (time.sleep + retry) and HTTP 401 (token refresh
        + single retry). Returns one MicrosoftDefenderO365SourceData
        per alert, all pages merged.

        Returns:
            A list of MicrosoftDefenderO365SourceData instances.
        """
        url = self._build_url("/security/alerts_v2")
        params = self._build_filter_params()
        all_alerts: list[dict[str, Any]] = []
        page_count = 0

        while url:
            page_count += 1
            token = self.auth_client.get_access_token()

            response = self.session.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                params=params,
            )

            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 1))
                logger.warning(
                    f"{LOG_PREFIX} Rate limited on page {page_count}, "
                    f"sleeping {retry_after}s"
                )
                time.sleep(retry_after)
                continue

            # Handle token expiry
            if response.status_code == 401:
                logger.info(
                    f"{LOG_PREFIX} Token expired on page {page_count}, refreshing"
                )
                token = self.auth_client.get_access_token(force_refresh=True)
                response = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                )
                if response.status_code == 401:
                    logger.warning(
                        f"{LOG_PREFIX} Second 401 after token refresh on page {page_count}"
                    )
                    # Don't raise, just continue with empty result for this page
                response.raise_for_status()

            data = response.json()
            value = data.get("value", [])

            # Validate and filter each alert
            for raw_alert in value:
                try:
                    alert = DefenderO365Alert.model_validate(raw_alert)
                    # Filter evidence to only analyzedMessageEvidence
                    filtered_evidence = alert.filter_evidence()
                    if filtered_evidence:
                        raw_alert["evidence"] = [
                            e.model_dump(by_alias=True) for e in filtered_evidence
                        ]
                    all_alerts.append(raw_alert)
                except Exception as exc:
                    logger.debug(
                        f"{LOG_PREFIX} Skipping malformed alert: {exc}"
                    )

            # Follow pagination
            url = data.get("@odata.nextLink")
            params = None  # nextLink carries its own params

            logger.info(
                f"{LOG_PREFIX} Page {page_count}: fetched {len(value)} alerts"
            )

        logger.info(
            f"{LOG_PREFIX} Total: {len(all_alerts)} alerts across {page_count} pages"
        )

        # Wrap each alert in SourceData
        return [
            MicrosoftDefenderO365SourceData(raw_alert=alert)
            for alert in all_alerts
        ]
