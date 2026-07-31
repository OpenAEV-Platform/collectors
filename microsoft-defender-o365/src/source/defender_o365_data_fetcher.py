"""DefenderO365DataFetcher: fetches alerts from Microsoft Graph Security API v2.

Implements DataFetcherProtocol with pagination, rate limiting, auth recovery,
and structured logging. Uses requests.Session with urllib3.Retry for
transient error handling.
"""

import logging
from typing import Any
from urllib.parse import urljoin, urlsplit

from pydantic import HttpUrl, ValidationError
from requests import Session
from requests.adapters import HTTPAdapter
from src.auth.ms_graph_auth_client import MSGraphAuthClient
from src.collector.protocols.data_fetcher import FetchParamsHook
from src.collector.types.collector import SourceConfig
from src.source.defender_o365_alert_model import DefenderO365Alert
from src.source.source_data import MicrosoftDefenderO365SourceData
from urllib3.util import Retry

LOG_PREFIX = "[DefenderO365DataFetcher]"
logger = logging.getLogger(__name__)


class DefenderO365DataFetcher:
    """Implements DataFetcherProtocol for Microsoft Defender O365 alerts.

    Fetches alerts from the Microsoft Graph Security API v2, handles
    pagination and auth recovery (HTTP 401).
    """

    def __init__(
        self,
        config: SourceConfig,
        fetch_params_hook: FetchParamsHook | None = None,
    ) -> None:
        """Initialize the data fetcher.

        Args:
            config: Source configuration containing authentication and
                connection parameters.
            fetch_params_hook: Optional callable that receives the filter params
                dict before the first request and returns the (possibly
                modified) params dict. Use this to inject custom filters
                such as a since_datetime clause without mutating fetcher
                state.
        """
        self.config = config
        self.auth_client = MSGraphAuthClient(config)
        self._fetch_params_hook = fetch_params_hook
        self._build_session()

    def _build_session(self) -> None:
        """Build requests.Session with urllib3 Retry adapter."""
        self.session = Session()
        retries = Retry(
            total=self.config.max_fetch_retries,
            allowed_methods=["GET"],
            status_forcelist=[500, 502, 503, 504],
            backoff_factor=0.5,
            backoff_jitter=0.2,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def close(self) -> None:
        """Close the underlying requests.Session connection pool."""
        self.session.close()

    def _build_url(self, path: str) -> str:
        """Build a full URL from the configured base_url and a path.

        Uses directory semantics: ensures trailing slash on base, strips
        leading slash from path, so urljoin preserves the base path segment
        (e.g. /v1.0) rather than replacing it.

        Args:
            path: The API path to append to the base URL.

        Returns:
            The full URL string.

        Raises:
            ValueError: If the path contains a scheme or netloc.
        """
        reference = urlsplit(path)

        if reference.scheme or reference.netloc:
            raise ValueError("URL reference must not replace the base origin")

        base = self.config.base_url.encoded_string().rstrip("/") + "/"
        relative_path = path.lstrip("/")

        return HttpUrl(urljoin(base, relative_path)).encoded_string()

    def _build_filter_params(self) -> dict[str, str]:
        """Build OData filter parameters from config.

        Combines serviceSource filter. Always orders results by createdDateTime
        descending (most recent first).

        Returns:
            Dict with $filter and $orderby parameters.
        """
        return {
            "$filter": f"serviceSource eq '{self.config.filter_service_source}'",
            "$orderby": "createdDateTime desc",
        }

    def fetch_data(self) -> list[MicrosoftDefenderO365SourceData]:
        """Retrieve all Defender O365 alerts from the Graph Security API.

        Follows @odata.nextLink pagination until no next page exists.
        Handles HTTP 401 (token refresh + single retry).
        Returns one MicrosoftDefenderO365SourceData per alert,
        all pages merged. Results are ordered by createdDateTime
        descending (most recent first).

        Returns:
            A list of MicrosoftDefenderO365SourceData instances.
        """
        url = self._build_url("security/alerts_v2")
        params = self._build_filter_params()

        if self._fetch_params_hook:
            params = self._fetch_params_hook(params)

        all_alerts: list[dict[str, Any]] = []
        page_count = 0

        while url:
            request_attempt = 0
            token = self.auth_client.get_access_token()

            while request_attempt < self.config.max_fetch_retries:
                request_attempt += 1

                response = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                )

                # Handle token expiry
                if response.status_code == 401:
                    logger.info(
                        f"{LOG_PREFIX} Token expired (attempt {request_attempt}), refreshing"
                    )
                    # force refresh implicitly handled by msal
                    token = self.auth_client.get_access_token()
                    continue

                response.raise_for_status()
                break

            data = response.json()

            if not isinstance(data, dict):
                raise ValueError("Graph response must be a JSON object")

            value = data.get("value")
            if not isinstance(value, list):
                raise ValueError("Graph response 'value' must be a list")

            # Validate and filter each alert
            for raw_alert in value:
                try:
                    alert = DefenderO365Alert.model_validate(raw_alert)
                except ValidationError as exc:
                    alert_id = (
                        raw_alert.get("id", "unknown")
                        if isinstance(raw_alert, dict)
                        else "unknown"
                    )
                    logger.info(
                        f"{LOG_PREFIX} Skipping malformed alert id={alert_id}: {exc}"
                    )
                    continue

                # Compact: id, status, createdDateTime, filtered evidence
                compact_alert = alert.filter_evidence()
                all_alerts.append(compact_alert)

            # Follow pagination
            next_link = data.get("@odata.nextLink")
            if next_link is not None and not isinstance(next_link, str):
                raise ValueError("Graph '@odata.nextLink' must be a string")

            url = next_link
            params = None  # nextLink carries its own params

            page_count += 1
            logger.info(f"{LOG_PREFIX} Page {page_count}: fetched {len(value)} alerts")

        logger.info(
            f"{LOG_PREFIX} Total: {len(all_alerts)} alerts across {page_count} pages"
        )

        # Wrap each alert in SourceData
        return [MicrosoftDefenderO365SourceData(alert=alert) for alert in all_alerts]
