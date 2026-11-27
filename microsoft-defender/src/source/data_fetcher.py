"""DefenderDataFetcher: fetches alerts from Microsoft Graph Security API v2.

Implements DataFetcherProtocol with pagination, rate limiting, auth recovery,
and structured logging. Uses requests.Session with urllib3.Retry for
transient error handling.
"""

import logging
import re
from datetime import timedelta
from typing import Any
from urllib.parse import urljoin, urlsplit

from pydantic import HttpUrl, ValidationError
from pyoaev.signatures.types import SignatureTypes
from requests import RequestException, Session
from requests.adapters import HTTPAdapter
from src.auth.ms_graph_auth_client import MSGraphAuthClient
from src.collector.protocols.data_fetcher import FetchParamsHook
from src.collector.types.collector import SourceConfig
from src.source.models.evidences import processEvidence
from src.source.source_data import Alert
from urllib3.util import Retry

LOG_PREFIX = "[DefenderDataFetcher]"
logger = logging.getLogger(__name__)

# Name every OpenAEV implant executable carries: an alert whose evidences already
# name it needs no drill-down (collectors#611).
IMPLANT_NAME_MARKER = "oaev-implant-"
# Bounds of the hunting drill-down: half-width of the time window around the
# creation of the process looked up, and number of lookups per fetch.
DRILLDOWN_HALF_WINDOW = timedelta(minutes=2)
MAX_DRILLDOWNS_PER_FETCH = 50
DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,128}$")


class DrilldownError(Exception):
    """A hunting drill-down failed: the fetch says nothing about the alerts."""


class DefenderDataFetcher:
    """Implements DataFetcherProtocol for Microsoft Defender alerts.

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
        self._drilldown_available = True
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

        Combines serviceSource filter. Always orders results by lastUpdateDateTime
        descending (most recent first).

        Returns:
            Dict with $filter and $orderby parameters.
        """
        return {
            "$filter": f"serviceSource eq '{self.config.filter_service_source}'",
            "$orderby": "lastUpdateDateTime desc",
        }

    def fetch_data(self) -> list[Alert]:
        """Retrieve all Defender alerts from the Graph Security API.

        Follows @odata.nextLink pagination until no next page exists.
        Handles HTTP 401 (token refresh + single retry).
        Returns one Alert (SourceDataProtocol-valid) per alert,
        all pages merged. Results are ordered by lastUpdateDateTime
        descending (most recent first).

        Returns:
            A list of Alert instances.
        """
        url = self._build_url("security/alerts_v2")
        params = self._build_filter_params()

        if self._fetch_params_hook:
            params = self._fetch_params_hook(params)

        logger.info(f"{LOG_PREFIX} Query url built, url: {url}, params: {params}")

        all_alerts: list[Alert] = []
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

                logger.info(
                    f"Requesting with url {response.url}, reponse with status code {response.status_code}"
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

            response.raise_for_status()
            data = response.json()

            if not isinstance(data, dict):
                raise ValueError("Graph response must be a JSON object")

            value = data.get("value")
            if not isinstance(value, list):
                raise ValueError("Graph response 'value' must be a list")

            # Validate and filter each alert
            for raw_alert in value:
                try:
                    alert = Alert(**raw_alert)
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
                all_alerts.append(alert)

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

        self.drill_down(all_alerts)

        return all_alerts

    @staticmethod
    def needs_drilldown(alert: Alert) -> bool:
        """Whether the alert carries process evidence but no name of an implant.

        Such an alert holds only child-tool evidence (reg.exe, cmd.exe): the
        ancestry missing from its evidences is read through advanced hunting.
        """
        if not alert.process_evidences():
            return False
        names = (
            alert.to_oaev_data()
            .model_dump()
            .get(SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME.value, [])
        )
        return not any(IMPLANT_NAME_MARKER in str(name).lower() for name in names)

    @staticmethod
    def build_hunting_query(process: processEvidence) -> str | None:
        """KQL reading the ancestry of one process on its device, in a bounded window.

        Returns None when the evidence lacks the device, the process id or the
        creation time that bound the query.
        """
        if (
            process.mde_device_id is None
            or process.process_id is None
            or process.process_creation_date_time is None
            or not DEVICE_ID_PATTERN.match(process.mde_device_id)
        ):
            return None
        start = process.process_creation_date_time - DRILLDOWN_HALF_WINDOW
        end = process.process_creation_date_time + DRILLDOWN_HALF_WINDOW
        return (
            "DeviceProcessEvents"
            f" | where Timestamp between (datetime({start.isoformat()})"
            f" .. datetime({end.isoformat()}))"
            f' | where DeviceId == "{process.mde_device_id}"'
            f" and ProcessId == {int(process.process_id)}"
            " | project FileName, InitiatingProcessFileName,"
            " InitiatingProcessParentFileName"
            " | take 20"
        )

    def drill_down(self, alerts: list[Alert]) -> None:
        """Add to each alert with only child-tool evidence its ancestors' names.

        Runs /security/runHuntingQuery on DeviceProcessEvents for the root of
        each process chain of the alert. A missing permission (HTTP 403) turns
        the drill-down off for this fetch and keeps today's matching; any other
        failure raises DrilldownError, so the batch is postponed and never
        scored "Not Detected" (collectors#723).
        """
        lookups = 0
        for alert in alerts:
            if not self._drilldown_available:
                return
            if not self.needs_drilldown(alert):
                continue
            names: set[str] = set()
            for root in alert.chain_roots():
                query = self.build_hunting_query(root)
                if query is None:
                    continue
                if lookups >= MAX_DRILLDOWNS_PER_FETCH:
                    logger.info(
                        f"{LOG_PREFIX} Drill-down cap of {MAX_DRILLDOWNS_PER_FETCH} "
                        "lookups reached for this fetch"
                    )
                    return
                lookups += 1
                rows = self._run_hunting_query(query)
                if rows is None:
                    return
                for row in rows:
                    for column in (
                        "InitiatingProcessFileName",
                        "InitiatingProcessParentFileName",
                    ):
                        value = row.get(column)
                        if isinstance(value, str) and value:
                            names.add(value)
            if names:
                alert.drilldown_process_names = sorted(names)
                logger.info(
                    f"{LOG_PREFIX} Drill-down on alert id={alert.id}: "
                    f"ancestors {alert.drilldown_process_names}"
                )

    def _run_hunting_query(self, query: str) -> list[dict[str, Any]] | None:
        """Run one advanced hunting query; None when the permission is missing."""
        url = self._build_url("security/runHuntingQuery")
        token = self.auth_client.get_access_token()
        try:
            response = self.session.post(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json={"Query": query},
            )
            if response.status_code == 401:
                token = self.auth_client.get_access_token()
                response = self.session.post(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    json={"Query": query},
                )
            if response.status_code == 403:
                logger.warning(
                    f"{LOG_PREFIX} Drill-down skipped: the application lacks the "
                    "ThreatHunting.Read.All permission"
                )
                self._drilldown_available = False
                return None
            response.raise_for_status()
            data = response.json()
        except (RequestException, ValueError) as err:
            raise DrilldownError(f"Hunting drill-down failed: {err}") from err

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            raise DrilldownError("Hunting response 'results' must be a list")
        return [row for row in results if isinstance(row, dict)]
