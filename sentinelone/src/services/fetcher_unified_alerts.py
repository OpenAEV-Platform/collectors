"""SentinelOne Unified Alerts fetcher (Singularity alerts GraphQL API).

The legacy Threats API only surfaces convicted threats (static-engine
reputation hits, mitigated behavioral threats). SentinelOne's newer
behavioral / STAR / AI detections land in **Unified Alerts**, exposed by a
separate GraphQL endpoint (``/web/api/v2.1/unifiedalerts/graphql``, Bearer
auth) and never returned by ``/threats``. An OpenAEV inject such as
"In-Memory Mimikatz-DumpCreds" typically raises a Unified Alert
("Potential Mimikatz Execution") without ever producing a Threat, so a
collector that reads only ``/threats`` reports Not Detected even though the
SentinelOne console shows the detection.

This fetcher lists Unified Alerts in the fetch window and maps each one to
the existing Deep-Visibility-shaped ``SentinelOneThreat`` + event contract,
so the unchanged matching pipeline can correlate them to expectations. The
OpenAEV implant process name (the ``parent_process_name`` signature the
matcher fuzzy-matches on) is recovered from the alert's OCSF ``rawData``.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from requests import ConnectionError, RequestException, Timeout

from .client_api import SentinelOneClientAPI
from .exception import (
    SentinelOneAPIError,
    SentinelOneNetworkError,
    SentinelOneValidationError,
)
from .model_threat import SentinelOneThreat

LOG_PREFIX = "[FetcherUnifiedAlerts]"
REQUEST_TIMEOUT_SECONDS = 30
PAGE_SIZE = 100
MAX_PAGES = 50

# The OpenAEV implant image name carries the inject id and the agent id, e.g.
# oaev-implant-<inject-uuid>-agent-<agent-uuid>.exe. It is the exact value of
# the expectation's parent_process_name signature, so recovering it from the
# alert is what lets a behavioral alert correlate to an OpenAEV expectation.
_IMPLANT_RE = re.compile(r"oaev-implant-[0-9a-fA-F-]+-agent-[0-9a-fA-F-]+(?:\.exe)?")

_ALERTS_QUERY = """
query($filters: [FilterInput!], $first: Int, $after: String) {
  alerts(filters: $filters, first: $first, after: $after,
         sort: {by: "detectedAt", order: DESC}) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        name
        detectedAt
        status
        result
        storylineId
        assets { name osType }
        process { parentName cmdLine }
      }
    }
  }
}
"""

# rawData (the OCSF blob holding the full process ancestry, hence the OpenAEV
# implant image name) lives on UnifiedAlertDetail, not on the list node, so it
# is fetched per alert.
_DETAIL_QUERY = """
query($id: ID!) {
  alert(id: $id) { rawData }
}
"""

# Defensive cap on per-alert detail fetches in a single cycle.
MAX_DETAIL_FETCHES = 200


class FetcherUnifiedAlerts:
    """Fetcher for SentinelOne Unified Alerts, mapped to the threat shape."""

    def __init__(self, client_api: SentinelOneClientAPI):
        """Initialize the Unified Alerts fetcher.

        Args:
            client_api: SentinelOne API client instance.

        """
        self.client_api = client_api
        self.logger = logging.getLogger(__name__)

    def fetch_alert_threats(
        self, start_time: datetime, end_time: datetime
    ) -> tuple[list[SentinelOneThreat], dict[str, list[dict[str, Any]]]]:
        """Fetch Unified Alerts in the window as threats + synthetic events.

        Args:
            start_time: Window start (inclusive).
            end_time: Window end (inclusive).

        Returns:
            Tuple of (threats, events_by_threat_id) where each threat is a
            ``SentinelOneThreat`` derived from one alert and the events carry
            the recovered OpenAEV implant name as ``parentProcessName`` so the
            existing matcher can fuzzy-match the expectation.

        Raises:
            SentinelOneValidationError: If the window is invalid.
            SentinelOneNetworkError: On a transport failure (transient).
            SentinelOneAPIError: On an HTTP or GraphQL failure.

        """
        if not isinstance(start_time, datetime) or not isinstance(end_time, datetime):
            raise SentinelOneValidationError(
                "start_time and end_time must be datetime objects"
            )
        if start_time >= end_time:
            raise SentinelOneValidationError("start_time must be before end_time")

        filters = [
            {
                "fieldId": "detectedAt",
                "dateTimeRange": {
                    "start": self._to_epoch_ms(start_time),
                    "end": self._to_epoch_ms(end_time),
                    "startInclusive": True,
                    "endInclusive": True,
                },
            }
        ]

        nodes = self._fetch_all_alert_nodes(filters)

        threats: list[SentinelOneThreat] = []
        events_by_id: dict[str, list[dict[str, Any]]] = {}
        for index, node in enumerate(nodes):
            if index < MAX_DETAIL_FETCHES:
                node["rawData"] = self._fetch_raw_data(node.get("id"))
            threat, events = self._map_alert_to_threat(node)
            if threat is None:
                continue
            threats.append(threat)
            if events:
                events_by_id.setdefault(threat.threat_id, []).extend(events)

        self.logger.info(
            f"{LOG_PREFIX} Fetched {len(threats)} unified alerts for the window "
            f"[{start_time.isoformat()} .. {end_time.isoformat()}]"
        )
        return threats, events_by_id

    def _fetch_all_alert_nodes(self, filters: list[dict]) -> list[dict]:
        """Page through the alerts connection and collect the raw nodes.

        Args:
            filters: GraphQL ``FilterInput`` list (already built).

        Returns:
            List of alert node dicts.

        Raises:
            SentinelOneNetworkError: On a transport failure.
            SentinelOneAPIError: On an HTTP or GraphQL failure.

        """
        nodes: list[dict] = []
        after: str | None = None

        for _page in range(MAX_PAGES):
            variables: dict[str, Any] = {"first": PAGE_SIZE, "filters": filters}
            if after is not None:
                variables["after"] = after

            body = self._post_graphql(_ALERTS_QUERY, variables)
            connection = (body.get("data") or {}).get("alerts") or {}
            for edge in connection.get("edges") or []:
                node = edge.get("node")
                if isinstance(node, dict):
                    nodes.append(node)

            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")
            if not after:
                break
        else:
            self.logger.warning(
                f"{LOG_PREFIX} Reached the maximum of {MAX_PAGES} alert pages; "
                f"returning {len(nodes)} nodes"
            )

        return nodes

    def _fetch_raw_data(self, alert_id: Any) -> Any:
        """Fetch one alert's OCSF ``rawData`` (holds the process ancestry).

        Args:
            alert_id: The alert id.

        Returns:
            The ``rawData`` value (dict or str), or None when unavailable.

        Raises:
            SentinelOneNetworkError: On a transport failure.
            SentinelOneAPIError: On an HTTP or GraphQL failure.

        """
        if not alert_id:
            return None
        body = self._post_graphql(_DETAIL_QUERY, {"id": str(alert_id)})
        return ((body.get("data") or {}).get("alert") or {}).get("rawData")

    def _post_graphql(self, query: str, variables: dict) -> dict:
        """POST a GraphQL request with Bearer auth and typed error handling.

        Args:
            query: GraphQL query string.
            variables: GraphQL variables.

        Returns:
            The parsed JSON response body.

        Raises:
            SentinelOneNetworkError: On a connection or timeout error.
            SentinelOneAPIError: On an HTTP error or a GraphQL ``errors`` block.

        """
        endpoint = f"{self.client_api.base_url}/web/api/v2.1/unifiedalerts/graphql"
        headers = {"Authorization": f"Bearer {self.client_api.api_key}"}

        try:
            response = self.client_api.session.post(
                endpoint,
                json={"query": query, "variables": variables},
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except (ConnectionError, Timeout) as e:
            raise SentinelOneNetworkError(
                f"Network error querying Unified Alerts: {e}"
            ) from e
        except RequestException as e:
            raise SentinelOneAPIError(
                f"HTTP request failed querying Unified Alerts: {e}"
            ) from e

        if response.status_code != 200:
            raise SentinelOneAPIError(
                f"Unified Alerts query failed with status "
                f"{response.status_code}: {response.text[:200]}"
            )

        body = response.json()
        if isinstance(body, dict) and body.get("errors"):
            raise SentinelOneAPIError(
                f"Unified Alerts GraphQL error: {json.dumps(body['errors'])[:300]}"
            )
        return body if isinstance(body, dict) else {}

    def _map_alert_to_threat(
        self, node: dict
    ) -> tuple[SentinelOneThreat | None, list[dict[str, Any]]]:
        """Map one alert node to a ``SentinelOneThreat`` + implant events.

        Args:
            node: Alert node dict from the GraphQL response.

        Returns:
            Tuple of (threat or None, events). ``None`` when the alert has no
            id. Events carry the recovered implant name as
            ``parentProcessName`` (empty when none could be recovered, in
            which case a parent_process_name expectation will simply not
            match, avoiding a false positive).

        """
        alert_id = node.get("id")
        if not alert_id:
            return None, []

        assets = node.get("assets") or []
        hostname = (
            assets[0].get("name") if assets and isinstance(assets[0], dict) else None
        )

        # Prevention polarity: MITIGATED means SentinelOne actively blocked the
        # activity; BENIGN / UNMITIGATED / absent means detect-only.
        is_mitigated = node.get("result") == "MITIGATED"

        threat = SentinelOneThreat(
            threat_id=str(alert_id),
            hostname=hostname,
            is_mitigated=is_mitigated,
            is_static=False,
            sha1=None,
        )
        threat._raw = node

        implants = self._extract_implant_names(node)
        events = [
            {
                "parentProcessName": implant,
                "processName": None,
                "hostname": hostname,
                "eventType": "unified_alert",
                "eventTime": node.get("detectedAt"),
                "fileSha1": None,
            }
            for implant in implants
        ]
        return threat, events

    def _extract_implant_names(self, node: dict) -> list[str]:
        """Recover the OpenAEV implant process name(s) from an alert node.

        The implant is the parent of the payload process. It is searched for
        in the process fields and, as the reliable source, in the OCSF
        ``rawData`` blob (the console keeps the full process ancestry there).

        Args:
            node: Alert node dict.

        Returns:
            Sorted unique list of implant image names found on the alert.

        """
        haystacks: list[str] = []
        process = node.get("process")
        if isinstance(process, dict):
            for key in ("parentName", "cmdLine"):
                value = process.get(key)
                if isinstance(value, str):
                    haystacks.append(value)
        raw = node.get("rawData")
        if raw is not None:
            haystacks.append(raw if isinstance(raw, str) else json.dumps(raw))

        found: set[str] = set()
        for text in haystacks:
            found.update(_IMPLANT_RE.findall(text))
        return sorted(found)

    def _to_epoch_ms(self, dt: datetime) -> int:
        """Convert a datetime to an epoch-millisecond integer (UTC).

        Args:
            dt: Datetime to convert (naive values are treated as UTC).

        Returns:
            Milliseconds since the Unix epoch.

        """
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
