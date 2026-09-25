"""Elastic Security API client for querying Elasticsearch detection alerts."""

import logging
import string
import time
from datetime import timedelta
from collections.abc import Callable
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
from .utils.url import redact_userinfo

LOG_PREFIX = "[ElasticClientAPI]"

DEFAULT_TIME_WINDOW_HOURS = 1
REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_RESULT_SIZE = 100

# Maximum number of parent hops the source-event drilldown walks up the process
# tree to recover the implant marker. The implant is not always the alerting
# process's direct parent - e.g. an implant may spawn ``cmd.exe`` which spawns
# the flagged ``reg.exe`` (marker two hops up) - so the drilldown climbs the
# ancestry (by process.entity_id, which is reuse-safe unlike raw pid) until it
# finds the marker or exhausts this budget.
MAX_ANCESTRY_DEPTH = 5

# Fallback window (seconds, either side of the alert time) used when the
# ancestry climb dead-ends because an intermediate process event is missing from
# the events index. The drilldown then looks for implant processes on the same
# host within this window and only credits the alert when EXACTLY ONE implant
# lineage is present - an ambiguous host (two+ injects' implants in the window)
# yields no marker, so a same-host alert is never cross-attributed.
FALLBACK_WINDOW_SECONDS = 600

# Clock-skew tolerance (seconds) when selecting the process instance live at an
# alert's time for a pid-only drilldown seed: the process is created before the
# alert, but ingestion/clock skew can place its event slightly after.
PID_SEED_BUFFER_SECONDS = 120

# Upper bound on how many candidate alerts are drilled per fetch. Each drill is
# up to MAX_ANCESTRY_DEPTH ES round-trips, so without a cap a broad query (many
# candidates) can issue hundreds of _search calls per expectation per attempt -
# a self-inflicted load on the customer cluster. Alerts are @timestamp desc, so
# the most recent (most relevant) are drilled first; the rest keep no marker.
MAX_DRILLDOWN_ALERTS = 20

# Sentinel injected for an empty placeholder so the rendered query_string stays
# syntactically valid while matching nothing (e.g. ``source.ip:(__oaev_no_match__)``).
NO_MATCH_TOKEN = "__oaev_no_match__"  # noqa: S105  # sentinel, not a credential

# Default Lucene ``query_string`` used to correlate detection alerts with an
# expectation. It is deliberately broad and multi-field so it works against both
# network alerts (source/destination IP) and endpoint/process alerts (host.ip,
# process fields) - the latter is what most Elastic Security rules produce. Every
# clause is optional at runtime: empty placeholders collapse to a no-match token.
# Users can override it entirely via ELASTIC_QUERY_TEMPLATE to see/edit the query.
DEFAULT_QUERY_TEMPLATE = (
    "(source.ip:({source_ips}) OR host.ip:({source_ips}) OR client.ip:({source_ips})) "
    "OR (destination.ip:({target_ips}) OR server.ip:({target_ips}) OR host.ip:({target_ips})) "
    "OR (url.path:({implant_urls}) OR url.original:({implant_urls})) "
    "OR (process.name:({implant_names}) OR process.parent.name:({implant_names}) "
    "OR process.command_line:({implant_names}))"
)

# Placeholders the query template may reference.
ALLOWED_PLACEHOLDERS = {
    "alerts_index",
    "source_ips",
    "target_ips",
    "implant_urls",
    "implant_names",
    "start_date",
    "end_date",
    "time_window",
}


class _SafeFormatter(string.Formatter):
    """Restricted formatter that blocks attribute/index access in templates."""

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> tuple:
        """Reject ``{value.__class__}`` / ``{value[0]}`` style traversal."""
        if "." in field_name or "[" in field_name:
            raise ValueError(
                f"Attribute/index access not allowed in query template: '{field_name}'"
            )
        return super().get_field(field_name, args, kwargs)


_safe_formatter = _SafeFormatter()


def _lucene_values(values: list[str] | None) -> str:
    """Render a list of values as an OR-joined, quoted Lucene group.

    Returns :data:`NO_MATCH_TOKEN` when the list is empty so the surrounding
    ``field:(...)`` clause stays valid but matches nothing.
    """
    cleaned = [str(v) for v in (values or []) if v not in (None, "")]
    if not cleaned:
        return NO_MATCH_TOKEN
    # Quote each value and escape Lucene metacharacters so a value is always
    # treated literally: backslash FIRST (so we don't double-escape), then the
    # double quote that delimits the phrase. Values are trusted (IPs / UUID
    # markers) but the template is operator-editable and values flow from an
    # external system, so escape defensively.
    def _esc(v: str) -> str:
        return v.replace("\\", "\\\\").replace('"', '\\"')

    return " OR ".join('"' + _esc(v) + '"' for v in cleaned)


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
            self.events_index = getattr(self.config.elastic, "events_index", None)
            self.offset = self.config.elastic.offset.total_seconds()
            self.max_retry = self.config.elastic.max_retry
            self.verify_ssl = self.config.elastic.verify_ssl
            self.ca_cert = getattr(self.config.elastic, "ca_cert", None) or None
            # Recovered-marker cache, shared across alerts/retries/expectations
            # within one processing cycle (reset via reset_marker_cache()).
            self._marker_cache: dict[tuple[str, str], str | None] = {}
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

        configured_template = getattr(self.config.elastic, "query_template", None)
        if configured_template:
            self._validate_template_placeholders(configured_template)
            self.query_template = configured_template
            self.logger.info(
                f"{LOG_PREFIX} Using custom query template from configuration"
            )
        else:
            self.query_template = DEFAULT_QUERY_TEMPLATE
            self.logger.debug(
                f"{LOG_PREFIX} No custom query template configured, using default"
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
        # TLS: prefer verifying against a provided CA bundle; only fall back to
        # verify=True; disabling verification is a loud, deliberate downgrade.
        if getattr(self, "ca_cert", None):
            session.verify = self.ca_cert
        else:
            session.verify = self.verify_ssl
            if not self.verify_ssl:
                self.logger.warning(
                    f"{LOG_PREFIX} TLS certificate verification is DISABLED "
                    "(ELASTIC_VERIFY_SSL=false). Credentials are exposed to "
                    "interception - do NOT use in production; trust the cluster "
                    "CA (ELASTIC_CA_CERT) instead."
                )
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
        match_check: "Callable[[list[ElasticAlert]], bool] | None" = None,
    ) -> list[ElasticAlert]:
        """Fetch Elastic Security alerts with a retry mechanism.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).
            match_check: Optional predicate over the fetched alerts. When given,
                the retry loop keeps going until it returns True (a matching alert
                appeared) or the budget is exhausted - so detection latency is
                absorbed even when unrelated alerts (from a concurrent inject) are
                already present. Without it, the loop stops at the first non-empty
                result as before.

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
            match_check=match_check,
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

    @staticmethod
    def _validate_template_placeholders(template: str) -> None:
        """Validate that a query template only uses supported placeholders.

        Args:
            template: The Lucene query_string template to validate.

        Raises:
            ElasticValidationError: If an unknown placeholder is referenced or
                the template is otherwise malformed.

        """
        try:
            fields = [
                field_name
                for _, field_name, _, _ in string.Formatter().parse(template)
                if field_name
            ]
        except (ValueError, IndexError) as e:
            raise ElasticValidationError(f"Malformed query template: {e}") from e

        for field_name in fields:
            base = field_name.split(".")[0].split("[")[0]
            if base not in ALLOWED_PLACEHOLDERS:
                raise ElasticValidationError(
                    f"Unknown placeholder '{{{field_name}}}' in query template. "
                    f"Allowed placeholders: {sorted(ALLOWED_PLACEHOLDERS)}"
                )

    def _render_query_string(self, search_criteria: ElasticSearchCriteria) -> str:
        """Render the configured query template into a Lucene query_string.

        Args:
            search_criteria: ElasticSearchCriteria object.

        Returns:
            The rendered Lucene query_string.

        """
        implant_urls: list[str] = []
        for parent_process_name in search_criteria.parent_process_names or []:
            uuids = self.parent_process_parser.extract_uuids_from_parent_process_name(
                parent_process_name
            )
            if uuids:
                inject_uuid, agent_uuid = uuids
                implant_urls.append(
                    f"/api/injects/{inject_uuid}/{agent_uuid}/executable-payload"
                )
        implant_names = list(search_criteria.parent_process_names or [])

        return _safe_formatter.format(
            self.query_template,
            alerts_index=self.alerts_index,
            source_ips=_lucene_values(search_criteria.source_ips),
            target_ips=_lucene_values(search_criteria.target_ips),
            implant_urls=_lucene_values(implant_urls),
            implant_names=_lucene_values(implant_names),
            # Absent dates render as ``*`` (an open range bound) so a custom
            # template like ``@timestamp:[{start_date} TO {end_date}]`` stays
            # valid Lucene instead of becoming ``[ TO ]``.
            start_date=search_criteria.start_date or "*",
            end_date=search_criteria.end_date or "*",
            time_window=int(self.time_window.total_seconds()),
        )

    def _build_query(
        self, search_criteria: ElasticSearchCriteria, extend_end_seconds: int = 0
    ) -> dict[str, Any]:
        """Build an Elasticsearch ``_search`` query body from search criteria.

        The correlation clause comes from the (default or user-supplied) query
        template rendered into a Lucene ``query_string``; the time window is
        always applied as a structured ``@timestamp`` range filter. ``lenient``
        keeps the query valid even when a referenced field does not exist on the
        alert mapping.

        Args:
            search_criteria: ElasticSearchCriteria object.
            extend_end_seconds: Optional seconds to widen the time window on retries.

        Returns:
            Elasticsearch query DSL as a dictionary.

        """
        rendered = self._render_query_string(search_criteria)
        window_seconds = int(self.time_window.total_seconds()) + extend_end_seconds

        return {
            "size": DEFAULT_RESULT_SIZE,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{window_seconds}s"}}}
                    ],
                    "must": [
                        {
                            "query_string": {
                                "query": rendered,
                                "lenient": True,
                                "analyze_wildcard": True,
                            }
                        }
                    ],
                }
            },
        }

    def _enrich_alerts_with_source_events(self, alerts: list[ElasticAlert]) -> None:
        """Recover the OpenAEV implant marker for each alert via a drilldown.

        Detection alerts rarely retain the process ancestry, so the implant
        marker (``oaev-implant-<inject>-agent-<agent>``) lives only in the raw
        endpoint/process events. For every alert carrying ``host.name`` and
        ``process.pid`` this looks up the matching source process event in
        ``events_index`` and, when found, stamps ``implant_marker`` on the
        alert. Results are cached per ``(host, pid)`` to avoid duplicate
        queries. No-op when no ``events_index`` is configured.

        Args:
            alerts: Alerts to enrich in place.

        """
        if not self.events_index or not alerts:
            return

        drills = 0
        for alert in alerts:
            if not alert.host_name or (alert.pid is None and not alert.process_entity_id):
                continue
            if alert.process_entity_id:
                # entity_id is reuse-safe, so its recovered marker can be cached
                # and reused across alerts/retries/expectations within the cycle.
                key = (alert.host_name, alert.process_entity_id)
                if key not in self._marker_cache:
                    # Bound the per-fetch drilldown fan-out; already-cached seeds
                    # are free (do not count against the cap).
                    if drills >= MAX_DRILLDOWN_ALERTS:
                        continue
                    drills += 1
                    self._marker_cache[key] = self._fetch_source_event_marker(
                        alert.host_name,
                        alert.pid,
                        alert.process_entity_id,
                        alert.time,
                    )
                marker = self._marker_cache[key]
            else:
                # pid-only seed (e.g. a PowerShell ScriptBlock alert): a pid can
                # be reused by another process within a cycle, so a marker cached
                # on pid could be stale/mis-attributed to a later instance. Its
                # drilldown is time-anchored per alert (_fetch_pid_seed), so
                # resolve it each time and never cache it.
                if drills >= MAX_DRILLDOWN_ALERTS:
                    continue
                drills += 1
                marker = self._fetch_source_event_marker(
                    alert.host_name,
                    alert.pid,
                    None,
                    alert.time,
                )
            if marker:
                alert.implant_marker = marker

    def reset_marker_cache(self) -> None:
        """Clear the recovered-marker cache. Only reuse-safe entity_id seeds are
        cached (pid-only seeds are never cached, see
        _enrich_alerts_with_source_events); clearing per cycle keeps the cache
        from growing without bound across cycles.
        """
        self._marker_cache = {}

    # Event ``_source`` fields the drilldown needs: process/parent text (for the
    # marker) plus the entity ids used to climb the ancestry reuse-safely.
    _DRILLDOWN_SOURCE = [  # noqa: RUF012
        "process.name",
        "process.command_line",
        "process.executable",
        "process.entity_id",
        "process.parent.name",
        "process.parent.command_line",
        "process.parent.executable",
        "process.parent.entity_id",
    ]

    def _fetch_source_event_marker(  # noqa: C901
        self,
        host_name: str,
        pid: int | None,
        entity_id: str | None = None,
        alert_time: str | None = None,
    ) -> str | None:
        """Recover the implant marker for an alert by climbing the process tree.

        The alerting process is not always the implant's direct child: an
        implant may spawn ``cmd.exe`` which spawns the flagged ``reg.exe``, so
        the marker lives two (or more) hops up. Starting from the alerting
        process, this walks up the ancestry by ``process.entity_id`` - which,
        unlike a raw pid, is not reused across process lifetimes - up to
        ``MAX_ANCESTRY_DEPTH`` levels, returning the first
        ``oaev-implant-<inject>-agent-<agent>`` marker found. The walk is seeded
        by the alert's ``process.entity_id`` when available (exact), else by pid.

        When the climb dead-ends because an intermediate process event is missing
        from the events index (incomplete endpoint telemetry), it falls back to
        ``_fallback_unique_host_marker``, which credits the alert only when
        exactly one implant lineage is present on the host around the alert time
        (never cross-attributing an ambiguous host).

        Args:
            host_name: Host the process ran on (``host.name``).
            pid: Process id of the alerting process (``process.pid``), used only
                when no ``entity_id`` seed is available.
            entity_id: The alert's ``process.entity_id`` (preferred seed).
            alert_time: The alert's ``@timestamp``, anchoring the fallback window.

        Returns:
            The reconstructed marker, or None when no ancestor carries one.

        """
        lookback = int(self.time_window.total_seconds()) + 900

        # Entry point: the alerting process's own events. Seed by entity_id when
        # the alert carries one (exact, reuse-safe); otherwise by pid, in which
        # case a reused pid only affects this first hop (mitigated by checking
        # each event's own marker before climbing).
        if entity_id:
            frontier = self._fetch_process_events(
                {"term": {"process.entity_id": entity_id}}, host_name, lookback
            )
        elif pid is not None:
            # A pid-only seed (e.g. a PowerShell ScriptBlock alert carries pid but
            # no entity_id) must account for pid reuse: several process instances
            # can share a pid over time. Pick the instance that was live at the
            # alert time so the marker belongs to the process that fired it.
            frontier = self._fetch_pid_seed(host_name, pid, lookback, alert_time)
        else:
            return None
        if not frontier:
            return None

        visited: set[str] = set()
        for depth in range(MAX_ANCESTRY_DEPTH + 1):
            next_entity_ids: list[str] = []
            for source in frontier:
                marker = self._marker_from_source(source)
                if marker:
                    self.logger.debug(
                        f"{LOG_PREFIX} Drilldown recovered implant marker for "
                        f"host={host_name} pid={pid} at depth {depth}: {marker}"
                    )
                    return marker
                _own, parent = self._event_entity_ids(source)
                if parent and parent not in visited:
                    next_entity_ids.append(parent)

            frontier = []
            for entity_id in next_entity_ids:
                if entity_id in visited:
                    continue
                visited.add(entity_id)
                frontier.extend(
                    self._fetch_process_events(
                        {"term": {"process.entity_id": entity_id}},
                        host_name,
                        lookback,
                    )
                )
            if not frontier:
                break

        # The ancestry climb reached no marker - most often because an
        # intermediate process event (e.g. the cmd.exe between the implant and
        # the flagged process) was never ingested, breaking the entity_id chain.
        # Fall back to a host + time-window implant lookup (safe: unique-only).
        return self._fallback_unique_host_marker(host_name, alert_time)

    def _fallback_unique_host_marker(
        self, host_name: str, alert_time: str | None
    ) -> str | None:
        """Recover the marker when the ancestry chain is broken, safely.

        Looks for implant processes on ``host_name`` within
        ``FALLBACK_WINDOW_SECONDS`` of ``alert_time`` and returns their marker
        ONLY when exactly one distinct implant lineage
        (``oaev-implant-<inject>-agent-<agent>``) is present. If two or more
        injects' implants are in the window the host is ambiguous and this
        returns None, so an alert whose ancestry could not be traced is never
        cross-attributed to the wrong inject. Downstream matching still requires
        the returned marker to equal the expectation's own, so a unique-but-
        unrelated implant simply fails to match rather than mis-crediting.

        Args:
            host_name: Host the alert fired on (``host.name``).
            alert_time: The alert's ``@timestamp`` (anchors the window).

        Returns:
            The single implant marker present on the host in the window, or None
            when there is none or more than one.

        """
        if not alert_time:
            return None
        body = {
            "size": 100,
            "_source": self._DRILLDOWN_SOURCE,
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": (
                                    "process.name:oaev-implant-* "
                                    "OR process.parent.name:oaev-implant-*"
                                ),
                                "lenient": True,
                            }
                        }
                    ],
                    "filter": [
                        {"term": {"host.name": host_name}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"{alert_time}||-{FALLBACK_WINDOW_SECONDS}s",
                                    "lte": f"{alert_time}||+{FALLBACK_WINDOW_SECONDS}s",
                                }
                            }
                        },
                    ],
                }
            },
        }
        hits = self._events_search(body, host_name, "unique-host fallback")

        markers = {
            marker
            for hit in hits
            if isinstance(hit, dict) and isinstance(hit.get("_source"), dict)
            for marker in [self._marker_from_source(hit["_source"])]
            if marker
        }
        if len(markers) == 1:
            marker = next(iter(markers))
            self.logger.debug(
                f"{LOG_PREFIX} Drilldown recovered implant marker for "
                f"host={host_name} via unique-host fallback: {marker}"
            )
            return marker
        if len(markers) > 1:
            self.logger.debug(
                f"{LOG_PREFIX} Fallback declined for host={host_name}: "
                f"{len(markers)} implant lineages in window (ambiguous)"
            )
        return None

    def _fetch_pid_seed(
        self, host_name: str, pid: int, lookback: int, alert_time: str | None
    ) -> list[dict[str, Any]]:
        """Seed the ancestry climb from a pid, resilient to pid reuse.

        Several process instances can share a pid over time, so a bare pid seed
        may climb the wrong instance's ancestry (a later process that reused the
        pid), recovering an unrelated inject's marker. When the alert time is
        known, this restricts the search to at/just-before it and keeps only the
        events of the single instance live then (the nearest process by time,
        isolated by its ``process.entity_id``) - the process that actually fired
        the alert. Without an alert time it falls back to the trailing window.

        Args:
            host_name: Host the process ran on.
            pid: The alert's ``process.pid``.
            lookback: How far back to search, in seconds.
            alert_time: The alert's ``@timestamp`` (ISO 8601), or None.

        Returns:
            The seed instance's event ``_source`` dicts (possibly empty).

        """
        time_range = None
        if alert_time:
            time_range = {
                "gte": f"{alert_time}||-{lookback}s",
                "lte": f"{alert_time}||+{PID_SEED_BUFFER_SECONDS}s",
            }
        events = self._fetch_process_events(
            {"term": {"process.pid": pid}}, host_name, lookback, time_range
        )
        if not events or not alert_time:
            return events

        # Events are sorted @timestamp desc. Identify the instance live at the
        # alert: prefer the latest creation-like event (one exposing a parent,
        # which carries the implant lineage) at/just-before the alert; fall back
        # to the nearest event of any kind. Keep only that instance's events, by
        # its entity_id, so a later pid reuse by another inject cannot leak in.
        creators = [e for e in events if self._event_entity_ids(e)[1]]
        anchor = creators[0] if creators else events[0]
        nearest_entity, _parent = self._event_entity_ids(anchor)
        if not nearest_entity:
            return [anchor]
        same_instance = [
            e for e in events if self._event_entity_ids(e)[0] == nearest_entity
        ]
        return same_instance or [anchor]

    def _fetch_process_events(
        self,
        match_clause: dict[str, Any],
        host_name: str,
        lookback: int,
        time_range: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch raw process-event ``_source`` docs matching a clause on a host.

        Args:
            match_clause: An ES term clause selecting the process (by pid or
                entity_id).
            host_name: Host to scope the search to.
            lookback: How far back to search, in seconds.
            time_range: Optional explicit ``@timestamp`` range clause; when
                omitted a trailing ``now-<lookback>s`` window is used.

        Returns:
            The matching events' ``_source`` dicts (possibly empty).

        """
        ts_range = time_range or {"gte": f"now-{lookback}s"}
        body = {
            "size": 25,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": self._DRILLDOWN_SOURCE,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"host.name": host_name}},
                        match_clause,
                        {"range": {"@timestamp": ts_range}},
                    ]
                }
            },
        }
        hits = self._events_search(body, host_name, f"clause={match_clause}")
        return [
            hit.get("_source", {})
            for hit in hits
            if isinstance(hit, dict) and isinstance(hit.get("_source"), dict)
        ]

    def _events_search(
        self, body: dict[str, Any], host_name: str, context: str
    ) -> list[dict[str, Any]]:
        """POST a drilldown query to the events index, surfacing config/auth errors.

        A credential that lacks ``read`` on the events index (401/403) or a
        non-existent events index (404) is raised as an actionable error instead
        of being swallowed as an empty result. Swallowing it would make every
        endpoint alert silently recover no implant marker and be rejected,
        downgrading implant injects to a false ``Not Detected`` (a silent false
        negative). Raising instead leaves those expectations pending (see
        ``LEAVE_PENDING_ERRORS``), exactly like the alerts query, so the
        misconfiguration is fixed rather than mis-graded. Transient failures
        (network blip, malformed JSON, other non-200) still return ``[]`` so the
        outer retry loop simply re-drills.

        Args:
            body: The ``_search`` request body.
            host_name: Host the drilldown is scoped to (for logs).
            context: Short description of the drilldown for debug logs.

        Returns:
            The raw ``hits`` list (possibly empty).

        Raises:
            ElasticAuthenticationError: On 401/403 against the events index.
            ElasticAPIError: When the events index does not exist (404).

        """
        endpoint = f"{self.base_url}/{self.events_index}/_search"
        try:
            response = self.session.post(
                endpoint, json=body, timeout=REQUEST_TIMEOUT_SECONDS
            )
        except (RequestException, ValueError) as e:
            self.logger.debug(
                f"{LOG_PREFIX} Drilldown failed for host={host_name} "
                f"({context}): {redact_userinfo(str(e))}"
            )
            return []
        if response.status_code in (401, 403):
            raise ElasticAuthenticationError(
                f"Authorization failed ({response.status_code}) on the events "
                f"index '{self.events_index}': the credential needs 'read' + "
                "'view_index_metadata' there for the implant-marker drilldown. "
                "Grant it, or unset ELASTIC_EVENTS_INDEX to disable the drilldown "
                "and correlate on IP + time. See README 'Required permissions'."
            )
        if response.status_code == 404:
            raise ElasticAPIError(
                f"Events index '{self.events_index}' not found (404): check "
                "ELASTIC_EVENTS_INDEX, or unset it to disable the drilldown."
            )
        if response.status_code != 200:
            self.logger.debug(
                f"{LOG_PREFIX} Drilldown returned {response.status_code} "
                f"for host={host_name} ({context})"
            )
            return []
        try:
            return response.json().get("hits", {}).get("hits", [])
        except ValueError:
            return []

    def _marker_from_source(self, source: dict[str, Any]) -> str | None:
        """Extract the implant marker from a single event ``_source`` if present.

        Args:
            source: The ``_source`` of a process event.

        Returns:
            The reconstructed marker, or None.

        """
        text = self._collect_process_text(source)
        uuids = self.parent_process_parser.extract_uuids_from_parent_process_name(text)
        if not uuids:
            return None
        inject_uuid, agent_uuid = uuids
        return self.parent_process_parser.construct_parent_process_name(
            inject_uuid, agent_uuid
        )

    @staticmethod
    def _event_entity_ids(source: dict[str, Any]) -> tuple[str | None, str | None]:
        """Return an event's own and parent ``process.entity_id``.

        Handles both nested (``{"process": {"parent": {...}}}``) and flattened
        (``"process.parent.entity_id"``) ECS layouts.

        Args:
            source: The ``_source`` of a process event.

        Returns:
            Tuple ``(own_entity_id, parent_entity_id)`` (either may be None).

        """
        own = source.get("process.entity_id")
        parent = source.get("process.parent.entity_id")
        proc = source.get("process")
        if isinstance(proc, dict):
            own = own or proc.get("entity_id")
            parent_obj = proc.get("parent")
            if isinstance(parent_obj, dict):
                parent = parent or parent_obj.get("entity_id")
        own = own if isinstance(own, str) else None
        parent = parent if isinstance(parent, str) else None
        return own, parent

    @staticmethod
    def _collect_process_text(source: dict[str, Any]) -> str:
        """Flatten every process/parent-process text field of an event ``_source``.

        Handles both nested (``{"process": {"parent": {...}}}``) and flattened
        (``"process.parent.command_line"``) ECS layouts.

        Args:
            source: The ``_source`` of an events-index hit.

        Returns:
            A single string joining all process/parent text values.

        """
        parts: list[str] = []
        proc = source.get("process")
        if isinstance(proc, dict):
            parent = proc.get("parent")
            containers = [proc, parent if isinstance(parent, dict) else {}]
            for container in containers:
                for key in ("name", "command_line", "executable"):
                    value = container.get(key)
                    if isinstance(value, str):
                        parts.append(value)
        for key in (
            "process.name",
            "process.command_line",
            "process.executable",
            "process.parent.name",
            "process.parent.command_line",
            "process.parent.executable",
        ):
            value = source.get(key)
            if isinstance(value, str):
                parts.append(value)
        return " ".join(parts)

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
                    "Authentication with Elastic Security failed: check "
                    "ELASTIC_API_KEY or ELASTIC_USERNAME/ELASTIC_PASSWORD."
                )
            if response.status_code == 403:
                # Actionable: the credential is valid but lacks read on the index.
                raise ElasticAuthenticationError(
                    "Authorization failed (403): the credential lacks 'read' on "
                    f"'{self.alerts_index}'. Grant read + view_index_metadata on "
                    "the alerts index and (for the drilldown) the events index. "
                    "See README 'Required permissions'."
                )
            if response.status_code == 404:
                raise ElasticAPIError(
                    f"Index '{self.alerts_index}' not found (404): check "
                    "ELASTIC_ALERTS_INDEX / ELASTIC_EVENTS_INDEX match indices that "
                    "exist in this cluster."
                )
            if response.status_code != 200:
                raise ElasticAPIError(
                    f"Elastic Security API returned status {response.status_code}: {response.text}"
                )

            elastic_response = ElasticResponse.from_raw_response(response.json())
            self.logger.info(
                f"{LOG_PREFIX} Retrieved {len(elastic_response.results)} alerts"
            )
            self._enrich_alerts_with_source_events(elastic_response.results)
            return elastic_response.results

        except (ElasticAuthenticationError, ElasticAPIError):
            raise
        except (ConnectionError, Timeout) as e:
            raise ElasticNetworkError(
                f"Network error during query: {redact_userinfo(str(e))}"
            ) from e
        except RequestException as e:
            raise ElasticAPIError(
                f"HTTP request failed during query: {redact_userinfo(str(e))}"
            ) from e
        except Exception as e:
            raise ElasticQueryError(
                f"Unexpected error executing query: {redact_userinfo(str(e))}"
            ) from e

    def _execute_query_with_retry(  # noqa: C901
        self,
        search_criteria: ElasticSearchCriteria,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
        match_check: "Callable[[list[ElasticAlert]], bool] | None" = None,
    ) -> list[ElasticAlert]:
        """Execute an Elasticsearch query with a retry mechanism.

        Args:
            search_criteria: ElasticSearchCriteria object with search parameters.
            max_retries: Maximum number of retry attempts.
            offset_seconds: Seconds to wait between retries.
            match_check: Optional predicate over the fetched alerts; when given,
                retries continue until it returns True (a matching alert appeared)
                or the budget is exhausted (see fetch_with_retry).

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
                    # With a match_check, keep retrying until a *matching* alert
                    # appears (absorbing detection latency even when unrelated
                    # alerts from a concurrent inject are already present), then
                    # return. On the last attempt return whatever was found so the
                    # caller can render the (Not Detected) verdict.
                    if match_check is not None and not match_check(alerts):
                        self.logger.info(
                            f"{LOG_PREFIX} Attempt {attempt + 1}: found "
                            f"{len(alerts)} alerts but none match yet"
                        )
                        if attempt == retries:
                            return alerts
                        continue
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
                self.logger.warning(
                    f"{LOG_PREFIX} Attempt {attempt + 1} failed: "
                    f"{redact_userinfo(str(e))}"
                )
                if attempt == retries:
                    break

        if last_exception:
            raise ElasticAPIError(
                "All Elastic Security fetch attempts failed. Last error: "
                f"{redact_userinfo(str(last_exception))}"
            ) from last_exception
        return []
