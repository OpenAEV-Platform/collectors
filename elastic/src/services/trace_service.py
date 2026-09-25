"""Elastic Security Trace Service Provider.

This module provides Elastic Security-specific logic for creating expectation traces
from processing results.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlparse, urlunparse

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)

from ..models.configs.config_loader import ConfigLoader
from .client_api import ElasticClientAPI
from .exception import ElasticDataConversionError, ElasticValidationError
from .utils.url import redact_userinfo

if TYPE_CHECKING:  # avoid a runtime services->collector import cycle
    from ..collector.models import ExpectationResult, ExpectationTrace

LOG_PREFIX = "[ElasticTraceService]"


class ElasticTraceService:
    """Elastic Security-specific trace service provider.

    This service extracts trace information from expectation processing results
    and converts them into OpenAEV expectation traces using proper Pydantic models.
    """

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the Elastic Security trace service.

        Args:
            config: Configuration loader instance for trace service settings.

        Raises:
            ElasticValidationError: If config is None.

        """
        if config is None:
            raise ElasticValidationError("Config is required for trace service")

        self.logger = logging.getLogger(__name__)
        self.config = config
        self.client_api = ElasticClientAPI(config)
        self.logger.debug(f"{LOG_PREFIX} Elastic Security trace service initialized")

    def create_traces_from_results(
        self, results: list[ExpectationResult], collector_id: str
    ) -> list[ExpectationTrace]:
        """Create trace data from processing results.

        Args:
            results: List of expectation processing results.
            collector_id: ID of the collector.

        Returns:
            List of ExpectationTrace models for OpenAEV.

        Raises:
            ElasticValidationError: If inputs are invalid.
            ElasticDataConversionError: If trace creation fails.

        """
        if not collector_id:
            raise ElasticValidationError("collector_id cannot be empty")

        if not isinstance(results, list):
            raise ElasticValidationError("results must be a list")

        try:
            valid_results = [r for r in results if r.is_valid and r.matched_alerts]

            if not valid_results:
                self.logger.info(
                    f"{LOG_PREFIX} No valid results with matching data for traces out of {len(results)} results"
                )
                return []

            self.logger.info(
                f"{LOG_PREFIX} Creating traces for {len(valid_results)} valid results out of {len(results)} total"
            )

            traces = []

            for i, result in enumerate(valid_results, 1):
                expectation_id = result.expectation_id
                if not expectation_id:
                    self.logger.warning(
                        f"{LOG_PREFIX} Skipping result {i} - missing expectation_id"
                    )
                    continue

                self.logger.debug(
                    f"{LOG_PREFIX} Creating trace {i}/{len(valid_results)} for expectation {expectation_id}"
                )

                try:
                    trace = self._create_expectation_trace(
                        result, expectation_id, collector_id
                    )

                    if trace:
                        traces.append(trace)
                        self.logger.debug(
                            f"{LOG_PREFIX} Created trace for expectation {expectation_id}: {trace.inject_expectation_trace_alert_name}"
                        )
                    else:
                        self.logger.warning(
                            f"{LOG_PREFIX} Trace creation returned None for expectation {expectation_id}"
                        )
                except Exception as e:
                    raise ElasticDataConversionError(
                        f"Error creating trace for expectation {expectation_id}: {e}"
                    ) from e

            self.logger.info(
                f"{LOG_PREFIX} Successfully created {len(traces)} traces from {len(valid_results)} valid results"
            )
            return traces

        except ElasticDataConversionError:
            raise
        except Exception as e:
            raise ElasticDataConversionError(
                f"Unexpected error creating traces from results: {e}"
            ) from e

    def _create_expectation_trace(
        self, result: ExpectationResult, expectation_id: str, collector_id: str
    ) -> ExpectationTrace:
        """Create ExpectationTrace model from a single result.

        Args:
            result: Processing result dictionary.
            expectation_id: ID of the expectation.
            collector_id: ID of the collector.

        Returns:
            ExpectationTrace model for OpenAEV.

        Raises:
            ElasticValidationError: If inputs are invalid.
            ElasticDataConversionError: If trace creation fails.

        """
        if not expectation_id:
            raise ElasticValidationError("expectation_id cannot be empty")

        if not collector_id:
            raise ElasticValidationError("collector_id cannot be empty")

        if not result.matched_alerts:
            raise ElasticValidationError(
                "result must have matched_alerts for trace creation"
            )

        try:
            matching_data = result.matched_alerts[0] or {}
            self.logger.debug(
                f"{LOG_PREFIX} Processing matching data with {len(matching_data)} fields"
            )

            # Prefer the matched alert's own rule name and a link to that exact
            # alert (by kibana.alert.uuid); fall back to the IP-based search only
            # when the specific alert id is unavailable.
            alert_id = matching_data.get("_alert_id")
            alert_url = matching_data.get("_alert_url")
            alert_name = matching_data.get("_rule_name") or self._determine_alert_name(
                matching_data
            )

            alert_time = matching_data.get("_alert_time")

            self.logger.debug(f"{LOG_PREFIX} Building trace URL...")
            # Canonical Kibana alert link (kibana.alert.url) - what a connector/
            # SOAR uses - when present and safe; otherwise a collector-built link.
            trace_link = self._resolve_alert_url(str(alert_url)) if alert_url else None
            if not trace_link:
                if alert_id:
                    trace_link = self._build_trace_url_from_alert_id(
                        str(alert_id), alert_time
                    )
                else:
                    trace_link = self._build_trace_url_from_expectation(
                        result.expectation
                    )
            self.logger.debug(f"{LOG_PREFIX} Generated trace link: {trace_link}")

            trace_date = datetime.utcnow().replace(microsecond=0)
            date_str = trace_date.isoformat() + "Z"
            self.logger.debug(f"{LOG_PREFIX} Generated trace date: {date_str}")

            from ..collector.models import ExpectationTrace

            trace = ExpectationTrace(
                inject_expectation_trace_expectation=str(expectation_id),
                inject_expectation_trace_source_id=str(collector_id),
                inject_expectation_trace_alert_name=alert_name,
                inject_expectation_trace_alert_link=trace_link,
                inject_expectation_trace_date=date_str,
            )

            self.logger.debug(
                f"{LOG_PREFIX} Created ExpectationTrace with alert name: {alert_name}"
            )
            return trace

        except ElasticValidationError:
            raise
        except Exception as e:
            raise ElasticDataConversionError(
                f"Error creating expectation trace: {e}"
            ) from e

    def _determine_alert_name(self, matching_data: dict[str, Any]) -> str:
        """Determine alert name based on matching data content.

        Args:
            matching_data: Dictionary containing the matched data elements.

        Returns:
            Human-readable alert name based on data content.

        """
        self.logger.debug(f"{LOG_PREFIX} Creating trace for Elastic Security alert")
        # Log only the field names, not the values: matching_data carries alert
        # contents (IPs, rule names, internal ids) that should not be dumped in
        # full at debug level.
        self.logger.debug(
            f"{LOG_PREFIX} Creating trace from matching data with keys: "
            f"{sorted(matching_data)}"
        )

        if (
            "source_ipv4_address" in matching_data
            or "source_ipv6_address" in matching_data
        ):
            self.logger.debug(
                f"{LOG_PREFIX} Creating trace for detection event (source IP)"
            )
            return "Elastic Security Detection Alert - Source IP"
        elif (
            "target_ipv4_address" in matching_data
            or "target_ipv6_address" in matching_data
        ):
            self.logger.debug(
                f"{LOG_PREFIX} Creating trace for detection event (target IP)"
            )
            return "Elastic Security Detection Alert - Target IP"
        else:
            self.logger.debug(
                f"{LOG_PREFIX} Using generic alert name - no specific IP data type identified"
            )
            return "Elastic Security Detection Alert"

    def _derive_kibana_base_url(self) -> str:
        """Derive the Kibana base URL used to build trace links.

        Resolution order:

        1. When ``elastic.kibana_url`` is configured, it is used directly (with
           any trailing slash trimmed).
        2. Otherwise a best-effort rewrite of ``elastic.base_url`` is performed:
           Elasticsearch and Kibana conventionally share a host with Kibana on
           port 5601, so an explicit port in ``base_url`` is rewritten to 5601
           regardless of its value (not only the Elasticsearch default 9200).
        3. When ``base_url`` carries no explicit port (for example a hostname
           behind a reverse proxy), the Kibana location cannot be inferred
           reliably, so the Elasticsearch host is returned and a warning is
           logged rather than silently emitting a wrong link. Set
           ``ELASTIC_KIBANA_URL`` to control the trace link in that case.

        In every derived (non-configured) case the URL is rebuilt from the
        scheme, host and port only; any userinfo/credentials present in
        ``base_url`` are never propagated into the trace link or the logs.

        Returns:
            The Kibana base URL without a trailing slash.

        """
        kibana_url = getattr(self.config.elastic, "kibana_url", None)
        if kibana_url:
            return str(kibana_url).rstrip("/")

        base_url = str(self.config.elastic.base_url).rstrip("/")
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        if ":" in host:  # bracket IPv6 literals
            host = f"[{host}]"

        # Always rebuild from scheme/host(/port) only, dropping any userinfo:
        # credentials in base_url (https://user:pass@host) must never leak into
        # a stored trace link or into the warning logged below. The no-port
        # fallback reuses the shared redact_userinfo helper so the credential
        # stripping is defined in exactly one place (see services/utils/url.py).
        if parsed.port is not None and host:
            return urlunparse(parsed._replace(netloc=f"{host}:5601")).rstrip("/")

        sanitized = redact_userinfo(base_url).rstrip("/")
        self.logger.warning(
            f"{LOG_PREFIX} Cannot derive a Kibana base URL from '{sanitized}': "
            "no explicit port to rewrite to 5601. Set ELASTIC_KIBANA_URL for "
            "correct trace links; using the Elasticsearch base URL as-is."
        )
        return sanitized

    def _resolve_alert_url(self, alert_url: str) -> str | None:
        """Validate and resolve the canonical Kibana alert URL for the trace link.

        ``kibana.alert.url`` is generated by Elastic from Kibana's
        ``server.publicBaseUrl``; a correctly configured Kibana (including
        on-prem) already emits a reachable link, so by default it is used
        verbatim - the same contract a connector/SOAR relies on. When
        ``ELASTIC_KIBANA_URL`` is explicitly configured (the reachable Kibana),
        the link's scheme and host are rebased onto it.

        The value comes from an alert document, so it is treated as untrusted:

        * It is only accepted when it is an ``http(s)`` URL with a host. Anything
          else (e.g. a ``javascript:`` / ``data:`` link injected via a tampered
          alert) is rejected (returns ``None``) so the caller falls back to a
          collector-built link.
        * Any embedded credentials (``https://user:pass@host``) are stripped and
          never propagated into the stored/displayed link.
        * When ``ELASTIC_KIBANA_URL`` is set, only the path is trusted: the
          scheme and host are replaced with the configured Kibana, neutralising a
          rogue host outright.
        * When ``ELASTIC_KIBANA_URL`` is unset, the host is trusted only when it
          matches the configured Elasticsearch host (a co-located Kibana). A
          different, unverifiable host falls back to the collector-built link
          rather than emit a possibly rogue link to a SOC analyst.

        Args:
            alert_url: The alert's ``kibana.alert.url``.

        Returns:
            A safe trace link, or ``None`` when the alert URL is unusable/unsafe.

        """
        try:
            parsed = urlparse(alert_url)
        except Exception:
            return None
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            self.logger.warning(
                f"{LOG_PREFIX} Ignoring non-http(s) kibana.alert.url in trace link "
                "(rejected untrusted scheme/host); using a collector-built link."
            )
            return None

        # Never propagate credentials embedded in the alert URL, whatever the host.
        if parsed.username or parsed.password:
            host = parsed.hostname or ""
            if ":" in host:  # bracket IPv6 literal
                host = f"[{host}]"
            if parsed.port:
                host = f"{host}:{parsed.port}"
            parsed = parsed._replace(netloc=host)

        configured = getattr(self.config.elastic, "kibana_url", None)
        if configured:
            try:
                base = urlparse(str(configured).rstrip("/"))
                rebased = parsed._replace(scheme=base.scheme, netloc=base.netloc)
                return urlunparse(rebased)
            except Exception as e:
                self.logger.warning(
                    f"{LOG_PREFIX} Failed to rebase alert URL onto "
                    f"ELASTIC_KIBANA_URL: {e}"
                )
                return None

        # ELASTIC_KIBANA_URL unset: trust the alert host only if it is the
        # Elasticsearch host (co-located Kibana). Otherwise it cannot be verified
        # as the real Kibana, so fall back to a collector-built link.
        try:
            es_host = urlparse(str(self.config.elastic.base_url)).hostname
        except Exception:
            es_host = None
        alert_host = parsed.hostname
        if es_host and alert_host and alert_host.lower() == es_host.lower():
            return urlunparse(parsed)
        self.logger.warning(
            f"{LOG_PREFIX} kibana.alert.url host is not the Elastic host and "
            "ELASTIC_KIBANA_URL is unset; using a collector-built link. Set "
            "ELASTIC_KIBANA_URL to trust a separate Kibana host."
        )
        return None

    def _build_trace_url_from_alert_id(
        self, alert_id: str, alert_time: str | None = None
    ) -> str:
        """Build a Kibana Security alerts URL pointing at one specific alert.

        Filters the Security alerts view on ``kibana.alert.uuid`` so the link
        opens the exact alert that was matched and verified against the
        expectation signatures - the SOC pivot to a single alert, rather than a
        broad IP search or the full alerts dashboard.

        Args:
            alert_id: The alert's ``kibana.alert.uuid`` (or ES ``_id``).
            alert_time: The alert's ``@timestamp`` (ISO 8601), used to anchor the
                time range so the alert is in view.

        Returns:
            Kibana Security alerts URL for that single alert, or an empty
            string if no base URL can be derived.

        """
        try:
            web_base_url = self._derive_kibana_base_url()
            if not web_base_url:
                return ""
            kql_query = f'kibana.alert.uuid: "{alert_id}"'
            return self._build_alerts_url(web_base_url, kql_query, alert_time)
        except Exception as e:
            self.logger.warning(f"{LOG_PREFIX} Failed to build alert-id trace URL: {e}")
            return ""

    def _build_alerts_url(
        self, web_base_url: str, kql_query: str, alert_time: str | None = None
    ) -> str:
        """Assemble a Kibana Security alerts deep link that actually filters.

        The Security Solution alerts page reads its global KQL query and time
        range from rison-encoded URL state, not from a plain ``query=<kql>``
        parameter (that is silently ignored, landing on the unfiltered alerts
        dashboard). This builds the rison ``query`` and ``timerange`` app-state
        so the page opens filtered to the matched alert(s), the way a SOC analyst
        pivots from a lead to the underlying alert.

        Args:
            web_base_url: Kibana base URL (no trailing slash).
            kql_query: The KQL to apply (e.g. ``kibana.alert.uuid: "<id>"``).
            alert_time: Alert ``@timestamp`` (ISO 8601). When present the range
                is +/-1h around it (absolute); otherwise a relative last-24h
                window is used.

        Returns:
            The deep link URL.

        """
        # rison: single-quoted strings, () objects, !( ) arrays, !t/!f bools.
        query_rison = f"(language:kuery,query:'{self._rison_str(kql_query)}')"
        from_val, to_val, kind = self._rison_timerange(alert_time)
        timerange_rison = (
            "(global:(linkTo:!(),timerange:"
            f"(from:'{from_val}',kind:{kind},to:'{to_val}')))"
        )
        return (
            f"{web_base_url}/app/security/alerts"
            f"?query={quote(query_rison, safe='')}"
            f"&timerange={quote(timerange_rison, safe='')}"
        )

    @staticmethod
    def _rison_str(value: str) -> str:
        """Escape a string for use inside a single-quoted rison literal."""
        # In rison a single quote and a bang are escaped with a leading bang.
        return value.replace("!", "!!").replace("'", "!'")

    def _rison_timerange(self, alert_time: str | None) -> tuple[str, str, str]:
        """Compute (from, to, kind) for the alerts time range.

        Anchors an absolute +/-1h window on the alert time so the specific alert
        is in view; falls back to a relative last-24h window when the alert time
        is missing or unparseable.
        """
        if alert_time:
            try:
                ts = datetime.fromisoformat(str(alert_time).replace("Z", "+00:00"))
                start = (ts - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                end = (ts + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                return start, end, "absolute"
            except (ValueError, TypeError):
                self.logger.debug(
                    f"{LOG_PREFIX} Unparseable alert_time '{alert_time}', "
                    "using relative range"
                )
        return "now-24h", "now", "relative"

    def _build_trace_url_from_expectation(
        self, expectation: DetectionExpectation | PreventionExpectation
    ) -> str:
        """Build a Kibana Security alerts URL from the expectation signatures.

        Reuses ``client_api._build_search_criteria`` to extract the source and
        destination IPs from the expectation signatures, then builds a Kibana
        KQL query from those IPs only. Unlike the Elasticsearch ``_search``
        query built by ``client_api._build_query``, this URL does not include
        the parent-process ``url.path`` match or the ``@timestamp`` time window.

        Args:
            expectation: The expectation object with signatures.

        Returns:
            Kibana Security alerts URL filtered by the expectation's source and
            destination IPs.

        Raises:
            ElasticDataConversionError: If URL building fails.

        """
        try:
            if not hasattr(self.config, "elastic"):
                self.logger.warning(
                    f"{LOG_PREFIX} No Elastic Security config available, returning empty URL"
                )
                return ""

            web_base_url = self._derive_kibana_base_url()
            self.logger.debug(f"{LOG_PREFIX} Using Kibana base URL: {web_base_url}")

            search_signatures = []
            for sig in expectation.inject_expectation_signatures:
                search_signatures.append({"type": sig.type.value, "value": sig.value})

            search_criteria = self.client_api._build_search_criteria(search_signatures)
            kql_parts = []
            for ip in search_criteria.source_ips or []:
                kql_parts.append(f'source.ip:"{ip}"')
            for ip in search_criteria.target_ips or []:
                kql_parts.append(f'destination.ip:"{ip}"')
            kql_query = " or ".join(kql_parts)

            url = self._build_alerts_url(web_base_url, kql_query)

            self.logger.debug(f"{LOG_PREFIX} Built trace URL with query: {kql_query}")
            return url

        except Exception as e:
            raise ElasticDataConversionError(f"Error building trace URL: {e}") from e

    def get_service_info(self) -> dict[str, Any]:
        """Get information about this trace service.

        Returns:
            Dictionary containing service metadata and capabilities.

        """
        info = {
            "service_type": "elastic_trace",
            "supported_result_types": ["Elastic Security processing results"],
            "creates_detection_traces": True,
            "creates_prevention_traces": False,
            "description": "Creates traces from Elastic Security expectation processing results",
        }
        self.logger.debug(f"{LOG_PREFIX} Trace service info: {info}")
        return info
