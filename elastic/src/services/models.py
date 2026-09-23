"""Elastic Security Data Models.

This module provides Pydantic models for Elastic Security operations.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field


def _dig(source: dict[str, Any], dotted: str) -> Optional[Any]:
    """Read a value from an ES ``_source`` by dotted path or nested traversal.

    Elastic documents may store ECS fields either flattened (``"source.ip"``)
    or nested (``{"source": {"ip": ...}}``); this resolves both.

    Args:
        source: The ``_source`` dictionary of an Elasticsearch hit.
        dotted: The dotted ECS field path (e.g. ``source.ip``).

    Returns:
        The resolved value, or ``None`` if absent.

    """
    if dotted in source:
        return source[dotted]
    current: Any = source
    for part in dotted.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _first(source: dict[str, Any], dotted_paths: list[str]) -> Optional[str]:
    """Return the first present value among several dotted ECS paths.

    A value counts as present when it is not ``None``, not an empty string,
    and not an empty container. Falsy-but-valid scalars such as ``0`` (e.g.
    ECS ``event.severity: 0``) or ``False`` are preserved rather than being
    silently dropped; only genuinely missing values are skipped.
    """
    for path in dotted_paths:
        value = _dig(source, path)
        if isinstance(value, list):
            if not value:
                continue
            value = value[0]
        if value is None:
            continue
        if isinstance(value, (str, list, dict, set, tuple)) and len(value) == 0:
            continue
        return str(value)
    return None


def _all(source: dict[str, Any], dotted_paths: list[str]) -> list[str]:
    """Collect every value found across several dotted ECS paths as a flat list.

    ECS fields such as ``host.ip`` are multi-valued (an array of every address
    on the host). Correlation must consider all of them - not just the first,
    which is often a link-local IPv6 - so this flattens and de-duplicates every
    present value while preserving order.
    """
    out: list[str] = []
    for path in dotted_paths:
        value = _dig(source, path)
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if item is None or item == "":
                continue
            text = str(item)
            if text not in out:
                out.append(text)
    return out


class ElasticSearchCriteria(BaseModel):
    """Search criteria for Elastic Security queries."""

    source_ips: Optional[list[str]] = Field(
        default_factory=list, description="Source IP addresses to search for"
    )
    target_ips: Optional[list[str]] = Field(
        default_factory=list, description="Target IP addresses to search for"
    )
    parent_process_names: Optional[list[str]] = Field(
        default_factory=list, description="Parent process names to search for"
    )
    start_date: Optional[str] = Field(
        None, description="Start date for the search in ISO format"
    )
    end_date: Optional[str] = Field(
        None, description="End date for the search in ISO format"
    )


class ElasticAlert(BaseModel):
    """Elastic Security alert model (mapped from an Elasticsearch hit)."""

    time: str = Field(..., description="Alert timestamp")
    src_ip: Optional[str] = Field(None, description="Source IP address (source.ip)")
    host_ips: list[str] = Field(
        default_factory=list,
        description=(
            "All IP addresses of the endpoint the alert fired on (host.ip). "
            "Used as additional source-IP correlation candidates for "
            "endpoint/process alerts that carry no source.ip."
        ),
    )
    host_name: Optional[str] = Field(
        None, description="Host the alert fired on (host.name)."
    )
    pid: Optional[int] = Field(
        None, description="Process id of the alert's process (process.pid)."
    )
    process_entity_id: Optional[str] = Field(
        None,
        description=(
            "Reuse-safe unique id of the alert's process (process.entity_id). "
            "Preferred seed for the implant-marker ancestry drilldown - unlike a "
            "raw pid it is not reused across process lifetimes."
        ),
    )
    implant_marker: Optional[str] = Field(
        None,
        description=(
            "OpenAEV implant marker (oaev-implant-<inject>-agent-<agent>) "
            "recovered from the source process event via the events-index "
            "drilldown. Enables deterministic per-inject correlation."
        ),
    )
    dst_ip: Optional[str] = Field(
        None, description="Destination IP address (destination.ip)"
    )
    url_path: Optional[str] = Field(None, description="URL path (url.path)")
    signature: Optional[str] = Field(None, description="Alert signature / rule name")
    rule_name: Optional[str] = Field(
        None, description="Detection rule name that triggered the alert"
    )
    event_type: Optional[str] = Field(None, description="Type of security event")
    severity: Optional[str] = Field(None, description="Alert severity level")
    alert_id: Optional[str] = Field(
        None,
        description=(
            "Identifier of this specific alert (kibana.alert.uuid, else the ES "
            "document _id). Used to build a trace link to the exact matched "
            "alert rather than a broad IP search."
        ),
    )
    alert_url: Optional[str] = Field(
        None,
        description=(
            "Canonical Kibana deep link to this alert (kibana.alert.url), "
            "generated by the Elastic detection engine from server.publicBaseUrl "
            "- the same link a connector/SOAR would use. Preferred trace link."
        ),
    )


class ElasticResponse(BaseModel):
    """Response from the Elasticsearch ``_search`` API."""

    results: list[ElasticAlert] = Field(
        default_factory=list, description="List of Elastic Security alerts"
    )

    @classmethod
    def from_raw_response(cls, response_data: dict[str, Any]) -> "ElasticResponse":
        """Create from a raw Elasticsearch ``_search`` response.

        Args:
            response_data: Raw response data from the Elasticsearch ``_search`` API.

        Returns:
            ElasticResponse instance with parsed alerts.

        """
        alerts = []
        hits = response_data.get("hits", {})
        hit_list = hits.get("hits", []) if isinstance(hits, dict) else []

        for hit in hit_list:
            source = hit.get("_source", {}) if isinstance(hit, dict) else {}
            if not isinstance(source, dict):
                continue
            rule_name = _first(
                source,
                ["kibana.alert.rule.name", "signal.rule.name", "rule.name"],
            )
            pid_raw = _first(source, ["process.pid"])
            try:
                pid_val = int(pid_raw) if pid_raw is not None else None
            except (TypeError, ValueError):
                pid_val = None
            alert = ElasticAlert(
                time=_first(source, ["@timestamp", "kibana.alert.original_time"]) or "",
                src_ip=_first(source, ["source.ip", "client.ip"]),
                host_ips=_all(source, ["host.ip", "source.ip", "client.ip"]),
                host_name=_first(source, ["host.name"]),
                pid=pid_val,
                process_entity_id=_first(source, ["process.entity_id"]),
                dst_ip=_first(source, ["destination.ip", "server.ip"]),
                url_path=_first(
                    source, ["url.path", "url.original", "http.request.referrer"]
                ),
                signature=rule_name,
                rule_name=rule_name,
                event_type=_first(source, ["event.category", "event.action"]),
                severity=_first(source, ["kibana.alert.severity", "event.severity"]),
                alert_id=_first(source, ["kibana.alert.uuid", "signal._meta.uuid"])
                or (hit.get("_id") if isinstance(hit, dict) else None),
                alert_url=_first(source, ["kibana.alert.url"]),
            )
            alerts.append(alert)

        return cls(results=alerts)
