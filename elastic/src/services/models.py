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
            alert = ElasticAlert(
                time=_first(source, ["@timestamp", "kibana.alert.original_time"]) or "",
                src_ip=_first(source, ["source.ip", "client.ip"]),
                dst_ip=_first(source, ["destination.ip", "server.ip"]),
                url_path=_first(
                    source, ["url.path", "url.original", "http.request.referrer"]
                ),
                signature=rule_name,
                rule_name=rule_name,
                event_type=_first(source, ["event.category", "event.action"]),
                severity=_first(source, ["kibana.alert.severity", "event.severity"]),
            )
            alerts.append(alert)

        return cls(results=alerts)
