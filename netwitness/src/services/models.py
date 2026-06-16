"""NetWitness Data Models.

This module provides Pydantic models for NetWitness Core SDK query operations.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field, PrivateAttr


def _meta_str(meta: dict[str, Any], keys: list[str]) -> Optional[str]:
    """Return the first non-empty meta value among several meta keys."""
    for key in keys:
        value = meta.get(key)
        if isinstance(value, list) and value:
            value = value[0]
        if value not in (None, ""):
            return str(value)
    return None


class NetWitnessSearchCriteria(BaseModel):
    """Search criteria for NetWitness Core SDK queries."""

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


class NetWitnessAlert(BaseModel):
    """NetWitness alert model (mapped from a grouped SDK query result)."""

    time: str = Field(..., description="Session time")
    src_ip: Optional[str] = Field(None, description="Source IP address (ip.src)")
    dst_ip: Optional[str] = Field(None, description="Destination IP address (ip.dst)")
    url_path: Optional[str] = Field(None, description="URL meta value")
    signature: Optional[str] = Field(None, description="Alert / risk meta")
    rule_name: Optional[str] = Field(None, description="Rule / alert name")
    event_type: Optional[str] = Field(None, description="Service / event category")
    severity: Optional[str] = Field(None, description="Risk severity")
    _raw: Optional[dict[str, Any]] = PrivateAttr(default=None)


class NetWitnessResponse(BaseModel):
    """Response from the NetWitness Core SDK query API."""

    results: list[NetWitnessAlert] = Field(
        default_factory=list, description="List of NetWitness alerts"
    )

    @classmethod
    def from_raw_response(cls, response_data: dict[str, Any]) -> "NetWitnessResponse":
        """Create from a raw SDK ``msg=query`` response.

        The SDK returns a flat list of meta ``fields`` tagged with a ``group``
        (session) identifier; this groups them back into per-session records.

        Args:
            response_data: Raw response from ``/sdk?msg=query``.

        Returns:
            NetWitnessResponse instance with parsed alerts.

        """
        results = response_data.get("results", {})
        fields = results.get("fields", []) if isinstance(results, dict) else []
        if not isinstance(fields, list):
            fields = []

        grouped: dict[Any, dict[str, Any]] = {}
        order: list[Any] = []
        for field in fields:
            if not isinstance(field, dict):
                continue
            group = field.get("group", 0)
            meta_type = field.get("type")
            if group not in grouped:
                grouped[group] = {}
                order.append(group)
            if meta_type and meta_type not in grouped[group]:
                grouped[group][meta_type] = field.get("value")

        alerts = []
        for group in order:
            meta = grouped[group]
            alert = NetWitnessAlert(
                time=_meta_str(meta, ["time", "event.time"]) or "",
                src_ip=_meta_str(meta, ["ip.src", "ipv6.src"]),
                dst_ip=_meta_str(meta, ["ip.dst", "ipv6.dst"]),
                url_path=_meta_str(meta, ["url", "web.host", "alias.host"]),
                signature=_meta_str(meta, ["alert", "risk.info", "risk.warning"]),
                rule_name=_meta_str(meta, ["alert.id", "rule.name"]),
                event_type=_meta_str(meta, ["service", "event.cat.name"]),
                severity=_meta_str(meta, ["risk", "severity"]),
                _raw=meta,
            )
            alerts.append(alert)

        return cls(results=alerts)
