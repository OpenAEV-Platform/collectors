"""LogRhythm Data Models.

This module provides Pydantic models for LogRhythm Search API operations.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field, PrivateAttr


def _first(row: dict[str, Any], keys: list[str]) -> Optional[str]:
    """Return the first non-empty value among several result item keys."""
    for key in keys:
        value = row.get(key)
        if isinstance(value, list) and value:
            value = value[0]
        if value not in (None, ""):
            return str(value)
    return None


class LogRhythmSearchCriteria(BaseModel):
    """Search criteria for LogRhythm Search API queries."""

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


class LogRhythmAlert(BaseModel):
    """LogRhythm alert model (mapped from a Search API result item)."""

    time: str = Field(..., description="Event timestamp")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Impacted/destination IP address")
    url_path: Optional[str] = Field(None, description="URL value")
    signature: Optional[str] = Field(None, description="Common event / classification")
    rule_name: Optional[str] = Field(None, description="MPE rule name")
    event_type: Optional[str] = Field(None, description="Classification name")
    severity: Optional[str] = Field(None, description="Priority / risk")
    _raw: Optional[dict[str, Any]] = PrivateAttr(default=None)


class LogRhythmResponse(BaseModel):
    """Response from the LogRhythm Search API results endpoint."""

    results: list[LogRhythmAlert] = Field(
        default_factory=list, description="List of LogRhythm alerts"
    )

    @classmethod
    def from_raw_response(cls, response_data: dict[str, Any]) -> "LogRhythmResponse":
        """Create from a raw LogRhythm search-result response.

        Args:
            response_data: Raw response from ``/actions/search-result``.

        Returns:
            LogRhythmResponse instance with parsed alerts.

        """
        alerts = []
        items = response_data.get("Items")
        if items is None:
            items = response_data.get("items", [])
        if not isinstance(items, list):
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue
            alert = LogRhythmAlert(
                time=_first(item, ["normalDateMin", "normalDate", "insertedDate"])
                or "",
                src_ip=_first(item, ["originIp", "sourceIp", "sip", "sourceIP"]),
                dst_ip=_first(
                    item, ["impactedIp", "destinationIp", "dip", "impactedIP"]
                ),
                url_path=_first(item, ["url", "URL", "object", "objectName"]),
                signature=_first(item, ["commonEventName", "classificationName"]),
                rule_name=_first(item, ["mpeRuleName", "ruleName", "commonEventName"]),
                event_type=_first(item, ["classificationName", "classificationType"]),
                severity=_first(item, ["priority", "risk", "severity"]),
                _raw=item,
            )
            alerts.append(alert)

        return cls(results=alerts)
