"""IBM QRadar Data Models.

This module provides Pydantic models for IBM QRadar Ariel search operations.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field


def _first(row: dict[str, Any], keys: list[str]) -> Optional[str]:
    """Return the first non-empty value among several Ariel result keys."""
    for key in keys:
        value = row.get(key)
        if isinstance(value, list) and value:
            value = value[0]
        if value not in (None, ""):
            return str(value)
    return None


class QRadarSearchCriteria(BaseModel):
    """Search criteria for IBM QRadar Ariel queries."""

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


class QRadarAlert(BaseModel):
    """IBM QRadar alert model (mapped from an Ariel search result row)."""

    time: str = Field(..., description="Event timestamp")
    src_ip: Optional[str] = Field(None, description="Source IP address (sourceip)")
    dst_ip: Optional[str] = Field(
        None, description="Destination IP address (destinationip)"
    )
    url_path: Optional[str] = Field(None, description="URL property value")
    signature: Optional[str] = Field(None, description="Event name / QID name")
    rule_name: Optional[str] = Field(
        None, description="Rule name that triggered the event"
    )
    event_type: Optional[str] = Field(None, description="Event category name")
    severity: Optional[str] = Field(None, description="Event severity / magnitude")


class QRadarResponse(BaseModel):
    """Response from the IBM QRadar Ariel results API."""

    results: list[QRadarAlert] = Field(
        default_factory=list, description="List of IBM QRadar alerts"
    )

    @classmethod
    def from_raw_response(
        cls, response_data: dict[str, Any], data_source: str = "events"
    ) -> "QRadarResponse":
        """Create from a raw Ariel results response.

        Args:
            response_data: Raw response from ``/api/ariel/searches/{id}/results``.
            data_source: The Ariel data source name keying the result rows.

        Returns:
            QRadarResponse instance with parsed alerts.

        """
        alerts = []
        rows = response_data.get(data_source, [])
        if not isinstance(rows, list):
            rows = []

        for row in rows:
            if not isinstance(row, dict):
                continue
            alert = QRadarAlert(
                time=_first(row, ["starttime", "Start Time", "devicetime"]) or "",
                src_ip=_first(row, ["sourceip", "Source IP"]),
                dst_ip=_first(row, ["destinationip", "Destination IP"]),
                url_path=_first(row, ["URL", "url", "Filename", "File Path"]),
                signature=_first(row, ["qidname", "QID Name", "eventname"]),
                rule_name=_first(row, ["Rule Name", "rulename", "creeventlist"]),
                event_type=_first(row, ["categoryname", "category"]),
                severity=_first(row, ["severity", "magnitude"]),
            )
            alerts.append(alert)

        return cls(results=alerts)
