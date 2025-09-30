"""Splunk ES Data Models.

This module provides Pydantic models for Splunk ES operations.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field, PrivateAttr, field_validator


class SplunkESSearchCriteria(BaseModel):
    """Search criteria for Splunk ES queries."""

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


class SplunkESAlert(BaseModel):
    """Splunk ES alert model with consolidated fields using aliases."""

    time: str = Field(..., description="Alert timestamp")
    src_ip: Optional[str] = Field(None, description="Consolidated source IP address")
    dst_ip: Optional[str] = Field(
        None, description="Consolidated destination IP address"
    )
    url_path: Optional[str] = Field(None, description="Consolidated URL path")
    signature: Optional[str] = Field(None, description="Alert signature")
    rule_name: Optional[str] = Field(
        None, description="Rule name that triggered the alert"
    )
    event_type: Optional[str] = Field(None, description="Type of security event")
    severity: Optional[str] = Field(None, description="Alert severity level")
    _raw: Optional[dict[str, Any]] = PrivateAttr(default=None)

    @field_validator("src_ip", mode="before")
    @classmethod
    def consolidate_source_ip(cls, v: Optional[str], info: Any) -> Any:
        """Consolidate various source IP field names into src_ip."""
        if v:
            return v
        raw_data = info.data.get("_raw", {}) if hasattr(info, "data") else {}
        if isinstance(raw_data, dict):
            for field_name in ["src", "source_ip", "client_ip"]:
                if raw_data.get(field_name):
                    return raw_data[field_name]
        return v

    @field_validator("dst_ip", mode="before")
    @classmethod
    def consolidate_dest_ip(cls, v: Optional[str], info: Any) -> Any:
        """Consolidate various destination IP field names into dst_ip."""
        if v:
            return v
        raw_data = info.data.get("_raw", {}) if hasattr(info, "data") else {}
        if isinstance(raw_data, dict):
            for field_name in ["dest", "dest_ip", "destination_ip", "server_ip"]:
                if raw_data.get(field_name):
                    return raw_data[field_name]
        return v

    @field_validator("url_path", mode="before")
    @classmethod
    def consolidate_url_path(cls, v: Optional[str], info: Any) -> Any:
        """Consolidate various URL field names into url_path."""
        if v:
            return v
        raw_data = info.data.get("_raw", {}) if hasattr(info, "data") else {}
        if isinstance(raw_data, dict):
            for field_name in ["url", "path", "query"]:
                if raw_data.get(field_name):
                    return raw_data[field_name]
        return v


class SplunkESResponse(BaseModel):
    """Response from Splunk ES API."""

    results: list[SplunkESAlert] = Field(
        default_factory=list, description="List of Splunk ES alerts"
    )

    @classmethod
    def from_raw_response(cls, response_data: dict[str, Any]) -> "SplunkESResponse":
        """Create from raw API response.

        Args:
            response_data: Raw response data from the Splunk ES API.

        Returns:
            SplunkESResponse instance with parsed alerts.

        """
        alerts = []
        raw_results = response_data.get("results", [])

        for raw_result in raw_results:
            alert = SplunkESAlert(
                time=raw_result.get("_time", ""),
                src_ip=(
                    raw_result.get("src_ip")
                    or raw_result.get("src")
                    or raw_result.get("source_ip")
                    or raw_result.get("client_ip")
                ),
                dst_ip=(
                    raw_result.get("dst_ip")
                    or raw_result.get("dest")
                    or raw_result.get("dest_ip")
                    or raw_result.get("destination_ip")
                    or raw_result.get("server_ip")
                ),
                url_path=(
                    raw_result.get("url_path")
                    or raw_result.get("url")
                    or raw_result.get("path")
                    or raw_result.get("query")
                ),
                signature=raw_result.get("signature"),
                rule_name=raw_result.get("rule_name"),
                event_type=raw_result.get("event_type"),
                severity=raw_result.get("severity"),
                _raw=raw_result,
            )
            alerts.append(alert)

        return cls(results=alerts)
