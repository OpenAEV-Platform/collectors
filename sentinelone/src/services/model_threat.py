"""SentinelOne Threat Models."""

from typing import Any, Optional

from pydantic import BaseModel, Field, PrivateAttr


class SentinelOneThreat(BaseModel):
    """SentinelOne threat model."""

    threat_id: str = Field(..., description="Unique identifier for the threat")
    hostname: Optional[str] = Field(None, description="Agent computer name")
    is_mitigated: bool = Field(False, description="Whether threat has been mitigated")
    is_static: bool = Field(False, description="Whether threat is static")
    _raw: Optional[dict[str, Any]] = PrivateAttr(default=None)

    def __str__(self) -> str:
        """Detaield representation with key debugging information."""
        return (
            f"SentinelOneThreat(threat_id='{self.threat_id}', "
            f"hostname='{self.hostname}', is_mitigated={self.is_mitigated}, is_static={self.is_static})"
        )

    @staticmethod
    def get_parent_process_name_from_events(events: list[dict]) -> list[str]:
        """Extract parent process names from threat events data.

        Args:
            events: List of event dictionaries from threat_events endpoint.

        Returns:
            List of unique parent process names found in events.

        """
        if not events:
            return []

        parent_process_names = set()
        for event in events:
            parent_process_name = event.get("parentProcessName")
            if parent_process_name:
                parent_process_names.add(parent_process_name)

        return list(parent_process_names)


class SentinelOneThreatsResponse(BaseModel):
    """Response from threats endpoint."""

    data: list[SentinelOneThreat] = Field(
        default_factory=list, description="List of SentinelOne threats"
    )

    @classmethod
    def from_raw_response(
        cls, response_data: dict[str, Any]
    ) -> "SentinelOneThreatsResponse":
        """Create from raw API response.

        Args:
            response_data: Raw response data from the threats API.

        Returns:
            SentinelOneThreatsResponse instance with parsed threats.

        """
        threats = []
        raw_threats = response_data.get("data", [])

        for raw_threat in raw_threats:
            threat_info = raw_threat.get("threatInfo", {})
            threat_id = threat_info.get("threatId")

            if threat_id:
                agent_realtime_info = raw_threat.get("agentRealtimeInfo", {})
                hostname = agent_realtime_info.get("agentComputerName")

                mitigation_status = raw_threat.get("mitigationStatus", [])
                is_mitigated = False
                if isinstance(mitigation_status, list):
                    is_mitigated = any(
                        status.get("status") == "success"
                        for status in mitigation_status
                        if isinstance(status, dict)
                    )

                detection_type = threat_info.get("detectionType", "").lower()
                is_static = detection_type == "static"

                threat = SentinelOneThreat(
                    threat_id=threat_id,
                    hostname=hostname,
                    is_mitigated=is_mitigated,
                    is_static=is_static,
                )
                threat._raw = raw_threat
                threats.append(threat)

        return cls(data=threats)
