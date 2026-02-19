from typing import List, Optional

from pydantic import BaseModel


class AlertEvent(BaseModel):
    actor_process_image_name: Optional[str] = None


class Alert(BaseModel):
    external_id: str
    severity: str
    matching_status: str
    case_id: int
    alert_id: int
    actor_process_command_line: Optional[str] = ""
    category: str
    description: str
    action: str
    action_pretty: str
    detection_timestamp: int
    events: Optional[List[AlertEvent]] = None

    def get_process_image_names(self) -> list[str]:
        """Extract actor_process_image_name from all events."""
        if not self.events:
            return []
        return [
            e.actor_process_image_name
            for e in self.events
            if e.actor_process_image_name
        ]


class Alerts(BaseModel):
    total_count: int
    data: List[Alert]


class FileArtifact(BaseModel):
    file_name: str


class FileArtifacts(BaseModel):
    total_count: int
    data: List[FileArtifact]


class GetAlertsResponseItem(BaseModel):
    total_count: Optional[int]
    result_count: Optional[int]
    alerts: List[Alert]


class GetAlertsResponse(BaseModel):
    reply: GetAlertsResponseItem


class IncidentItem(BaseModel):
    incident_id: int


class Incident(BaseModel):
    incident: IncidentItem
    alerts: Alerts
    file_artifacts: FileArtifacts


class GetIncidentsResponseItem(BaseModel):
    total_count: Optional[int]
    result_count: Optional[int]
    incidents: List[IncidentItem]


class GetIncidentsResponse(BaseModel):
    reply: GetIncidentsResponseItem


class GetIncidentExtraDataResponse(BaseModel):
    reply: Incident
