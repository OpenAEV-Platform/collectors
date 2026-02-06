from typing import List, Optional

from pydantic import BaseModel


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
