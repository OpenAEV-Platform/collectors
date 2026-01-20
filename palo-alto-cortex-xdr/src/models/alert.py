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


class GetAlertsResponseItem(BaseModel):
    total_count: Optional[int]
    result_count: Optional[int]
    alerts: List[Alert]


class GetAlertsResponse(BaseModel):
    reply: GetAlertsResponseItem
