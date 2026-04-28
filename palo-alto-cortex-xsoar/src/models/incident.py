from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Alert(BaseModel):
    """Represents an alert inside an XSOAR incident (CustomFields.xdralerts)."""

    alert_id: str
    case_id: Optional[int] = None
    action_pretty: Optional[str] = None
    actor_process_command_line: Optional[str] = None
    actor_process_image_name: Optional[str] = None
    actor_process_image_path: Optional[str] = None
    detection_timestamp: int

    # Fields that were in XDR but might be missing or different in XSOAR
    external_id: Optional[str] = None
    severity: Optional[str] = None
    matching_status: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    action: Optional[str] = None

    def get_process_image_names(self) -> list[str]:
        """Extract actor_process_image_name."""
        if self.actor_process_image_name:
            return [self.actor_process_image_name]
        return []


class CustomFields(BaseModel):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)
    xdralerts: List[Alert] = Field(default_factory=list, alias="xdralerts")


class Incident(BaseModel):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)

    id: str
    name: Optional[str] = None
    type: Optional[str] = None
    status: Optional[int] = None
    severity: Optional[int] = None
    custom_fields: Optional[CustomFields] = Field(None, alias="CustomFields")


class XSOARSearchIncidentsResponse(BaseModel):
    total: int
    data: List[Incident]


class XSOARUser(BaseModel):
    id: str
    username: str
