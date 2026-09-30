from collections import defaultdict
from datetime import datetime
from typing import Any, Literal

from pydantic import AnyHttpUrl, BaseModel, Field, model_validator
from pyoaev.signatures.types import SignatureTypes
from src.collector.models.data import OAEVData, TraceData
from src.source.models.evidences import Evidence


class Alert(BaseModel):
    id: str
    title: str
    status: Literal["unknown", "new", "inProgress", "resolved", "unknownFutureValue"]
    service_source: str = Field(
        ...,
        alias="serviceSource",
        description="The service or product that created this alert.",
    )
    alert_web_url: AnyHttpUrl = Field(
        ...,
        alias="alertWebUrl",
        description="URL for the Microsoft 365 Defender portal alert page.",
    )
    created_date_time: datetime = Field(
        ...,
        alias="createdDateTime",
        description="Time when Microsoft 365 Defender created the alert.",
    )
    evidence: list[Evidence]
    raw: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def save_raw_alert_if_missing_or_empty(cls, data: Any) -> Any:
        if isinstance(data, dict) and not data.get("raw"):
            return {**data, "raw": dict(data)}
        return data

    def _extract_evidences(self) -> defaultdict[SignatureTypes, set[str]]:
        """Cycle through all evidence to extract signature-related elements."""
        evidences_data: defaultdict[SignatureTypes, set[str]] = defaultdict(set)

        for el in self.evidence:
            subdata = el.extract_evidences()
            for key, value in subdata.items():
                evidences_data[key].update(value)

        return evidences_data

    def to_oaev_data(self) -> OAEVData:
        """Serialize the evidence data as an OAEVData object."""
        data = self._extract_evidences()
        data = {sig_type.value: evidences for sig_type, evidences in data.items()}
        return OAEVData(**data)

    def to_traces_data(self) -> TraceData:
        """Serialize metadata from the alert into a TraceData object."""
        return TraceData(
            alert_name=self.title,
            alert_link=self.alert_web_url,
            alert_date=self.created_date_time,
        )

    def is_prevented(self) -> bool:
        """Determine if the threat is/has been prevented."""
        return self.status in ["inProgress", "resolved"]

    def is_detected(self) -> bool:
        """By essence, the element is detected if an alert has been created."""
        return True

    def __str__(self) -> str:
        """Str output for logging purposes."""
        return f"{self.service_source} alert id {self.id}: {self.title}"
