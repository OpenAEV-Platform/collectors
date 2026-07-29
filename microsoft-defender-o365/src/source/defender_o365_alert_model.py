"""Pydantic models for Microsoft Defender O365 Graph Security API v2 alerts.

Intermediate representation between raw Graph API response and
DefenderO365SourceData. Validates alert structure and filters evidence
to keep only analyzedMessageEvidence items.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EmailSender(BaseModel):
    """Email sender information from analyzed message evidence."""

    email_address: str | None = Field(None, alias="emailAddress")
    display_name: str | None = Field(None, alias="displayName")
    domain_name: str | None = Field(None, alias="domainName")


class AnalyzedMessageEvidence(BaseModel):
    """Analyzed message evidence from a Defender O365 alert."""

    network_message_id: str | None = Field(None, alias="networkMessageId")
    internet_message_id: str | None = Field(None, alias="internetMessageId")
    subject: str | None = None
    received_date_time: datetime | None = Field(None, alias="receivedDateTime")
    recipient_email_address: str | None = Field(None, alias="recipientEmailAddress")
    sender_ip: str | None = Field(None, alias="senderIp")
    p1_sender: EmailSender | None = Field(None, alias="p1Sender")
    p2_sender: EmailSender | None = Field(None, alias="p2Sender")
    delivery_action: str | None = Field(None, alias="deliveryAction")
    delivery_location: str | None = Field(None, alias="deliveryLocation")
    threats: list[str] = []
    threat_detection_methods: list[str] = Field(default_factory=list, alias="threatDetectionMethods")
    urls: list[str] = []
    url_count: int | None = Field(None, alias="urlCount")
    attachments_count: int | None = Field(None, alias="attachmentsCount")


class DefenderO365Alert(BaseModel):
    """Intermediate Pydantic model for Graph Security API v2 alert validation.

    Maps the Graph Security Alert v2 schema fields to a typed representation.
    Used by the data fetcher to validate and filter raw API responses before
    wrapping in DefenderO365SourceData.
    """

    model_config = {"populate_by_name": True}

    id: str = Field(..., alias="id")
    provider_alert_id: str | None = Field(None, alias="providerAlertId")
    incident_id: str | None = Field(None, alias="incidentId")
    incident_web_url: str | None = Field(None, alias="incidentWebUrl")
    alert_web_url: str | None = Field(None, alias="alertWebUrl")
    title: str = Field(...)
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    classification: str | None = Field(None, alias="classification")
    determination: str | None = Field(None, alias="determination")
    service_source: str = Field(..., alias="serviceSource")
    detection_source: str | None = Field(None, alias="detectionSource")
    categories: list[str] = []
    mitre_techniques: list[str] = Field(default_factory=list, alias="mitreTechniques")
    evidence: list[dict[str, Any]] = []
    created_date_time: datetime = Field(..., alias="createdDateTime")
    last_update_date_time: datetime | None = Field(None, alias="lastUpdateDateTime")
    first_activity_date_time: datetime | None = Field(None, alias="firstActivityDateTime")
    last_activity_date_time: datetime | None = Field(None, alias="lastActivityDateTime")
    threat_display_name: str | None = Field(None, alias="threatDisplayName")
    threat_family_name: str | None = Field(None, alias="threatFamilyName")
    raw: dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def _is_analyzed_message_evidence(item: dict[str, Any]) -> bool:
        """Check if an evidence item is analyzedMessageEvidence type."""
        odata_type = item.get("@odata.type", "")
        return "analyzedMessageEvidence" in odata_type

    def filter_evidence(self) -> list[AnalyzedMessageEvidence]:
        """Filter evidence to keep only analyzedMessageEvidence items.

        Returns:
            A list of AnalyzedMessageEvidence instances parsed from the
            alert's evidence field.
        """
        filtered = []
        for item in self.evidence:
            if self._is_analyzed_message_evidence(item):
                try:
                    evidence = AnalyzedMessageEvidence.model_validate(item)
                    filtered.append(evidence)
                except Exception:
                    # Skip malformed evidence items
                    continue
        return filtered

    @classmethod
    def model_validate(cls, obj: dict[str, Any]) -> "DefenderO365Alert":
        """Validate and parse a raw alert dict.

        Args:
            obj: The raw alert dict from the Graph Security API.

        Returns:
            A validated DefenderO365Alert instance with the raw dict preserved.
        """
        # Store the original raw dict before validation transforms it
        validated = super().model_validate(obj)
        validated.raw = obj
        return validated
