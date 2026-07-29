import secrets
from typing import Any

from src.collector.models.data import OAEVData, TraceData


class MicrosoftDefenderO365SourceData:
    """Source data wrapper for Microsoft Defender O365 alerts.

    Stores the raw alert dict verbatim so CHK.7 can serialize it without
    information loss. Accepts raw_alert parameter while maintaining
    backward compatibility with no-arg construction.
    """

    def __init__(self, raw_alert: dict[str, Any] | None = None) -> None:
        """Initialize source data with optional raw alert dict.

        Args:
            raw_alert: The original Graph Security API alert dict, preserved
                verbatim. If None, generates a placeholder value.
        """
        self.raw_alert = raw_alert
        if raw_alert is None:
            self.value = secrets.token_hex(8)
        else:
            self.value = raw_alert.get("id", secrets.token_hex(8))

    def to_oaev_data(self) -> OAEVData:
        """Serialize source data into OAEVData"""
        return OAEVData(parent_process_name=f"{self.value}")

    def to_traces_data(self) -> TraceData:
        """Serialize traces data into TraceData"""
        alert_web_url = self.raw_alert.get("alertWebUrl") if self.raw_alert else None
        return TraceData(
            alert_name=f"Alert {self.value}",
            alert_link=alert_web_url or f"http://fake.url/{self.value}",
        )

    def is_prevented(self) -> bool:
        """Placeholder analysis of the data to determine if the threat is prevented"""
        if self.raw_alert:
            status = self.raw_alert.get("status", "")
            return status in ("closed", "resolved")
        return bool(secrets.randbits(1))

    def is_detected(self) -> bool:
        """Placeholder analysis of the data to determine if the threat is detected"""
        if self.raw_alert:
            status = self.raw_alert.get("status", "")
            return status in ("new", "active", "inProgress")
        return bool(secrets.randbits(1))

    def __str__(self) -> str:
        """Str output of the source data for logging purposes"""
        return f"{self.value}"
