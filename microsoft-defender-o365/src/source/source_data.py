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
                verbatim. If None, the instance is empty (no placeholder).
        """
        self.raw_alert = raw_alert
        self.value = raw_alert.get("id") if raw_alert else None

    def to_oaev_data(self) -> OAEVData:
        """Serialize source data into OAEVData."""
        return OAEVData(parent_process_name=self.value or "")

    def to_traces_data(self) -> TraceData:
        """Serialize traces data into TraceData."""
        alert_web_url = self.raw_alert.get("alertWebUrl") if self.raw_alert else None
        return TraceData(
            alert_name=f"Alert {self.value}" if self.value else "",
            alert_link=alert_web_url,
        )

    def is_prevented(self) -> bool:
        """Determine if the threat is prevented.

        Status interpretation is out of scope for this chunk; returns False.
        """
        return False

    def is_detected(self) -> bool:
        """Determine if the threat is detected.

        Status interpretation is out of scope for this chunk; returns False.
        """
        return False

    def __str__(self) -> str:
        """Str output of the source data for logging purposes."""
        return str(self.value) if self.value else "<empty>"
