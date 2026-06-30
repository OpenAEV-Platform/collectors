"""OAEV data models: OAEVData and TraceData."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import AnyUrl, BaseModel, Field

__all__ = ["OAEVData", "TraceData"]


class OAEVData(BaseModel, extra="allow"):
    """Source-side version of OAEV formatted data.

    Accepts dynamic extra fields that must be valid signature type names.
    """

    __pydantic_extra__: dict[str, str] = Field(default_factory=dict)

    def __str__(self) -> str:
        """Readable string representation."""
        text = ", ".join(
            f"{key}='{value}'" for key, value in self.model_dump().items()
        )
        return f"OAEVData({text})"


class TraceData(BaseModel, frozen=True):
    """Trace data for expectation alert tracking."""

    alert_name: str = Field(..., description="Alert name")
    alert_link: AnyUrl = Field(..., description="Alert link")
    alert_date: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Alert date"
    )

    def __str__(self) -> str:
        """Readable string representation."""
        return (
            f"TraceData(alert_name='{self.alert_name}', "
            f"alert_link='{self.alert_link}', "
            f"alert_date='{self.alert_date}')"
        )
