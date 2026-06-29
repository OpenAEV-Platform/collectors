"""Expectation result, trace, and summary models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

__all__ = ["ExpectationResult", "ExpectationTrace", "ExpectationSummary"]


class ExpectationResult(BaseModel):
    """Model for expectation processing results."""

    model_config = {"arbitrary_types_allowed": True}

    expectation_id: str = Field(..., description="ID of the processed expectation")
    is_valid: bool = Field(..., description="Whether the expectation was validated")
    expectation: Any | None = Field(None, description="The original expectation object")
    matched_alerts: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of alerts that matched this expectation",
    )
    error_message: str | None = Field(
        None, description="Error message if processing failed"
    )
    processing_time: float | None = Field(
        None, description="Time taken to process this expectation in seconds"
    )

    @classmethod
    def from_error(cls, error: Exception, expectation: Any) -> ExpectationResult:
        """Create a failed result from an error and its expectation."""
        return cls(
            expectation_id=str(expectation.inject_expectation_id),
            is_valid=False,
            expectation=expectation,
            error_message=str(error),
        )

    def to_result_text(self) -> str:
        """Produce the text-based result for API upload."""
        if not self.expectation:
            return "Unknown"
        text = ""
        if not self.is_valid:
            text += "Not "
        cls_name = type(self.expectation).__name__
        if cls_name == "DetectionExpectation":
            text += "Detected"
        else:
            text += "Prevented"
        return text


class ExpectationTrace(BaseModel):
    """Trace data sent to the OpenAEV API for expectation tracking."""

    inject_expectation_trace_expectation: str = Field(
        description="The expectation ID this trace is associated with"
    )
    inject_expectation_trace_source_id: str = Field(
        description="The collector/source ID that generated this trace"
    )
    inject_expectation_trace_alert_name: str = Field(
        description="Name of the alert that was matched"
    )
    inject_expectation_trace_alert_link: str = Field(
        description="Link to the alert in the source system"
    )
    inject_expectation_trace_date: str = Field(
        description="Date when the trace was created (ISO format string)"
    )

    @field_validator("inject_expectation_trace_expectation")
    @classmethod
    def expectation_must_not_be_empty(cls, v: str) -> str:
        """Validate that expectation ID is not empty."""
        if not v or not v.strip():
            raise ValueError("Expectation ID cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_source_id")
    @classmethod
    def source_id_must_not_be_empty(cls, v: str) -> str:
        """Validate that source ID is not empty."""
        if not v or not v.strip():
            raise ValueError("Source ID cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_alert_name")
    @classmethod
    def alert_name_must_not_be_empty(cls, v: str) -> str:
        """Validate that alert name is not empty."""
        if not v or not v.strip():
            raise ValueError("Alert name cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_alert_link")
    @classmethod
    def alert_link_must_not_be_empty(cls, v: str) -> str:
        """Validate that alert link is not empty."""
        if not v or not v.strip():
            raise ValueError("Alert link cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_date")
    @classmethod
    def date_must_not_be_empty(cls, v: str) -> str:
        """Validate that date is not empty."""
        if not v or not v.strip():
            raise ValueError("Trace date cannot be empty")
        return v.strip()

    def to_api_dict(self) -> dict[str, str]:
        """Convert to a dictionary suitable for API submission."""
        return {
            key: str(value) if value is not None else ""
            for key, value in self.model_dump().items()
        }

    @classmethod
    def from_result(
        cls, result: ExpectationResult, collector_id: str, collector_name: str
    ) -> ExpectationTrace:
        """Create a trace from an ExpectationResult."""
        matching_data = result.matched_alerts[0] if result.matched_alerts else {}
        alert_name = matching_data.get("alert_name", f"{collector_name} Alert")
        trace_link = matching_data.get("alert_link", "")
        trace_date = datetime.now(UTC).replace(microsecond=0)
        date_str = trace_date.isoformat().replace("+00:00", "Z")
        return cls(
            inject_expectation_trace_expectation=str(result.expectation_id),
            inject_expectation_trace_source_id=str(collector_id),
            inject_expectation_trace_alert_name=alert_name,
            inject_expectation_trace_alert_link=trace_link or "N/A",
            inject_expectation_trace_date=date_str,
        )


class ExpectationSummary(BaseModel):
    """Mutable summary of expectation processing.

    NOT frozen — the engine increments fields in-place during processing.
    """

    received: int = Field(default=0, description="Total expectations received")
    supported: int = Field(default=0, description="Total supported expectations")
    processed: int = Field(default=0, description="Total processed expectations")
    valid: int = Field(default=0, description="Number of valid expectations")
    total_processing_time: float | None = Field(
        None, description="Total processing time in seconds"
    )

    @property
    def unsupported(self) -> int:
        """Number of unsupported expectations received."""
        return self.received - self.supported

    @property
    def unprocessed(self) -> int:
        """Number of expectations skipped during processing."""
        return self.supported - self.processed

    @property
    def invalid(self) -> int:
        """Number of invalid expectations."""
        return self.processed - self.valid

    @property
    def total_skipped(self) -> int:
        """Total expectations skipped (unsupported + unprocessed)."""
        return self.received - self.processed

    def __str__(self) -> str:
        """Return an overview of the summary."""
        return (
            f"{self.received} expectations received, "
            f"{self.supported} expectations supported ({self.unsupported} unsupported), "
            f"{self.processed} expectations processed ({self.unprocessed} unprocessed), "
            f"{self.valid} valid expectations ({self.invalid} invalid)"
        )
