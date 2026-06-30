"""Pydantic models for expectation processing results and traces."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ExpectationResult(BaseModel):
    """Model for expectation processing results."""

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
    def from_error(cls, error: Exception, expectation: Any) -> "ExpectationResult":
        return cls(
            expectation_id=str(expectation.inject_expectation_id),
            is_valid=False,
            expectation=expectation,
            error_message=str(error),
        )

    def to_result_text(self) -> str:
        if not self.expectation:
            return "Unknown"
        text = ""
        if not self.is_valid:
            text += "Not "
        # Duck-type check for prevention vs detection
        if hasattr(self.expectation, "inject_expectation_prevention"):
            text += "Prevented"
        else:
            text += "Detected"
        return text


class ExpectationTrace(BaseModel):
    """Pydantic model for expectation trace data."""

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
        if not v or not v.strip():
            raise ValueError("Expectation ID cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_source_id")
    @classmethod
    def source_id_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Source ID cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_alert_name")
    @classmethod
    def alert_name_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Alert name cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_alert_link")
    @classmethod
    def alert_link_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Alert link cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_date")
    @classmethod
    def date_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Trace date cannot be empty")
        return v.strip()

    def to_api_dict(self) -> dict[str, str]:
        return {
            key: str(value) if value is not None else ""
            for key, value in self.model_dump().items()
        }

    @classmethod
    def from_result(
        cls, result: "ExpectationResult", collector_id: str, collector_name: str
    ) -> "ExpectationTrace":
        matching_data = result.matched_alerts[0] if result.matched_alerts else {}
        alert_name = matching_data.get("alert_name", f"{collector_name} Alert")
        trace_link = matching_data.get("alert_link", "")
        trace_date = datetime.now(UTC).replace(microsecond=0)
        date_str = trace_date.isoformat().replace("+00:00", "Z")
        return cls(
            inject_expectation_trace_expectation=str(result.expectation_id),
            inject_expectation_trace_source_id=str(collector_id),
            inject_expectation_trace_alert_name=alert_name,
            inject_expectation_trace_alert_link=trace_link,
            inject_expectation_trace_date=date_str,
        )


class ExpectationSummary(BaseModel):
    """Model for expectation processing summary."""

    received: int = Field(default=0, description="Total number of expectations received")
    supported: int = Field(default=0, description="Total number of expectations supported")
    processed: int = Field(default=0, description="Total number of expectations processed")
    valid: int = Field(default=0, description="Number of valid expectations")
    total_processing_time: float | None = Field(None, description="Total processing time in seconds")

    @property
    def unsupported(self) -> int:
        return self.received - self.supported

    @property
    def unprocessed(self) -> int:
        return self.supported - self.processed

    @property
    def invalid(self) -> int:
        return self.processed - self.valid

    @property
    def total_skipped(self) -> int:
        return self.received - self.processed

    def __str__(self) -> str:
        return (
            f"{self.received} expectations received, "
            f"{self.supported} expectations supported ({self.unsupported} unsupported), "
            f"{self.processed} expectations processed ({self.unprocessed} unprocessed), "
            f"{self.valid} valid expectations ({self.invalid} invalid)"
        )
