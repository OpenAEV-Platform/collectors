"""Pydantic models for collector data structures."""

from typing import Any

from pydantic import BaseModel, Field, field_validator


class ExpectationTrace(BaseModel):
    """Pydantic model for expectation trace data.

    This model represents the structure of trace data that gets sent to the
    OpenAEV API for expectation tracking and validation.
    """

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
        """Convert the model to a dictionary suitable for API submission.

        This method ensures all values are strings as expected by the API,
        replacing the manual sanitization logic in the expectation manager.

        Returns:
            Dict with all values converted to strings.

        """
        return {
            key: str(value) if value is not None else ""
            for key, value in self.model_dump().items()
        }


class ExpectationResult(BaseModel):
    expectation_id: str = Field(..., description="ID of the processed expectation")
    is_valid: bool = Field(..., description="Whether the expectation was validated")
    expectation: Any | None = Field(None, description="The original expectation object")
    matched_alerts: list[dict[str, Any]] | None = Field(
        None, description="List of alerts that matched this expectation"
    )
    error_message: str | None = Field(
        None, description="Error message if processing failed"
    )
    processing_time: float | None = Field(
        None, description="Time taken to process this expectation in seconds"
    )


class ProcessingSummary(BaseModel):
    processed: int = Field(..., description="Total number of expectations processed")
    valid: int = Field(..., description="Number of valid expectations")
    invalid: int = Field(..., description="Number of invalid expectations")
    skipped: int = Field(..., description="Number of skipped expectations")
    total_processing_time: float | None = Field(
        None, description="Total processing time in seconds"
    )
