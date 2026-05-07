"""Pydantic models for collector data structures."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator
from pyoaev.apis.inject_expectation.model import (
    DetectionExpectation,
    PreventionExpectation,
)


class ExpectationResult(BaseModel):
    """Model for expectation processing results."""

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

    @classmethod
    def from_error(
        cls, error: Exception, expectation: DetectionExpectation | PreventionExpectation
    ):
        """
        Produce an ExpectationResult based on an error message
        and the related expectation
        """
        return cls(
            expectation_id=str(expectation.inject_expectation_id),
            is_valid=False,
            expectation=expectation,
            matched_alerts=None,
            error_message=str(error),
            processing_time=None,
        )

    def to_result_text(self) -> str:
        """
        Produce the text-based result required for bulk upload
        """
        if not self.expectation:
            return "Unknown"

        text = ""
        if not self.is_valid:
            text += "Not "
        if isinstance(self.expectation, DetectionExpectation):
            text += "Detected"
        else:
            text += "Prevented"

        return text


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
        """Validate that expectation ID is not empty.

        Args:
            v: The expectation ID value to validate.

        Returns:
            The trimmed expectation ID.

        Raises:
            ValueError: If the expectation ID is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Expectation ID cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_source_id")
    @classmethod
    def source_id_must_not_be_empty(cls, v: str) -> str:
        """Validate that source ID is not empty.

        Args:
            v: The source ID value to validate.

        Returns:
            The trimmed source ID.

        Raises:
            ValueError: If the source ID is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Source ID cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_alert_name")
    @classmethod
    def alert_name_must_not_be_empty(cls, v: str) -> str:
        """Validate that alert name is not empty.

        Args:
            v: The alert name value to validate.

        Returns:
            The trimmed alert name.

        Raises:
            ValueError: If the alert name is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Alert name cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_alert_link")
    @classmethod
    def alert_link_must_not_be_empty(cls, v: str) -> str:
        """Validate that alert link is not empty.

        Args:
            v: The alert link value to validate.

        Returns:
            The trimmed alert link.

        Raises:
            ValueError: If the alert link is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Alert link cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_date")
    @classmethod
    def date_must_not_be_empty(cls, v: str) -> str:
        """Validate that date is not empty.

        Args:
            v: The date value to validate.

        Returns:
            The trimmed date string.

        Raises:
            ValueError: If the date is empty or whitespace only.

        """
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

    @classmethod
    def from_result(
        cls, result: ExpectationResult, collector_id: str, collector_name: str
    ):
        """
        Produce an ExpectationTrace based on the provided ExpectationResult
        and collector's ID and name
        """
        matching_data = result.matched_alerts[0] or {}
        alert_name = matching_data.get("alert_name", f"{collector_name} Alert")
        trace_link = matching_data.get("alert_link", "")
        trace_date = datetime.now(UTC).replace(microsecond=0)
        date_str = trace_date.isoformat().replace("+00:00", "Z")  # TODO WTF?
        return cls(
            inject_expectation_trace_expectation=str(result.expectation_id),
            inject_expectation_trace_source_id=str(collector_id),
            inject_expectation_trace_alert_name=alert_name,
            inject_expectation_trace_alert_link=trace_link,
            inject_expectation_trace_date=date_str,
        )


class ExpectationSummary(BaseModel):
    """Model for expectation processing summary."""

    received: int = Field(
        default=0, description="Total number of expectations received"
    )
    supported: int = Field(
        default=0, description="Total number of expectations supported"
    )
    processed: int = Field(
        default=0, description="Total number of expectations processed"
    )
    valid: int = Field(default=0, description="Number of valid expectations")
    total_processing_time: float | None = Field(
        None, description="Total processing time in seconds"
    )

    @property
    def unsupported(self):
        """Number of unsupported expectations received"""
        return self.received - self.supported

    @property
    def unprocessed(self):
        """Number of expectations skipped during processing"""
        return self.supported - self.processed

    @property
    def invalid(self):
        """Number of invalid expectations"""
        return self.processed - self.valid

    @property
    def total_skipped(self):
        """Number of expectations skipped since receiving (unsupported+unprocessed)"""
        return self.received - self.processed

    def __str__(self):
        """Return an overview of the summary as a string"""
        return (
            f"{self.received} expectations received, "
            f"{self.supported} expectations supported ({self.unsupported} unsupported), "
            f"{self.processed} expectations processed ({self.unprocessed} unprocessed), "
            f"{self.valid} valid expectations ({self.invalid} invalid)"
        )
