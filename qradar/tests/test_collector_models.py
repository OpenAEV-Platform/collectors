"""Tests for collector Pydantic models."""

import pytest
from pydantic import ValidationError
from src.collector.models import (
    ExpectationResult,
    ExpectationTrace,
    ProcessingSummary,
)


def _valid_trace_kwargs() -> dict:
    """Return a set of valid ExpectationTrace field values."""
    return {
        "inject_expectation_trace_expectation": "exp-1",
        "inject_expectation_trace_source_id": "qradar--collector",
        "inject_expectation_trace_alert_name": "IBM QRadar Detection Alert",
        "inject_expectation_trace_alert_link": "https://kibana/app/security/alerts",
        "inject_expectation_trace_date": "2026-01-01T00:00:00Z",
    }


class TestExpectationTrace:
    """Test cases for the ExpectationTrace model."""

    def test_valid_trace(self):
        """A fully populated trace builds successfully."""
        trace = ExpectationTrace(**_valid_trace_kwargs())
        assert trace.inject_expectation_trace_expectation == "exp-1"  # noqa: S101

    def test_to_api_dict_stringifies_values(self):
        """to_api_dict returns string values for all fields."""
        trace = ExpectationTrace(**_valid_trace_kwargs())
        api_dict = trace.to_api_dict()
        assert all(isinstance(value, str) for value in api_dict.values())  # noqa: S101
        assert api_dict["inject_expectation_trace_expectation"] == "exp-1"  # noqa: S101

    def test_values_are_trimmed(self):
        """Leading/trailing whitespace is stripped from values."""
        kwargs = _valid_trace_kwargs()
        kwargs["inject_expectation_trace_expectation"] = "  exp-1  "
        trace = ExpectationTrace(**kwargs)
        assert trace.inject_expectation_trace_expectation == "exp-1"  # noqa: S101

    @pytest.mark.parametrize(
        "field",
        [
            "inject_expectation_trace_expectation",
            "inject_expectation_trace_source_id",
            "inject_expectation_trace_alert_name",
            "inject_expectation_trace_alert_link",
            "inject_expectation_trace_date",
        ],
    )
    def test_empty_field_raises(self, field):
        """Each required field rejects empty/whitespace-only values."""
        kwargs = _valid_trace_kwargs()
        kwargs[field] = "   "
        with pytest.raises(ValidationError):
            ExpectationTrace(**kwargs)


class TestExpectationResult:
    """Test cases for the ExpectationResult model."""

    def test_valid_result(self):
        """An ExpectationResult builds with required and optional fields."""
        result = ExpectationResult(
            expectation_id="exp-1",
            is_valid=True,
            matched_alerts=[{"source_ipv4_address": {"data": "1.2.3.4"}}],
        )
        assert result.is_valid is True  # noqa: S101
        assert result.matched_alerts is not None  # noqa: S101
        assert result.error_message is None  # noqa: S101


class TestProcessingSummary:
    """Test cases for the ProcessingSummary model."""

    def test_valid_summary(self):
        """A ProcessingSummary builds with all counters."""
        summary = ProcessingSummary(processed=3, valid=2, invalid=1, skipped=0)
        assert summary.processed == 3  # noqa: S101
        assert summary.valid == 2  # noqa: S101
        assert summary.invalid == 1  # noqa: S101
