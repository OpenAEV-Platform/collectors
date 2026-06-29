"""RED tests for data models."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from collectors_sdk import (
    ExpectationResult,
    ExpectationSummary,
    ExpectationTrace,
    OAEVData,
    Source,
    SourceHandler,
    TraceData,
)


class TestOAEVData:
    """OAEVData model tests."""

    def test_allows_extra_fields(self) -> None:
        data = OAEVData.model_validate({"process_name": "cmd.exe"})
        assert data.process_name == "cmd.exe"  # type: ignore[attr-defined]

    def test_str_readable(self) -> None:
        data = OAEVData.model_validate({"process_name": "cmd.exe"})
        result = str(data)
        assert "OAEVData" in result


class TestTraceData:
    """TraceData model tests."""

    def test_required_fields(self) -> None:
        trace = TraceData(
            alert_name="Test Alert",
            alert_link="https://example.com/alert/1",  # type: ignore[arg-type]
        )
        assert trace.alert_name == "Test Alert"
        assert trace.alert_date is not None

    def test_str_readable(self) -> None:
        trace = TraceData(
            alert_name="Test",
            alert_link="https://example.com",  # type: ignore[arg-type]
        )
        assert "TraceData" in str(trace)


class TestSource:
    """Source model tests."""

    def test_construction(self) -> None:
        class MockFetcher:
            def fetch_data(self) -> list[Any]:
                return []

        class MockData:
            def to_oaev_data(self) -> Any: ...
            def to_traces_data(self) -> Any: ...
            def is_prevented(self) -> bool:
                return False
            def is_detected(self) -> bool:
                return True
            def __str__(self) -> str:
                return "mock"

        source = Source(
            data_fetcher_model=MockFetcher,
            source_data_model=MockData,
            signatures=[],
        )
        assert source.data_fetcher_model is MockFetcher


class TestSourceHandler:
    """SourceHandler default implementation tests."""

    def test_has_get_source_data(self) -> None:
        handler = SourceHandler(config=MagicMock())
        assert hasattr(handler, "get_source_data")

    def test_has_serialize_as_oaevdata(self) -> None:
        handler = SourceHandler(config=MagicMock())
        assert hasattr(handler, "serialize_as_oaevdata")

    def test_has_serialize_as_tracedata(self) -> None:
        handler = SourceHandler(config=MagicMock())
        assert hasattr(handler, "serialize_as_tracedata")


class TestExpectationResult:
    """ExpectationResult model tests."""

    def test_required_fields(self) -> None:
        result = ExpectationResult(
            expectation_id="exp-001",
            is_valid=True,
        )
        assert result.expectation_id == "exp-001"
        assert result.is_valid is True
        assert result.matched_alerts == []

    def test_from_error_classmethod(self) -> None:
        mock_exp = MagicMock()
        mock_exp.inject_expectation_id = "exp-002"
        result = ExpectationResult.from_error(ValueError("boom"), mock_exp)
        assert result.is_valid is False
        assert result.error_message == "boom"

    def test_to_result_text_detected(self) -> None:
        mock_exp = MagicMock(spec_set=["inject_expectation_id"])
        mock_exp.__class__.__name__ = "DetectionExpectation"
        result = ExpectationResult(
            expectation_id="exp-003",
            is_valid=True,
            expectation=mock_exp,
        )
        text = result.to_result_text()
        assert "Detected" in text

    def test_to_result_text_not_valid(self) -> None:
        mock_exp = MagicMock(spec_set=["inject_expectation_id"])
        result = ExpectationResult(
            expectation_id="exp-004",
            is_valid=False,
            expectation=mock_exp,
        )
        text = result.to_result_text()
        assert "Not" in text


class TestExpectationTrace:
    """ExpectationTrace model tests."""

    def test_required_fields(self) -> None:
        trace = ExpectationTrace(
            inject_expectation_trace_expectation="exp-001",
            inject_expectation_trace_source_id="src-001",
            inject_expectation_trace_alert_name="Alert",
            inject_expectation_trace_alert_link="https://example.com",
            inject_expectation_trace_date="2024-01-01T00:00:00Z",
        )
        assert trace.inject_expectation_trace_expectation == "exp-001"

    def test_rejects_empty_expectation_id(self) -> None:
        with pytest.raises(ValueError):
            ExpectationTrace(
                inject_expectation_trace_expectation="",
                inject_expectation_trace_source_id="src-001",
                inject_expectation_trace_alert_name="Alert",
                inject_expectation_trace_alert_link="https://example.com",
                inject_expectation_trace_date="2024-01-01T00:00:00Z",
            )

    def test_rejects_empty_source_id(self) -> None:
        with pytest.raises(ValueError):
            ExpectationTrace(
                inject_expectation_trace_expectation="exp-001",
                inject_expectation_trace_source_id="  ",
                inject_expectation_trace_alert_name="Alert",
                inject_expectation_trace_alert_link="https://example.com",
                inject_expectation_trace_date="2024-01-01T00:00:00Z",
            )

    def test_to_api_dict(self) -> None:
        trace = ExpectationTrace(
            inject_expectation_trace_expectation="exp-001",
            inject_expectation_trace_source_id="src-001",
            inject_expectation_trace_alert_name="Alert",
            inject_expectation_trace_alert_link="https://example.com",
            inject_expectation_trace_date="2024-01-01T00:00:00Z",
        )
        d = trace.to_api_dict()
        assert isinstance(d, dict)
        assert all(isinstance(v, str) for v in d.values())


class TestExpectationSummary:
    """ExpectationSummary model tests."""

    def test_defaults_to_zero(self) -> None:
        summary = ExpectationSummary()
        assert summary.received == 0
        assert summary.supported == 0
        assert summary.processed == 0
        assert summary.valid == 0

    def test_computed_unsupported(self) -> None:
        summary = ExpectationSummary(received=10, supported=7)
        assert summary.unsupported == 3

    def test_computed_unprocessed(self) -> None:
        summary = ExpectationSummary(supported=7, processed=5)
        assert summary.unprocessed == 2

    def test_computed_invalid(self) -> None:
        summary = ExpectationSummary(processed=5, valid=3)
        assert summary.invalid == 2

    def test_computed_total_skipped(self) -> None:
        summary = ExpectationSummary(received=10, processed=6)
        assert summary.total_skipped == 4

    def test_not_frozen(self) -> None:
        summary = ExpectationSummary()
        summary.received = 5  # must not raise
        assert summary.received == 5

    def test_str_returns_summary(self) -> None:
        summary = ExpectationSummary(received=10, supported=8, processed=6, valid=4)
        text = str(summary)
        assert "10" in text
        assert "expectations" in text
