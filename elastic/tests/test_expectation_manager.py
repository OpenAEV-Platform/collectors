"""Tests for the GenericExpectationManager."""

from unittest.mock import Mock

import pytest
from pyoaev.apis.inject_expectation.model import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes
from src.collector.exception import ExpectationUpdateError
from src.collector.expectation_manager import GenericExpectationManager
from src.collector.models import ExpectationResult


def _detection_exp(exp_id: str = "e1", end_date: bool = True) -> Mock:
    """Build a mock detection expectation, optionally with an end_date signature."""
    expectation = Mock(spec=DetectionExpectation)
    expectation.inject_expectation_id = exp_id
    signatures = []
    if end_date:
        sig = Mock()
        sig.type = SignatureTypes.SIG_TYPE_END_DATE
        signatures.append(sig)
    expectation.inject_expectation_signatures = signatures
    return expectation


def _manager() -> tuple[GenericExpectationManager, Mock, Mock]:
    """Build a manager with mock API and handler."""
    api = Mock()
    handler = Mock()
    manager = GenericExpectationManager(api, "collector-1", handler)
    return manager, api, handler


class TestGenericExpectationManager:
    """Test cases for GenericExpectationManager."""

    def test_init_requires_api(self):
        """A missing API raises ValueError."""
        with pytest.raises(ValueError):
            GenericExpectationManager(None, "c", Mock())

    def test_init_requires_collector_id(self):
        """A missing collector id raises ValueError."""
        with pytest.raises(ValueError):
            GenericExpectationManager(Mock(), "", Mock())

    def test_init_requires_handler(self):
        """A missing handler raises ValueError."""
        with pytest.raises(ValueError):
            GenericExpectationManager(Mock(), "c", None)

    def test_process_expectations_success(self):
        """A full processing cycle returns a summary and updates the API."""
        manager, api, handler = _manager()
        expectation = _detection_exp()
        api.inject_expectation.expectations_models_for_source.return_value = [
            expectation
        ]
        handler.handle_batch_expectations.return_value = [
            ExpectationResult(
                expectation_id="e1", is_valid=True, expectation=expectation
            )
        ]

        summary = manager.process_expectations(Mock())

        assert summary.processed == 1  # noqa: S101
        assert summary.valid == 1  # noqa: S101
        api.inject_expectation.bulk_update.assert_called_once()

    def test_check_for_end_date(self):
        """end_date detection returns True only when present."""
        manager, _, _ = _manager()
        assert (
            manager._check_for_end_date([_detection_exp(end_date=True)]) is True
        )  # noqa: S101
        assert (  # noqa: S101
            manager._check_for_end_date([_detection_exp(end_date=False)]) is False
        )

    def test_prepare_bulk_data_filters(self):
        """Bulk data preparation skips results without ids or expectations."""
        manager, _, _ = _manager()
        expectation = _detection_exp()
        results = [
            ExpectationResult(
                expectation_id="e1", is_valid=True, expectation=expectation
            ),
            ExpectationResult(
                expectation_id="", is_valid=True, expectation=expectation
            ),
            ExpectationResult(expectation_id="e3", is_valid=False, expectation=None),
        ]

        bulk = manager._prepare_bulk_data(results)

        assert "e1" in bulk  # noqa: S101
        assert "e3" not in bulk  # noqa: S101
        assert bulk["e1"]["is_success"] is True  # noqa: S101

    def test_get_result_text(self):
        """Result text reflects expectation type and validity."""
        manager, _, _ = _manager()
        detection = Mock(spec=DetectionExpectation)
        prevention = Mock(spec=PreventionExpectation)
        assert manager._get_result_text(detection, True) == "Detected"  # noqa: S101
        assert (
            manager._get_result_text(detection, False) == "Not Detected"
        )  # noqa: S101
        assert manager._get_result_text(prevention, True) == "Prevented"  # noqa: S101

    def test_attempt_bulk_update_success(self):
        """A successful bulk update calls the API once."""
        manager, api, _ = _manager()
        manager._attempt_bulk_update({"e1": {"x": 1}})
        api.inject_expectation.bulk_update.assert_called_once()

    def test_attempt_bulk_update_falls_back_to_individual(self):
        """A bulk failure falls back to individual updates without raising."""
        manager, api, _ = _manager()
        api.inject_expectation.bulk_update.side_effect = RuntimeError("bulk")
        api.inject_expectation.update.side_effect = RuntimeError("individual")

        manager._attempt_bulk_update({"e1": {"x": 1}})

        api.inject_expectation.update.assert_called()

    def test_update_expectation_error(self):
        """A failed individual update raises ExpectationUpdateError."""
        manager, api, _ = _manager()
        api.inject_expectation.update.side_effect = RuntimeError("x")
        with pytest.raises(ExpectationUpdateError):
            manager._update_expectation("e1", {"x": 1})

    def test_bulk_update_empty_results(self):
        """No results means no bulk update call."""
        manager, api, _ = _manager()
        manager._bulk_update_expectations([])
        api.inject_expectation.bulk_update.assert_not_called()

    def test_interruptible_sleep_zero_returns(self):
        """A non-positive sleep returns immediately."""
        manager, _, _ = _manager()
        manager._interruptible_sleep(0)
