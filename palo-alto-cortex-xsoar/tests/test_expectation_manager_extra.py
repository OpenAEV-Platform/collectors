from unittest.mock import MagicMock, patch

import pytest
from pyoaev.apis.inject_expectation.model import (
    DetectionExpectation,
    PreventionExpectation,
)
from src.collector.exception import (
    APIError,
    BulkUpdateError,
    ExpectationHandlerError,
    ExpectationProcessingError,
    ExpectationUpdateError,
)
from src.collector.expectation_manager import GenericExpectationManager
from src.collector.models import ExpectationResult


@pytest.fixture
def mock_oaev_api():
    return MagicMock()


@pytest.fixture
def expectation_service():
    return MagicMock()


@pytest.fixture
def trace_service():
    return MagicMock()


@pytest.fixture
def manager(mock_oaev_api, expectation_service, trace_service):
    return GenericExpectationManager(
        oaev_api=mock_oaev_api,
        collector_id="test-collector",
        expectation_service=expectation_service,
        trace_service=trace_service,
    )


def test_bulk_update_no_results(manager):
    manager.logger = MagicMock()
    manager._bulk_update_expectations([])
    manager.logger.debug.assert_any_call(
        "[ExpectationManager] No results to update, skipping bulk update"
    )


def test_bulk_update_exception(manager):
    result = ExpectationResult(
        expectation_id="123",
        is_valid=True,
        expectation=MagicMock(spec=DetectionExpectation),
    )
    with patch.object(
        manager, "_prepare_bulk_data", side_effect=Exception("prepare error")
    ):
        with pytest.raises(
            BulkUpdateError, match="Error in bulk update: prepare error"
        ):
            manager._bulk_update_expectations([result])


def test_prepare_bulk_data_missing_id(manager):
    result = MagicMock(spec=ExpectationResult)
    result.expectation_id = None
    manager.logger = MagicMock()
    data = manager._prepare_bulk_data([result])
    assert data == {}
    manager.logger.debug.assert_any_call(
        "[ExpectationManager] Skipping result without expectation_id"
    )


def test_prepare_bulk_data_missing_expectation(manager):
    result = MagicMock()  # Use a plain MagicMock
    result.expectation_id = "123"
    result.expectation = None
    with patch.object(manager, "logger") as mock_logger:
        data = manager._prepare_bulk_data([result])
        assert data == {}
        assert any(
            "Skipping result 123 without expectation object" in str(arg)
            for call in mock_logger.debug.call_args_list
            for arg in call.args
        )


def test_prepare_bulk_data_exception(manager):
    result = MagicMock(spec=ExpectationResult)
    result.expectation_id = "123"
    # Mocking result.expectation to raise an exception when accessed
    type(result).expectation = property(lambda x: exec('raise Exception("fail")'))
    manager.logger = MagicMock()
    data = manager._prepare_bulk_data([result])
    assert data == {}
    manager.logger.warning.assert_called()


def test_get_result_text_exception(manager):
    # Pass something that isn't an expectation and will cause an exception in isinstance or somewhere
    # Actually, isinstance(None, DetectionExpectation) is False and doesn't raise.
    # To trigger the exception block in _get_result_text, we can mock isinstance or pass something weird.
    with patch(
        "src.collector.expectation_manager.isinstance",
        side_effect=Exception("isinstance fail"),
    ):
        result = manager._get_result_text(None, True)
        assert result == "Unknown"


def test_attempt_bulk_update_fallback_success(manager, mock_oaev_api):
    mock_oaev_api.inject_expectation.bulk_update.side_effect = Exception("bulk fail")
    bulk_data = {
        "123": {"collector_id": "test", "result": "Detected", "is_success": True}
    }

    with patch.object(manager, "_update_expectation") as mock_update:
        manager._attempt_bulk_update(bulk_data)
        mock_update.assert_called_once_with("123", bulk_data["123"])


def test_attempt_bulk_update_fallback_fail(manager, mock_oaev_api):
    mock_oaev_api.inject_expectation.bulk_update.side_effect = Exception("bulk fail")
    bulk_data = {
        "123": {"collector_id": "test", "result": "Detected", "is_success": True}
    }

    with patch.object(
        manager, "_fallback_individual_updates", side_effect=Exception("fallback fail")
    ):
        with pytest.raises(
            BulkUpdateError, match="Both bulk and individual updates failed"
        ):
            manager._attempt_bulk_update(bulk_data)


def test_process_expectations_api_error(manager):
    with patch.object(manager, "_fetch_expectations", side_effect=APIError("api fail")):
        with pytest.raises(
            ExpectationProcessingError, match="API error during processing"
        ):
            manager.process_expectations(MagicMock())


def test_process_expectations_unexpected_error(manager):
    with patch.object(
        manager, "_fetch_expectations", side_effect=Exception("unexpected")
    ):
        with pytest.raises(
            ExpectationProcessingError, match="Unexpected error processing expectations"
        ):
            manager.process_expectations(MagicMock())


# --- New tests ---


def test_handle_expectations_post_process_fills_expectation(
    manager, expectation_service
):
    """Line 89: result.expectation is None → filled from expectations list."""
    exp = MagicMock(spec=DetectionExpectation)
    exp.inject_expectation_id = "exp-id-1"
    result = ExpectationResult(
        expectation_id="exp-id-1",
        is_valid=True,
        expectation=None,  # None so post-processing fills it
    )
    expectation_service.handle_expectations.return_value = [result]
    results = manager.handle_expectations([exp], MagicMock())
    assert results[0].expectation is exp


def test_handle_expectations_post_process_fills_expectation_id(
    manager, expectation_service
):
    """Line 91: result.expectation_id empty → filled from result.expectation."""
    exp = MagicMock(spec=DetectionExpectation)
    exp.inject_expectation_id = "exp-id-2"
    result = ExpectationResult(
        expectation_id="",  # Empty so post-processing fills it
        is_valid=True,
        expectation=exp,
    )
    expectation_service.handle_expectations.return_value = [result]
    results = manager.handle_expectations([exp], MagicMock())
    assert results[0].expectation_id == "exp-id-2"


def test_handle_expectations_exception(manager, expectation_service):
    """Lines 104-106: exception in handle_expectations wraps in ExpectationHandlerError."""
    expectation_service.handle_expectations.side_effect = Exception("service boom")
    with pytest.raises(
        ExpectationHandlerError, match="Error in processing: service boom"
    ):
        manager.handle_expectations([MagicMock()], MagicMock())


def test_process_expectations_skips_unsupported_types(manager, expectation_service):
    """Line 158: unsupported expectation types are skipped and logged."""
    detection = MagicMock(spec=DetectionExpectation)
    detection.inject_expectation_id = "det-1"
    unsupported = MagicMock()  # Not Detection or Prevention

    manager._fetch_expectations = MagicMock(return_value=[detection, unsupported])
    expectation_service.handle_expectations.return_value = []
    manager.trace_manager = MagicMock()

    summary = manager.process_expectations(MagicMock())
    assert summary.skipped == 1
    assert summary.processed == 0


def test_bulk_update_empty_bulk_data(manager):
    """Line 235: prepared bulk data is empty → skip update."""
    result = ExpectationResult(
        expectation_id="123",
        is_valid=True,
        expectation=None,  # No expectation → _prepare_bulk_data returns {}
    )
    manager.logger = MagicMock()
    manager._bulk_update_expectations([result])
    assert any(
        "No valid bulk data prepared" in str(arg)
        for call in manager.logger.debug.call_args_list
        for arg in call.args
    )


def test_fallback_individual_updates_api_error(manager, mock_oaev_api):
    """Lines 382-386: APIError in individual update is caught and logged."""
    mock_oaev_api.inject_expectation.update.side_effect = ExpectationUpdateError(
        "update fail"
    )
    bulk_data = {
        "id1": {"collector_id": "test", "result": "Detected", "is_success": True},
    }
    manager.logger = MagicMock()
    manager._fallback_individual_updates(bulk_data)
    assert any(
        "Failed to update expectation id1" in str(arg)
        for call in manager.logger.error.call_args_list
        for arg in call.args
    )


def test_fallback_individual_updates_unexpected_error(manager, mock_oaev_api):
    """Lines 387-391: unexpected (non-API/Update) error in individual update is caught and logged."""
    # Patch _update_expectation directly to raise a generic Exception (not APIError or ExpectationUpdateError)
    with patch.object(
        manager, "_update_expectation", side_effect=RuntimeError("weird")
    ):
        bulk_data = {
            "id2": {"collector_id": "test", "result": "Prevented", "is_success": True},
        }
        manager.logger = MagicMock()
        manager._fallback_individual_updates(bulk_data)
        assert any(
            "Unexpected error updating expectation id2" in str(arg)
            for call in manager.logger.error.call_args_list
            for arg in call.args
        )


def test_fallback_individual_updates_mixed(manager, mock_oaev_api):
    """Some succeed, some fail."""
    call_count = [0]

    def side_effect(**kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return None  # success
        raise Exception("fail")

    mock_oaev_api.inject_expectation.update.side_effect = side_effect
    bulk_data = {
        "id-ok": {"collector_id": "test", "result": "Detected", "is_success": True},
        "id-fail": {"collector_id": "test", "result": "Prevented", "is_success": True},
    }
    manager.logger = MagicMock()
    manager._fallback_individual_updates(bulk_data)
    assert any(
        "1 successful, 1 failed" in str(arg)
        for call in manager.logger.info.call_args_list
        for arg in call.args
    )


def test_update_expectation_success(manager, mock_oaev_api):
    """Lines 410-421: successful individual update."""
    mock_oaev_api.inject_expectation.update.return_value = None
    manager._update_expectation("exp-1", {"result": "Detected"})
    mock_oaev_api.inject_expectation.update.assert_called_once_with(
        inject_expectation_id="exp-1",
        inject_expectation={"result": "Detected"},
    )


def test_update_expectation_failure(manager, mock_oaev_api):
    """Lines 423-426: exception in update wraps in ExpectationUpdateError."""
    mock_oaev_api.inject_expectation.update.side_effect = Exception("api down")
    with pytest.raises(
        ExpectationUpdateError, match="Failed to update expectation exp-1"
    ):
        manager._update_expectation("exp-1", {"result": "Detected"})


def test_fetch_expectations_error(manager, mock_oaev_api):
    """Lines 452-454: error fetching expectations returns empty list."""
    mock_oaev_api.inject_expectation.expectations_models_for_source.side_effect = (
        Exception("fetch fail")
    )
    result = manager._fetch_expectations()
    assert result == []


def test_get_result_text_detection_valid(manager):
    exp = MagicMock(spec=DetectionExpectation)
    assert manager._get_result_text(exp, True) == "Detected"


def test_get_result_text_detection_invalid(manager):
    exp = MagicMock(spec=DetectionExpectation)
    assert manager._get_result_text(exp, False) == "Not Detected"


def test_get_result_text_prevention_valid(manager):
    exp = MagicMock(spec=PreventionExpectation)
    assert manager._get_result_text(exp, True) == "Prevented"


def test_get_result_text_prevention_invalid(manager):
    exp = MagicMock(spec=PreventionExpectation)
    assert manager._get_result_text(exp, False) == "Not Prevented"


def test_process_expectations_bulk_update_error(manager, expectation_service):
    """Lines 195-197: BulkUpdateError during processing wraps in ExpectationProcessingError."""
    det = MagicMock(spec=DetectionExpectation)
    det.inject_expectation_id = "det-1"
    manager._fetch_expectations = MagicMock(return_value=[det])
    expectation_service.handle_expectations.return_value = []
    manager.trace_manager = MagicMock()

    with patch.object(
        manager, "_bulk_update_expectations", side_effect=BulkUpdateError("bulk fail")
    ):
        with pytest.raises(
            ExpectationProcessingError, match="API error during processing"
        ):
            manager.process_expectations(MagicMock())
