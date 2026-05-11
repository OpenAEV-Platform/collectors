from unittest.mock import MagicMock, patch

import pytest
from src.collector.exception import (
    TraceCreationError,
    TraceSubmissionError,
    TracingError,
)
from src.collector.trace_manager import TraceManager


@pytest.fixture
def mock_oaev_api():
    return MagicMock()


@pytest.fixture
def trace_service():
    return MagicMock()


@pytest.fixture
def manager(mock_oaev_api, trace_service):
    return TraceManager(
        oaev_api=mock_oaev_api,
        collector_id="test-collector",
        trace_service=trace_service,
    )


def test_create_and_submit_traces_no_traces(manager, trace_service):
    trace_service.create_traces_from_results.return_value = []
    manager.logger = MagicMock()
    manager.create_and_submit_traces([MagicMock()])
    assert any(
        "No traces created from results" in str(arg)
        for call in manager.logger.info.call_args_list
        for arg in call.args
    )


def test_create_and_submit_traces_exception(manager, trace_service):
    manager.logger = MagicMock()
    # Pass a list with one item to ensure len(results) works
    results = [MagicMock()]
    trace_service.create_traces_from_results.side_effect = Exception("creation error")
    with pytest.raises(
        TracingError, match="Error creating and submitting traces: creation error"
    ):
        manager.create_and_submit_traces(results)


def test_submit_traces_no_dicts(manager):
    manager.logger = MagicMock()
    # Don't pass any traces
    manager._submit_traces([])
    assert any(
        "No trace dictionaries generated from traces" in str(arg)
        for call in manager.logger.warning.call_args_list
        for arg in call.args
    )


def test_submit_traces_fallback_success(manager, mock_oaev_api):
    mock_trace = MagicMock()
    mock_trace.to_api_dict.return_value = {"key": "val"}
    mock_oaev_api.inject_expectation_trace.bulk_create.side_effect = Exception(
        "bulk fail"
    )

    with patch.object(manager, "_fallback_individual_trace_creation") as mock_fallback:
        with pytest.raises(TraceSubmissionError):
            manager._submit_traces([mock_trace])
        mock_fallback.assert_called_once_with([mock_trace])


def test_submit_traces_fallback_fail(manager, mock_oaev_api):
    mock_trace = MagicMock()
    mock_trace.to_api_dict.return_value = {"key": "val"}
    mock_oaev_api.inject_expectation_trace.bulk_create.side_effect = Exception(
        "bulk fail"
    )

    with patch.object(
        manager,
        "_fallback_individual_trace_creation",
        side_effect=TraceCreationError("fallback fail"),
    ):
        with pytest.raises(TraceSubmissionError):
            manager._submit_traces([mock_trace])


def test_fallback_individual_trace_creation_all_fail(manager, mock_oaev_api):
    mock_trace = MagicMock()
    mock_trace.to_api_dict.return_value = {"key": "val"}
    mock_oaev_api.inject_expectation_trace.create.side_effect = Exception(
        "individual fail"
    )

    with pytest.raises(
        TraceCreationError, match="All individual trace creations failed"
    ):
        manager._fallback_individual_trace_creation([mock_trace])


def test_fallback_individual_trace_creation_unexpected_error(manager):
    # Pass something that doesn't have to_api_dict
    with pytest.raises(TraceCreationError, match="Error in fallback trace creation"):
        manager._fallback_individual_trace_creation([None])


# --- New tests ---


def test_init_no_trace_service():
    """Line 56: no trace service logs 'no trace service provided'."""
    api = MagicMock()
    tm = TraceManager(oaev_api=api, collector_id="coll-1", trace_service=None)
    assert tm.trace_service is None


def test_create_and_submit_traces_no_trace_service():
    """Lines 75-78: no trace service → skip trace creation."""
    api = MagicMock()
    tm = TraceManager(oaev_api=api, collector_id="coll-1", trace_service=None)
    tm.create_and_submit_traces([MagicMock()])
    # Should not raise, just skip


def test_submit_traces_success(manager, mock_oaev_api):
    """Happy path: traces submitted via bulk_create."""
    mock_trace = MagicMock()
    mock_trace.to_api_dict.return_value = {"key": "val"}
    manager._submit_traces([mock_trace])
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once_with(
        payload={"expectation_traces": [{"key": "val"}]}
    )


def test_create_and_submit_traces_happy_path(manager, trace_service, mock_oaev_api):
    """Full happy path: results → traces → submitted."""
    mock_trace = MagicMock()
    mock_trace.to_api_dict.return_value = {"key": "val"}
    trace_service.create_traces_from_results.return_value = [mock_trace]

    manager.create_and_submit_traces([MagicMock()])
    mock_oaev_api.inject_expectation_trace.bulk_create.assert_called_once()


def test_fallback_individual_trace_creation_partial_success(manager, mock_oaev_api):
    """Lines 182-186: some individual traces succeed, some fail."""
    mock_trace_ok = MagicMock()
    mock_trace_ok.to_api_dict.return_value = {"key": "ok"}
    mock_trace_fail = MagicMock()
    mock_trace_fail.to_api_dict.return_value = {"key": "fail"}

    call_count = [0]

    def side_effect(data):
        call_count[0] += 1
        if call_count[0] == 2:
            raise Exception("individual fail")
        return None

    mock_oaev_api.inject_expectation_trace.create.side_effect = side_effect
    # Should not raise because at least one succeeded
    manager._fallback_individual_trace_creation([mock_trace_ok, mock_trace_fail])
