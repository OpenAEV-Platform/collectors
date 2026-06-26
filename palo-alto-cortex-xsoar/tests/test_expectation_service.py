"""Tests for ExpectationService to improve coverage."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from src.models.settings.config_loader import ConfigLoader
from src.services.exception import (
    PaloAltoCortexXSOARAPIError,
    PaloAltoCortexXSOARExpectationError,
    PaloAltoCortexXSOARValidationError,
)
from src.services.expectation_service import ExpectationService
from src.services.ioc_extractor import IncidentResult, IndicatorResults
from tests.factories import DetectionExpectationFactory


@pytest.fixture
def mock_config():
    config = MagicMock(spec=ConfigLoader)
    config.palo_alto_cortex_xsoar = MagicMock()
    config.palo_alto_cortex_xsoar.api_url = "test.api.com"
    config.palo_alto_cortex_xsoar.api_key.get_secret_value.return_value = "secret"
    config.palo_alto_cortex_xsoar.api_key_id = "key-id"
    config.palo_alto_cortex_xsoar.api_key_type = "standard"
    config.palo_alto_cortex_xsoar.time_window = timedelta(hours=1)
    return config


@pytest.fixture
def service(mock_config):
    with patch("src.services.expectation_service.AlertFetcher"):
        with patch("src.services.expectation_service.PaloAltoCortexXSOARClientAPI"):
            return ExpectationService(config=mock_config)


def _make_incident(incident_id="test-id", action=None, oaev_implant=None):
    """Helper to create an IncidentResult for tests."""
    return IncidentResult(
        id=incident_id,
        action=action or ["Detected (Reported)"],
        indicators=IndicatorResults(oaev_implant=oaev_implant or []),
    )


class TestInit:
    def test_none_config(self):
        with pytest.raises(
            PaloAltoCortexXSOARValidationError, match="config cannot be None"
        ):
            ExpectationService(config=None)  # ty:ignore[invalid-argument-type]

    def test_none_api_url(self):
        config = MagicMock(spec=ConfigLoader)
        config.palo_alto_cortex_xsoar = MagicMock()
        config.palo_alto_cortex_xsoar.api_url = None
        with pytest.raises(
            PaloAltoCortexXSOARValidationError, match="api_url cannot be None"
        ):
            ExpectationService(config=config)


class TestHandleExpectations:
    def test_empty_expectations(self, service):
        result = service.handle_expectations([], MagicMock())
        assert result == []

    def test_exception_wraps_in_expectation_error(self, service):
        service.alert_fetcher.fetch_alerts_for_time_window.side_effect = Exception(
            "boom"
        )
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        with pytest.raises(
            PaloAltoCortexXSOARExpectationError, match="Error in handle_expectations"
        ):
            service.handle_expectations([exp], MagicMock())


class TestFetchAlertsForTimeWindow:
    def test_no_end_date_uses_now(self, service):
        service.alert_fetcher.fetch_alerts_for_time_window.return_value = []
        result = service._fetch_alerts_for_time_window(expectations=None)
        assert isinstance(result, list)
        service.alert_fetcher.fetch_alerts_for_time_window.assert_called_once()

    def test_naive_end_time_gets_utc(self, service):
        """When end_date is naive (no tzinfo), it should get UTC attached."""
        service.alert_fetcher.fetch_alerts_for_time_window.return_value = []
        # Patch _extract_end_date to return a naive datetime
        naive_dt = datetime(2026, 4, 27, 12, 0, 0)
        with patch.object(
            service, "_extract_end_date_from_expectations", return_value=naive_dt
        ):
            result = service._fetch_alerts_for_time_window(expectations=[])
        assert isinstance(result, list)

    def test_exception_wraps_in_api_error(self, service):
        service.alert_fetcher.fetch_alerts_for_time_window.side_effect = Exception(
            "api fail"
        )
        with pytest.raises(PaloAltoCortexXSOARAPIError, match="Error fetching alerts"):
            service._fetch_alerts_for_time_window(expectations=None)

    def test_inverted_date_window_logs_warning_and_applies_fallback(self, service):
        """When start_date > end_date, a warning is logged and fallback is applied."""
        service.alert_fetcher.fetch_alerts_for_time_window.return_value = []
        end_date = datetime(2020, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        start_date = datetime(2020, 1, 1, 11, 0, 0, tzinfo=timezone.utc)  # after end

        with patch.object(
            service,
            "_extract_date_signatures",
            return_value=(start_date, end_date),
        ):
            with patch.object(service, "logger") as mock_logger:
                service._fetch_alerts_for_time_window(expectations=[])

        mock_logger.warning.assert_called_once()
        warning_msg = mock_logger.warning.call_args[0][0]
        assert "start_date > end_date" in warning_msg

        call_kwargs = (
            service.alert_fetcher.fetch_alerts_for_time_window.call_args.kwargs
        )
        assert call_kwargs["start_time"] == end_date
        assert call_kwargs["end_time"] > end_date


class TestMatchAlertsToExpectations:
    def test_exception_in_matching_creates_error_result(self, service):
        """When matching raises, an error result is appended."""
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        incident = _make_incident(
            oaev_implant=["oaev-implant-test-agent-test"],
        )
        detection_helper = MagicMock()

        with patch.object(
            service,
            "_expectation_matches_incident",
            side_effect=Exception("match error"),
        ):
            results = service._match_alerts_to_expectations(
                [exp], [incident], detection_helper
            )
        assert len(results) == 1
        assert results[0].is_valid is False
        assert "match error" in results[0].error_message

    def test_no_oaev_data_returns_false(self, service):
        """When converter returns empty data, matching returns False."""
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        incident = _make_incident()
        service.converter.convert_incident_to_oaev = MagicMock(return_value={})
        result = service._expectation_matches_incident(
            exp, incident, ["proc"], MagicMock()
        )
        assert result is False

    def test_exception_in_expectation_matches_incident(self, service):
        """When an exception occurs during matching, returns False."""
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        incident = _make_incident()
        service.converter.convert_incident_to_oaev = MagicMock(
            side_effect=Exception("convert fail")
        )
        result = service._expectation_matches_incident(
            exp, incident, ["proc"], MagicMock()
        )
        assert result is False


class TestErrorResultAndConvert:
    def test_create_error_result(self, service):
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        result = service._create_error_result_object(Exception("test error"), exp)
        assert result.is_valid is False
        assert "test error" in result.error_message

    def test_convert_dict_to_result(self, service):
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        result_dict = {"is_valid": True, "traces": [{"a": 1}], "error": None}
        result = service._convert_dict_to_result(result_dict, exp)
        assert result.is_valid is True
        assert result.matched_alerts == [{"a": 1}]

    def test_get_service_info(self, service):
        info = service.get_service_info()
        assert info["service_name"] == "PaloAltoCortexXSOARExpectationService"
        assert info["flow_type"] == "all_at_once"
