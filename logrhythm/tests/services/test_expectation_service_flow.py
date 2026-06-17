"""Flow-level tests for LogRhythmExpectationService (real processing paths)."""

from unittest.mock import Mock

import pytest
from pyoaev.apis.inject_expectation.model import (
    DetectionExpectation,
    PreventionExpectation,
)
from src.services.exception import LogRhythmNoAlertsFoundError
from src.services.expectation_service import LogRhythmExpectationService
from tests.services.fixtures.factories import create_test_config

PARENT_VALUE = (
    "oaev-implant-12345678-1234-1234-1234-123456789abc"
    "-agent-87654321-4321-4321-4321-cba987654321"
)


def _service() -> LogRhythmExpectationService:
    """Build an LogRhythmExpectationService from a test config."""
    return LogRhythmExpectationService(config=create_test_config())


def _detection_expectation(signatures: list[tuple[str, str]]) -> Mock:
    """Build a mock detection expectation with the given (type, value) signatures."""
    expectation = Mock(spec=DetectionExpectation)
    expectation.inject_expectation_id = "exp-1"
    sig_objs = []
    for sig_type, value in signatures:
        sig = Mock()
        sig.type.value = sig_type
        sig.value = value
        sig_objs.append(sig)
    expectation.inject_expectation_signatures = sig_objs
    return expectation


class TestExpectationServiceFlow:
    """Flow-level tests covering process/handle/match paths."""

    def test_process_expectation_detection_success(self):
        """A detection expectation with a matching alert returns a valid result."""
        service = _service()
        service.client_api.fetch_with_retry = Mock(return_value=[Mock()])
        service.converter.convert_data_to_oaev_data = Mock(
            return_value=[
                {
                    "source_ipv4_address": {"type": "simple", "data": ["1.2.3.4"]},
                    "parent_process_name": {"type": "simple", "data": PARENT_VALUE},
                }
            ]
        )
        helper = Mock()
        helper.match_alert_elements.return_value = True

        expectation = _detection_expectation(
            [
                ("source_ipv4_address", "1.2.3.4"),
                ("parent_process_name", PARENT_VALUE),
            ]
        )

        result = service.process_expectation(expectation, helper)

        assert result.is_valid is True  # noqa: S101
        assert result.matched_alerts is not None  # noqa: S101

    def test_process_expectation_no_alerts_raises(self):
        """No fetched alerts raises LogRhythmNoAlertsFoundError."""
        service = _service()
        service.client_api.fetch_with_retry = Mock(return_value=[])
        service.converter.convert_data_to_oaev_data = Mock(return_value=[])

        expectation = _detection_expectation([("source_ipv4_address", "1.2.3.4")])

        with pytest.raises(LogRhythmNoAlertsFoundError):
            service.process_expectation(expectation, Mock())

    def test_handle_prevention_expectation_invalid(self):
        """Prevention expectations are reported as invalid."""
        service = _service()
        expectation = Mock(spec=PreventionExpectation)
        expectation.inject_expectation_id = "prev-1"

        result = service.handle_prevention_expectation(expectation, Mock())

        assert result.is_valid is False  # noqa: S101
        assert (
            "only supports DetectionExpectations" in result.error_message
        )  # noqa: S101

    def test_match_with_detection_helper_parent_fail(self):
        """A failing parent-process match short-circuits to False."""
        service = _service()
        helper = Mock()
        helper.match_alert_elements.return_value = False

        signatures = [{"type": "parent_process_name", "value": PARENT_VALUE}]
        data_item = {"parent_process_name": {"type": "simple", "data": PARENT_VALUE}}

        assert (  # noqa: S101
            service._match_with_detection_helper(signatures, data_item, helper) is False
        )

    def test_match_with_detection_helper_target_only(self):
        """A target-IP match (with parent) returns True."""
        service = _service()
        helper = Mock()
        helper.match_alert_elements.return_value = True

        signatures = [
            {"type": "parent_process_name", "value": PARENT_VALUE},
            {"type": "target_ipv4_address", "value": "10.0.0.1"},
        ]
        data_item = {
            "parent_process_name": {"type": "simple", "data": PARENT_VALUE},
            "target_ipv4_address": {"type": "simple", "data": ["10.0.0.1"]},
        }

        assert (  # noqa: S101
            service._match_with_detection_helper(signatures, data_item, helper) is True
        )

    def test_match_with_detection_helper_source_and_target(self):
        """Source and target IP signatures both present resolves via OR logic."""
        service = _service()
        helper = Mock()
        helper.match_alert_elements.return_value = True

        signatures = [
            {"type": "parent_process_name", "value": PARENT_VALUE},
            {"type": "source_ipv4_address", "value": "1.2.3.4"},
            {"type": "target_ipv4_address", "value": "10.0.0.1"},
        ]
        data_item = {
            "parent_process_name": {"type": "simple", "data": PARENT_VALUE},
            "source_ipv4_address": {"type": "simple", "data": ["1.2.3.4"]},
            "target_ipv4_address": {"type": "simple", "data": ["10.0.0.1"]},
        }

        assert (  # noqa: S101
            service._match_with_detection_helper(signatures, data_item, helper) is True
        )

    def test_match_with_detection_helper_source_only_no_parent(self):
        """An IP-only expectation (no parent_process signature) can still match."""
        service = _service()
        helper = Mock()
        helper.match_alert_elements.return_value = True

        signatures = [{"type": "source_ipv4_address", "value": "1.2.3.4"}]
        data_item = {
            "source_ipv4_address": {"type": "simple", "data": ["1.2.3.4"]},
        }

        assert (  # noqa: S101
            service._match_with_detection_helper(signatures, data_item, helper) is True
        )

    def test_match_with_detection_helper_source_only_no_parent_no_match(self):
        """An IP-only expectation returns False when the IP does not match."""
        service = _service()
        helper = Mock()
        helper.match_alert_elements.return_value = False

        signatures = [{"type": "source_ipv4_address", "value": "1.2.3.4"}]
        data_item = {
            "source_ipv4_address": {"type": "simple", "data": ["9.9.9.9"]},
        }

        assert (  # noqa: S101
            service._match_with_detection_helper(signatures, data_item, helper)
            is False
        )

    def test_create_error_result_dict(self):
        """_create_error_result builds an error dictionary from a service error."""
        service = _service()
        error = LogRhythmNoAlertsFoundError("none found")

        result = service._create_error_result(error)

        assert result["is_valid"] is False  # noqa: S101
        assert result["error_type"] == "LogRhythmNoAlertsFoundError"  # noqa: S101
