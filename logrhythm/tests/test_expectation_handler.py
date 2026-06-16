"""Tests for the GenericExpectationHandler."""

from unittest.mock import Mock

import pytest
from pyoaev.apis.inject_expectation.model import (
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.signatures.types import SignatureTypes
from src.collector.exception import ExpectationHandlerError
from src.collector.expectation_handler import GenericExpectationHandler
from src.collector.models import ExpectationResult


def _service_provider() -> Mock:
    """Build a mock service provider exposing supported signatures."""
    provider = Mock()
    provider.get_supported_signatures.return_value = [
        SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS
    ]
    return provider


class TestGenericExpectationHandler:
    """Test cases for GenericExpectationHandler."""

    def test_init_registers_with_registry(self):
        """Initialization registers handlers using the provider's signatures."""
        provider = _service_provider()
        handler = GenericExpectationHandler(provider)
        assert handler.service_provider is provider  # noqa: S101
        provider.get_supported_signatures.assert_called()

    def test_handle_detection_expectation(self):
        """Detection expectations are delegated to the detection handler."""
        provider = _service_provider()
        expected = ExpectationResult(expectation_id="e1", is_valid=True)
        provider.handle_detection_expectation.return_value = expected
        handler = GenericExpectationHandler(provider)

        expectation = Mock(spec=DetectionExpectation)
        expectation.inject_expectation_id = "e1"

        result = handler.handle_expectation(expectation, Mock())

        assert result is expected  # noqa: S101
        provider.handle_detection_expectation.assert_called_once()

    def test_handle_prevention_expectation(self):
        """Prevention expectations are delegated to the prevention handler."""
        provider = _service_provider()
        expected = ExpectationResult(expectation_id="e2", is_valid=False)
        provider.handle_prevention_expectation.return_value = expected
        handler = GenericExpectationHandler(provider)

        expectation = Mock(spec=PreventionExpectation)
        expectation.inject_expectation_id = "e2"

        result = handler.handle_expectation(expectation, Mock())

        assert result is expected  # noqa: S101

    def test_handle_unsupported_type(self):
        """Unsupported expectation types yield an invalid result."""
        provider = _service_provider()
        handler = GenericExpectationHandler(provider)

        expectation = Mock()
        expectation.inject_expectation_id = "e3"

        result = handler.handle_expectation(expectation, Mock())

        assert result.is_valid is False  # noqa: S101
        assert "Unsupported" in result.error_message  # noqa: S101

    def test_handle_expectation_propagates_errors(self):
        """Errors from the service provider are propagated."""
        provider = _service_provider()
        provider.handle_detection_expectation.side_effect = RuntimeError("boom")
        handler = GenericExpectationHandler(provider)

        expectation = Mock(spec=DetectionExpectation)
        expectation.inject_expectation_id = "e4"

        with pytest.raises(RuntimeError):
            handler.handle_expectation(expectation, Mock())

    def test_handle_batch_post_processes_results(self):
        """Batch handling fills in missing expectation IDs and objects."""
        provider = _service_provider()
        provider.handle_batch_expectations.return_value = [
            ExpectationResult(expectation_id="", is_valid=True)
        ]
        handler = GenericExpectationHandler(provider)

        expectation = Mock()
        expectation.inject_expectation_id = "e5"

        results = handler.handle_batch_expectations([expectation], Mock())

        assert len(results) == 1  # noqa: S101
        assert results[0].expectation is expectation  # noqa: S101
        assert results[0].expectation_id == "e5"  # noqa: S101

    def test_handle_batch_wraps_errors(self):
        """Batch failures are wrapped in ExpectationHandlerError."""
        provider = _service_provider()
        provider.handle_batch_expectations.side_effect = RuntimeError("x")
        handler = GenericExpectationHandler(provider)

        with pytest.raises(ExpectationHandlerError):
            handler.handle_batch_expectations([Mock()], Mock())

    def test_get_supported_signatures(self):
        """The handler exposes the provider's supported signatures."""
        provider = _service_provider()
        handler = GenericExpectationHandler(provider)
        assert handler.get_supported_signatures() == [  # noqa: S101
            SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS
        ]
