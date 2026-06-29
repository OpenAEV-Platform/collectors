"""RED tests for the collectors-sdk error hierarchy."""

from __future__ import annotations

import pytest

from collectors_sdk import (
    APIError,
    BulkPreparationError,
    BulkUploadError,
    CollectorConfigError,
    CollectorEngineConfigError,
    CollectorError,
    CollectorProcessingError,
    CollectorSetupError,
    ExpectationHandlerError,
    ExpectationProcessingError,
    ExpectationUpdateError,
    TraceCreationError,
    TraceSubmissionError,
    TracingError,
)


ALL_ERRORS = [
    CollectorError,
    CollectorConfigError,
    CollectorEngineConfigError,
    CollectorSetupError,
    CollectorProcessingError,
    ExpectationHandlerError,
    ExpectationProcessingError,
    ExpectationUpdateError,
    BulkUploadError,
    BulkPreparationError,
    APIError,
    TracingError,
    TraceSubmissionError,
    TraceCreationError,
]


class TestErrorHierarchy:
    """Verify the 14-class exception hierarchy."""

    @pytest.mark.parametrize("cls", ALL_ERRORS)
    def test_is_exception(self, cls: type[Exception]) -> None:
        assert issubclass(cls, Exception)

    @pytest.mark.parametrize("cls", ALL_ERRORS)
    def test_is_collector_error(self, cls: type[Exception]) -> None:
        assert issubclass(cls, CollectorError)

    @pytest.mark.parametrize("cls", ALL_ERRORS)
    def test_constructable_with_message(self, cls: type[Exception]) -> None:
        err = cls("test message")
        assert str(err) == "test message"

    @pytest.mark.parametrize("cls", ALL_ERRORS)
    def test_has_docstring(self, cls: type[Exception]) -> None:
        assert cls.__doc__ is not None

    def test_inheritance_config_error(self) -> None:
        assert issubclass(CollectorConfigError, CollectorError)

    def test_inheritance_engine_config_error(self) -> None:
        assert issubclass(CollectorEngineConfigError, CollectorError)

    def test_inheritance_setup_error(self) -> None:
        assert issubclass(CollectorSetupError, CollectorError)

    def test_inheritance_processing_error(self) -> None:
        assert issubclass(CollectorProcessingError, CollectorError)

    def test_inheritance_expectation_handler_error(self) -> None:
        assert issubclass(ExpectationHandlerError, CollectorError)

    def test_inheritance_expectation_processing_error(self) -> None:
        assert issubclass(ExpectationProcessingError, CollectorError)

    def test_inheritance_expectation_update_error(self) -> None:
        assert issubclass(ExpectationUpdateError, CollectorError)

    def test_inheritance_bulk_upload_error(self) -> None:
        assert issubclass(BulkUploadError, ExpectationUpdateError)

    def test_inheritance_bulk_preparation_error(self) -> None:
        assert issubclass(BulkPreparationError, ExpectationUpdateError)

    def test_inheritance_api_error(self) -> None:
        assert issubclass(APIError, CollectorError)

    def test_inheritance_tracing_error(self) -> None:
        assert issubclass(TracingError, CollectorError)

    def test_inheritance_trace_submission_error(self) -> None:
        assert issubclass(TraceSubmissionError, TracingError)

    def test_inheritance_trace_creation_error(self) -> None:
        assert issubclass(TraceCreationError, TracingError)

    def test_catch_collector_error_catches_all(self) -> None:
        for cls in ALL_ERRORS:
            with pytest.raises(CollectorError):
                raise cls("caught")
