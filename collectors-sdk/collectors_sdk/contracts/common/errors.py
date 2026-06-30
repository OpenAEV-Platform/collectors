"""Error contracts — stable vocabulary for the collector domain."""

from collectors_sdk._core.base_collector.models.exception import (
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

__all__ = [
    "APIError",
    "BulkPreparationError",
    "BulkUploadError",
    "CollectorConfigError",
    "CollectorEngineConfigError",
    "CollectorError",
    "CollectorProcessingError",
    "CollectorSetupError",
    "ExpectationHandlerError",
    "ExpectationProcessingError",
    "ExpectationUpdateError",
    "TraceCreationError",
    "TraceSubmissionError",
    "TracingError",
]
