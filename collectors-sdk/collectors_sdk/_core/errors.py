"""Collector exception hierarchy.

All collector errors inherit from CollectorError, which itself
inherits from Exception. Consumers can catch CollectorError to
handle any SDK-originated exception.
"""

__all__ = [
    "CollectorError",
    "CollectorConfigError",
    "CollectorEngineConfigError",
    "CollectorSetupError",
    "CollectorProcessingError",
    "ExpectationHandlerError",
    "ExpectationProcessingError",
    "ExpectationUpdateError",
    "BulkUploadError",
    "BulkPreparationError",
    "APIError",
    "TracingError",
    "TraceSubmissionError",
    "TraceCreationError",
]


class CollectorError(Exception):
    """Base exception for all collector SDK errors."""


class CollectorConfigError(CollectorError):
    """Raised when collector initialization configuration fails."""


class CollectorEngineConfigError(CollectorError):
    """Raised when the collector engine configuration is invalid or missing."""


class CollectorSetupError(CollectorError):
    """Raised when collector setup fails."""


class CollectorProcessingError(CollectorError):
    """Raised when an error occurs during the collector processing cycle."""


class ExpectationHandlerError(CollectorError):
    """Raised when there is an error in expectation handling."""


class ExpectationProcessingError(CollectorError):
    """Raised when there is an error processing individual expectations."""


class ExpectationUpdateError(CollectorError):
    """Raised when there is an error updating expectations."""


class BulkUploadError(ExpectationUpdateError):
    """Raised when bulk upload operations fail."""


class BulkPreparationError(ExpectationUpdateError):
    """Raised when bulk data preparation fails."""


class APIError(CollectorError):
    """Raised when an OpenAEV API operation fails."""


class TracingError(CollectorError):
    """Raised when there is an error with tracing operations."""


class TraceSubmissionError(TracingError):
    """Raised when trace submission to the API fails."""


class TraceCreationError(TracingError):
    """Raised when trace creation fails."""
