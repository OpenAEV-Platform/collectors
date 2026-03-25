"""Custom exceptions for the collector."""


class CollectorError(Exception):
    """Base exception for the collector."""

    pass


class CollectorConfigError(CollectorError):
    """Exception raised when there is an error in the collector configuration."""

    pass


class CollectorSetupError(CollectorError):
    """Exception raised when there is an error setting up the collector."""

    pass


class CollectorProcessingError(CollectorError):
    """Exception raised when there is an error processing data in the collector."""

    pass


class ExpectationHandlerError(CollectorError):
    """Exception raised when there is an error in expectation handling."""

    pass


class ExpectationProcessingError(CollectorError):
    """Exception raised when there is an error processing expectations."""

    pass


class ExpectationUpdateError(CollectorError):
    """Exception raised when there is an error updating expectations."""

    pass


class BulkUpdateError(ExpectationUpdateError):
    """Exception raised when there is an error during bulk update operations."""

    pass


class APIError(CollectorError):
    """Exception raised when there is an error with API operations."""

    pass


class TracingError(CollectorError):
    """Exception raised when there is an error with tracing operations."""

    pass


class TraceSubmissionError(TracingError):
    """Exception raised when there is an error submitting traces."""

    pass


class TraceCreationError(TracingError):
    """Exception raised when there is an error creating traces."""

    pass
