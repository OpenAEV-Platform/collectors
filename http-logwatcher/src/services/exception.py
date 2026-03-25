"""HTTPLogwatcher Service Exceptions."""


class HTTPLogwatcherServiceError(Exception):
    """Base exception for all HTTPLogwatcher service errors."""

    pass


class HTTPLogwatcherExpectationError(HTTPLogwatcherServiceError):
    """Raised when there's an error processing expectations."""

    pass


class HTTPLogwatcherDataConversionError(HTTPLogwatcherServiceError):
    """Raised when there's an error converting data."""

    pass


class HTTPLogwatcherFileError(HTTPLogwatcherServiceError):
    """Raised when there's an error with file operations."""

    pass


class HTTPLogwatcherValidationError(HTTPLogwatcherServiceError):
    """Raised when input validation fails."""

    pass
