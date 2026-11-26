"""SentinelOne Service Exceptions."""


class SentinelOneServiceError(Exception):
    """Base exception for all SentinelOne service errors."""

    pass


class SentinelOneExpectationError(SentinelOneServiceError):
    """Raised when there's an error processing expectations."""

    pass


class SentinelOneDataConversionError(SentinelOneServiceError):
    """Raised when there's an error converting data."""

    pass


class SentinelOneAPIError(SentinelOneServiceError):
    """Raised when there's an error with SentinelOne API operations.

    ``status_code`` carries the HTTP status when the error comes from an
    HTTP response, so callers can react to it (e.g. 401/403) without
    parsing the message.
    """

    def __init__(self, message: str = "", status_code: int | None = None):
        """Initialize the error with an optional HTTP status code."""
        super().__init__(message)
        self.status_code = status_code


class SentinelOneNetworkError(SentinelOneServiceError):
    """Raised when there's a network connectivity error."""

    pass


class SentinelOneSessionError(SentinelOneServiceError):
    """Raised when there's an error with session management."""

    pass


class SentinelOneValidationError(SentinelOneServiceError):
    """Raised when input validation fails."""

    pass
