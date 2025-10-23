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
    """Raised when there's an error with SentinelOne API operations."""

    pass


class SentinelOneNetworkError(SentinelOneServiceError):
    """Raised when there's a network connectivity error."""

    pass


class SentinelOneSessionError(SentinelOneServiceError):
    """Raised when there's an error with session management."""

    pass


class SentinelOneValidationError(SentinelOneServiceError):
    """Raised when input validation fails."""

    pass
