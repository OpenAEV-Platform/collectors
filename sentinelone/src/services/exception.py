"""SentinelOne Service Exceptions.

Custom exceptions for SentinelOne service operations.
"""


class SentinelOneServiceError(Exception):
    """Base exception for all SentinelOne service errors."""

    pass


class SentinelOneConfigurationError(SentinelOneServiceError):
    """Raised when there's a configuration error."""

    pass


class SentinelOneExpectationError(SentinelOneServiceError):
    """Raised when there's an error processing expectations."""

    pass


class SentinelOneFetchError(SentinelOneServiceError):
    """Raised when there's an error fetching data from SentinelOne API."""

    pass


class SentinelOneMatchingError(SentinelOneServiceError):
    """Raised when there's an error matching alerts."""

    pass


class SentinelOneNoAlertsFoundError(SentinelOneServiceError):
    """Raised when no alerts are found for the search criteria."""

    pass


class SentinelOneNoMatchingAlertsError(SentinelOneServiceError):
    """Raised when alerts are found but none match the expectation."""

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


class SentinelOneQueryError(SentinelOneServiceError):
    """Raised when there's an error with query operations."""

    pass


class SentinelOneValidationError(SentinelOneServiceError):
    """Raised when input validation fails."""

    pass


class SentinelOneTimeoutError(SentinelOneServiceError):
    """Raised when operations timeout."""

    pass
