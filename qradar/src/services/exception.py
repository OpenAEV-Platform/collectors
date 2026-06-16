"""IBM QRadar Service Exceptions.

Custom exceptions for IBM QRadar service operations.
"""


class QRadarServiceError(Exception):
    """Base exception for all IBM QRadar service errors."""

    pass


class QRadarConfigurationError(QRadarServiceError):
    """Raised when there's a configuration error."""

    pass


class QRadarExpectationError(QRadarServiceError):
    """Raised when there's an error processing expectations."""

    pass


class QRadarFetchError(QRadarServiceError):
    """Raised when there's an error fetching data from IBM QRadar API."""

    pass


class QRadarMatchingError(QRadarServiceError):
    """Raised when there's an error matching alerts."""

    pass


class QRadarNoAlertsFoundError(QRadarServiceError):
    """Raised when no alerts are found for the search criteria."""

    pass


class QRadarNoMatchingAlertsError(QRadarServiceError):
    """Raised when alerts are found but none match the expectation."""

    pass


class QRadarDataConversionError(QRadarServiceError):
    """Raised when there's an error converting data."""

    pass


class QRadarAPIError(QRadarServiceError):
    """Raised when there's an error with IBM QRadar API operations."""

    pass


class QRadarNetworkError(QRadarServiceError):
    """Raised when there's a network connectivity error."""

    pass


class QRadarSessionError(QRadarServiceError):
    """Raised when there's an error with session management."""

    pass


class QRadarQueryError(QRadarServiceError):
    """Raised when there's an error with query operations."""

    pass


class QRadarValidationError(QRadarServiceError):
    """Raised when input validation fails."""

    pass


class QRadarTimeoutError(QRadarServiceError):
    """Raised when operations timeout."""

    pass


class QRadarAuthenticationError(QRadarServiceError):
    """Raised when authentication fails."""

    pass
