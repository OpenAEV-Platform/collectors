"""LogRhythm Service Exceptions.

Custom exceptions for LogRhythm service operations.
"""


class LogRhythmServiceError(Exception):
    """Base exception for all LogRhythm service errors."""

    pass


class LogRhythmConfigurationError(LogRhythmServiceError):
    """Raised when there's a configuration error."""

    pass


class LogRhythmExpectationError(LogRhythmServiceError):
    """Raised when there's an error processing expectations."""

    pass


class LogRhythmFetchError(LogRhythmServiceError):
    """Raised when there's an error fetching data from LogRhythm API."""

    pass


class LogRhythmMatchingError(LogRhythmServiceError):
    """Raised when there's an error matching alerts."""

    pass


class LogRhythmNoAlertsFoundError(LogRhythmServiceError):
    """Raised when no alerts are found for the search criteria."""

    pass


class LogRhythmNoMatchingAlertsError(LogRhythmServiceError):
    """Raised when alerts are found but none match the expectation."""

    pass


class LogRhythmDataConversionError(LogRhythmServiceError):
    """Raised when there's an error converting data."""

    pass


class LogRhythmAPIError(LogRhythmServiceError):
    """Raised when there's an error with LogRhythm API operations."""

    pass


class LogRhythmNetworkError(LogRhythmServiceError):
    """Raised when there's a network connectivity error."""

    pass


class LogRhythmSessionError(LogRhythmServiceError):
    """Raised when there's an error with session management."""

    pass


class LogRhythmQueryError(LogRhythmServiceError):
    """Raised when there's an error with query operations."""

    pass


class LogRhythmValidationError(LogRhythmServiceError):
    """Raised when input validation fails."""

    pass


class LogRhythmTimeoutError(LogRhythmServiceError):
    """Raised when operations timeout."""

    pass


class LogRhythmAuthenticationError(LogRhythmServiceError):
    """Raised when authentication fails."""

    pass
