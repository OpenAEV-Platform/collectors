"""Elastic Security Service Exceptions.

Custom exceptions for Elastic Security service operations.
"""


class ElasticServiceError(Exception):
    """Base exception for all Elastic Security service errors."""

    pass


class ElasticConfigurationError(ElasticServiceError):
    """Raised when there's a configuration error."""

    pass


class ElasticExpectationError(ElasticServiceError):
    """Raised when there's an error processing expectations."""

    pass


class ElasticFetchError(ElasticServiceError):
    """Raised when there's an error fetching data from Elastic Security API."""

    pass


class ElasticMatchingError(ElasticServiceError):
    """Raised when there's an error matching alerts."""

    pass


class ElasticNoAlertsFoundError(ElasticServiceError):
    """Raised when no alerts are found for the search criteria."""

    pass


class ElasticNoMatchingAlertsError(ElasticServiceError):
    """Raised when alerts are found but none match the expectation."""

    pass


class ElasticDataConversionError(ElasticServiceError):
    """Raised when there's an error converting data."""

    pass


class ElasticAPIError(ElasticServiceError):
    """Raised when there's an error with Elastic Security API operations."""

    pass


class ElasticNetworkError(ElasticServiceError):
    """Raised when there's a network connectivity error."""

    pass


class ElasticSessionError(ElasticServiceError):
    """Raised when there's an error with session management."""

    pass


class ElasticQueryError(ElasticServiceError):
    """Raised when there's an error with query operations."""

    pass


class ElasticValidationError(ElasticServiceError):
    """Raised when input validation fails."""

    pass


class ElasticTimeoutError(ElasticServiceError):
    """Raised when operations timeout."""

    pass


class ElasticAuthenticationError(ElasticServiceError):
    """Raised when authentication fails."""

    pass
