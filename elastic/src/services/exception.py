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


class ElasticUngradableError(ElasticServiceError):
    """Raised when an expectation cannot be graded either way.

    Used when the expectation carries no usable signature (e.g. only unknown /
    non-canonical signature types after normalization): the collector can assert
    neither Detected nor Not Detected, so the expectation is left pending
    (omitted from the results) and re-served next cycle, rather than recorded as
    a false 'Not Detected'.
    """

    pass


# Error classes that mean "could not query/decide this cycle" (transient outage
# or ungradable), for which the expectation must be LEFT PENDING (omitted from
# results) instead of graded 'Not Detected'. Kept explicit so the batch loop can
# distinguish them from a genuine "queried successfully, nothing matched".
LEAVE_PENDING_ERRORS = (
    ElasticAPIError,
    ElasticNetworkError,
    ElasticAuthenticationError,
    ElasticTimeoutError,
    ElasticUngradableError,
)
