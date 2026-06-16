"""NetWitness Service Exceptions.

Custom exceptions for NetWitness service operations.
"""


class NetWitnessServiceError(Exception):
    """Base exception for all NetWitness service errors."""

    pass


class NetWitnessConfigurationError(NetWitnessServiceError):
    """Raised when there's a configuration error."""

    pass


class NetWitnessExpectationError(NetWitnessServiceError):
    """Raised when there's an error processing expectations."""

    pass


class NetWitnessFetchError(NetWitnessServiceError):
    """Raised when there's an error fetching data from NetWitness API."""

    pass


class NetWitnessMatchingError(NetWitnessServiceError):
    """Raised when there's an error matching alerts."""

    pass


class NetWitnessNoAlertsFoundError(NetWitnessServiceError):
    """Raised when no alerts are found for the search criteria."""

    pass


class NetWitnessNoMatchingAlertsError(NetWitnessServiceError):
    """Raised when alerts are found but none match the expectation."""

    pass


class NetWitnessDataConversionError(NetWitnessServiceError):
    """Raised when there's an error converting data."""

    pass


class NetWitnessAPIError(NetWitnessServiceError):
    """Raised when there's an error with NetWitness API operations."""

    pass


class NetWitnessNetworkError(NetWitnessServiceError):
    """Raised when there's a network connectivity error."""

    pass


class NetWitnessSessionError(NetWitnessServiceError):
    """Raised when there's an error with session management."""

    pass


class NetWitnessQueryError(NetWitnessServiceError):
    """Raised when there's an error with query operations."""

    pass


class NetWitnessValidationError(NetWitnessServiceError):
    """Raised when input validation fails."""

    pass


class NetWitnessTimeoutError(NetWitnessServiceError):
    """Raised when operations timeout."""

    pass


class NetWitnessAuthenticationError(NetWitnessServiceError):
    """Raised when authentication fails."""

    pass
