"""PaloAltoCortexXSOAR Service Exceptions."""


class PaloAltoCortexXSOARServiceError(Exception):
    """Base exception for all PaloAltoCortexXSOAR service errors."""

    pass


class PaloAltoCortexXSOARExpectationError(PaloAltoCortexXSOARServiceError):
    """Raised when there's an error processing expectations."""

    pass


class PaloAltoCortexXSOARDataConversionError(PaloAltoCortexXSOARServiceError):
    """Raised when there's an error converting data."""

    pass


class PaloAltoCortexXSOARAPIError(PaloAltoCortexXSOARServiceError):
    """Raised when there's an error with PaloAltoCortexXSOAR API operations."""

    pass


class PaloAltoCortexXSOARNetworkError(PaloAltoCortexXSOARServiceError):
    """Raised when there's a network connectivity error."""

    pass


class PaloAltoCortexXSOARValidationError(PaloAltoCortexXSOARServiceError):
    """Raised when input validation fails."""

    pass
