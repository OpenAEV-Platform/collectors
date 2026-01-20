"""PaloAltoCortexXDR Service Exceptions."""


class PaloAltoCortexXDRServiceError(Exception):
    """Base exception for all PaloAltoCortexXDR service errors."""

    pass


class PaloAltoCortexXDRExpectationError(PaloAltoCortexXDRServiceError):
    """Raised when there's an error processing expectations."""

    pass


class PaloAltoCortexXDRDataConversionError(PaloAltoCortexXDRServiceError):
    """Raised when there's an error converting data."""

    pass


class PaloAltoCortexXDRAPIError(PaloAltoCortexXDRServiceError):
    """Raised when there's an error with PaloAltoCortexXDR API operations."""

    pass


class PaloAltoCortexXDRNetworkError(PaloAltoCortexXDRServiceError):
    """Raised when there's a network connectivity error."""

    pass


class PaloAltoCortexXDRSessionError(PaloAltoCortexXDRServiceError):
    """Raised when there's an error with session management."""

    pass


class PaloAltoCortexXDRValidationError(PaloAltoCortexXDRServiceError):
    """Raised when input validation fails."""

    pass
