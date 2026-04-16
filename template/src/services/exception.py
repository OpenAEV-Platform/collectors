"""Template Service Exceptions."""


class TemplateServiceError(Exception):
    """Base exception for all Template service errors."""

    pass


class TemplateExpectationError(TemplateServiceError):
    """Raised when there's an error processing expectations."""

    pass


class TemplateDataConversionError(TemplateServiceError):
    """Raised when there's an error converting data."""

    pass


class TemplateFetcherError(TemplateServiceError):
    """Raised when there's an error with Template fetcher operations."""

    pass


class TemplateValidationError(TemplateServiceError):
    """Raised when input validation fails."""

    pass
