"""LogRhythm Services Module.

This module provides all the service components for LogRhythm integration
following the SentinelOne pattern with KISS principles.
"""

from .client_api import LogRhythmClientAPI
from .converter import Converter
from .exception import (
    LogRhythmAPIError,
    LogRhythmAuthenticationError,
    LogRhythmConfigurationError,
    LogRhythmDataConversionError,
    LogRhythmExpectationError,
    LogRhythmFetchError,
    LogRhythmMatchingError,
    LogRhythmNetworkError,
    LogRhythmNoAlertsFoundError,
    LogRhythmNoMatchingAlertsError,
    LogRhythmQueryError,
    LogRhythmServiceError,
    LogRhythmSessionError,
    LogRhythmTimeoutError,
    LogRhythmValidationError,
)
from .expectation_service import LogRhythmExpectationService
from .models import LogRhythmAlert, LogRhythmResponse, LogRhythmSearchCriteria
from .trace_service import LogRhythmTraceService

__all__ = [
    # Main services
    "LogRhythmClientAPI",
    "LogRhythmExpectationService",
    "LogRhythmTraceService",
    "Converter",
    # Models
    "LogRhythmAlert",
    "LogRhythmResponse",
    "LogRhythmSearchCriteria",
    # Exceptions
    "LogRhythmServiceError",
    "LogRhythmConfigurationError",
    "LogRhythmExpectationError",
    "LogRhythmFetchError",
    "LogRhythmMatchingError",
    "LogRhythmNoAlertsFoundError",
    "LogRhythmNoMatchingAlertsError",
    "LogRhythmDataConversionError",
    "LogRhythmAPIError",
    "LogRhythmNetworkError",
    "LogRhythmSessionError",
    "LogRhythmQueryError",
    "LogRhythmValidationError",
    "LogRhythmTimeoutError",
    "LogRhythmAuthenticationError",
]
