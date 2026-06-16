"""IBM QRadar Services Module.

This module provides all the service components for IBM QRadar integration
following the SentinelOne pattern with KISS principles.
"""

from .client_api import QRadarClientAPI
from .converter import Converter
from .exception import (
    QRadarAPIError,
    QRadarAuthenticationError,
    QRadarConfigurationError,
    QRadarDataConversionError,
    QRadarExpectationError,
    QRadarFetchError,
    QRadarMatchingError,
    QRadarNetworkError,
    QRadarNoAlertsFoundError,
    QRadarNoMatchingAlertsError,
    QRadarQueryError,
    QRadarServiceError,
    QRadarSessionError,
    QRadarTimeoutError,
    QRadarValidationError,
)
from .expectation_service import QRadarExpectationService
from .models import QRadarAlert, QRadarResponse, QRadarSearchCriteria
from .trace_service import QRadarTraceService

__all__ = [
    # Main services
    "QRadarClientAPI",
    "QRadarExpectationService",
    "QRadarTraceService",
    "Converter",
    # Models
    "QRadarAlert",
    "QRadarResponse",
    "QRadarSearchCriteria",
    # Exceptions
    "QRadarServiceError",
    "QRadarConfigurationError",
    "QRadarExpectationError",
    "QRadarFetchError",
    "QRadarMatchingError",
    "QRadarNoAlertsFoundError",
    "QRadarNoMatchingAlertsError",
    "QRadarDataConversionError",
    "QRadarAPIError",
    "QRadarNetworkError",
    "QRadarSessionError",
    "QRadarQueryError",
    "QRadarValidationError",
    "QRadarTimeoutError",
    "QRadarAuthenticationError",
]
