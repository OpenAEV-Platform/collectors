"""Splunk ES Services Module.

This module provides all the service components for Splunk ES integration
following the SentinelOne pattern with KISS principles.
"""

from .client_api import SplunkESClientAPI
from .converter import Converter
from .exception import (
    SplunkESAPIError,
    SplunkESAuthenticationError,
    SplunkESConfigurationError,
    SplunkESDataConversionError,
    SplunkESExpectationError,
    SplunkESFetchError,
    SplunkESMatchingError,
    SplunkESNetworkError,
    SplunkESNoAlertsFoundError,
    SplunkESNoMatchingAlertsError,
    SplunkESQueryError,
    SplunkESServiceError,
    SplunkESSessionError,
    SplunkESTimeoutError,
    SplunkESValidationError,
)
from .expectation_service import SplunkESExpectationService
from .models import SplunkESAlert, SplunkESResponse, SplunkESSearchCriteria
from .trace_service import SplunkESTraceService

__all__ = [
    # Main services
    "SplunkESClientAPI",
    "SplunkESExpectationService",
    "SplunkESTraceService",
    "Converter",
    # Models
    "SplunkESAlert",
    "SplunkESResponse",
    "SplunkESSearchCriteria",
    # Exceptions
    "SplunkESServiceError",
    "SplunkESConfigurationError",
    "SplunkESExpectationError",
    "SplunkESFetchError",
    "SplunkESMatchingError",
    "SplunkESNoAlertsFoundError",
    "SplunkESNoMatchingAlertsError",
    "SplunkESDataConversionError",
    "SplunkESAPIError",
    "SplunkESNetworkError",
    "SplunkESSessionError",
    "SplunkESQueryError",
    "SplunkESValidationError",
    "SplunkESTimeoutError",
    "SplunkESAuthenticationError",
]
