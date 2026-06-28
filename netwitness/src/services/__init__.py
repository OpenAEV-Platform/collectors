"""NetWitness Services Module.

This module provides all the service components for NetWitness integration
following the SentinelOne pattern with KISS principles.
"""

from .client_api import NetWitnessClientAPI
from .converter import Converter
from .exception import (
    NetWitnessAPIError,
    NetWitnessAuthenticationError,
    NetWitnessConfigurationError,
    NetWitnessDataConversionError,
    NetWitnessExpectationError,
    NetWitnessFetchError,
    NetWitnessMatchingError,
    NetWitnessNetworkError,
    NetWitnessNoAlertsFoundError,
    NetWitnessNoMatchingAlertsError,
    NetWitnessQueryError,
    NetWitnessServiceError,
    NetWitnessSessionError,
    NetWitnessTimeoutError,
    NetWitnessValidationError,
)
from .expectation_service import NetWitnessExpectationService
from .models import NetWitnessAlert, NetWitnessResponse, NetWitnessSearchCriteria
from .trace_service import NetWitnessTraceService

__all__ = [
    # Main services
    "NetWitnessClientAPI",
    "NetWitnessExpectationService",
    "NetWitnessTraceService",
    "Converter",
    # Models
    "NetWitnessAlert",
    "NetWitnessResponse",
    "NetWitnessSearchCriteria",
    # Exceptions
    "NetWitnessServiceError",
    "NetWitnessConfigurationError",
    "NetWitnessExpectationError",
    "NetWitnessFetchError",
    "NetWitnessMatchingError",
    "NetWitnessNoAlertsFoundError",
    "NetWitnessNoMatchingAlertsError",
    "NetWitnessDataConversionError",
    "NetWitnessAPIError",
    "NetWitnessNetworkError",
    "NetWitnessSessionError",
    "NetWitnessQueryError",
    "NetWitnessValidationError",
    "NetWitnessTimeoutError",
    "NetWitnessAuthenticationError",
]
