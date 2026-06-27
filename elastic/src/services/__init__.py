"""Elastic Security Services Module.

This module provides all the service components for Elastic Security integration
following the SentinelOne pattern with KISS principles.
"""

from .client_api import ElasticClientAPI
from .converter import Converter
from .exception import (
    ElasticAPIError,
    ElasticAuthenticationError,
    ElasticConfigurationError,
    ElasticDataConversionError,
    ElasticExpectationError,
    ElasticFetchError,
    ElasticMatchingError,
    ElasticNetworkError,
    ElasticNoAlertsFoundError,
    ElasticNoMatchingAlertsError,
    ElasticQueryError,
    ElasticServiceError,
    ElasticSessionError,
    ElasticTimeoutError,
    ElasticValidationError,
)
from .expectation_service import ElasticExpectationService
from .models import ElasticAlert, ElasticResponse, ElasticSearchCriteria
from .trace_service import ElasticTraceService

__all__ = [
    # Main services
    "ElasticClientAPI",
    "ElasticExpectationService",
    "ElasticTraceService",
    "Converter",
    # Models
    "ElasticAlert",
    "ElasticResponse",
    "ElasticSearchCriteria",
    # Exceptions
    "ElasticServiceError",
    "ElasticConfigurationError",
    "ElasticExpectationError",
    "ElasticFetchError",
    "ElasticMatchingError",
    "ElasticNoAlertsFoundError",
    "ElasticNoMatchingAlertsError",
    "ElasticDataConversionError",
    "ElasticAPIError",
    "ElasticNetworkError",
    "ElasticSessionError",
    "ElasticQueryError",
    "ElasticValidationError",
    "ElasticTimeoutError",
    "ElasticAuthenticationError",
]
