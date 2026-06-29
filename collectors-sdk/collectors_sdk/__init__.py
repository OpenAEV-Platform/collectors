"""OpenAEV Collectors SDK — Base collector, engine, and extension framework."""

__version__ = "0.1.0"

# --- Errors ---
# --- Base ---
# --- Daemon protocol (re-exported from xtm-oaev-sdk) ---
from xtm_oaev_sdk import DaemonProtocol

from collectors_sdk._core.base import BaseCollector

# --- Config ---
from collectors_sdk._core.config.settings import (
    ConfigBaseSettings,
    ConfigLoaderCollector,
    ConfigLoaderCustom,
    ConfigLoaderOAEV,
)

# --- Engine ---
from collectors_sdk._core.engine.engine import BasicCollectorEngine
from collectors_sdk._core.errors import (
    APIError,
    BulkPreparationError,
    BulkUploadError,
    CollectorConfigError,
    CollectorEngineConfigError,
    CollectorError,
    CollectorProcessingError,
    CollectorSetupError,
    ExpectationHandlerError,
    ExpectationProcessingError,
    ExpectationUpdateError,
    TraceCreationError,
    TraceSubmissionError,
    TracingError,
)

# --- Data models ---
from collectors_sdk._core.models.data import OAEVData, TraceData
from collectors_sdk._core.models.expectations import (
    ExpectationResult,
    ExpectationSummary,
    ExpectationTrace,
)
from collectors_sdk._core.models.source import Source, SourceHandler

# --- Protocols ---
from collectors_sdk._core.protocols import (
    CollectorEngineProtocol,
    DataFetcherProtocol,
    SourceDataProtocol,
    SourceHandlerProtocol,
)

# --- Type aliases ---
from collectors_sdk._core.types import (
    BulkData,
    BulkUploadFunction,
    CustomConfig,
    ExpectationsList,
    IndividualUploadFunction,
    PrepareBulkFunction,
    SignatureGroups,
    UnpackBulkFunction,
)

# --- Detection ---
from collectors_sdk._core.detection import (
    SignatureMatcher,
    _decode_value,
    _is_base64_encoded,
)

__all__ = [
    # Errors (14)
    "CollectorError",
    "CollectorConfigError",
    "CollectorEngineConfigError",
    "CollectorSetupError",
    "CollectorProcessingError",
    "ExpectationHandlerError",
    "ExpectationProcessingError",
    "ExpectationUpdateError",
    "BulkUploadError",
    "BulkPreparationError",
    "APIError",
    "TracingError",
    "TraceSubmissionError",
    "TraceCreationError",
    # Protocols (4)
    "CollectorEngineProtocol",
    "DataFetcherProtocol",
    "SourceDataProtocol",
    "SourceHandlerProtocol",
    # Data models (7)
    "OAEVData",
    "TraceData",
    "Source",
    "SourceHandler",
    "ExpectationResult",
    "ExpectationTrace",
    "ExpectationSummary",
    # Config (4)
    "ConfigBaseSettings",
    "ConfigLoaderOAEV",
    "ConfigLoaderCollector",
    "ConfigLoaderCustom",
    # Type aliases (8)
    "CustomConfig",
    "ExpectationsList",
    "SignatureGroups",
    "BulkData",
    "PrepareBulkFunction",
    "BulkUploadFunction",
    "UnpackBulkFunction",
    "IndividualUploadFunction",
    # Engine (1)
    "BasicCollectorEngine",
    # Base (1)
    "BaseCollector",
    # Daemon protocol (1, re-exported from xtm-oaev-sdk)
    "DaemonProtocol",
    # Detection (3)
    "SignatureMatcher",
    "_decode_value",
    "_is_base64_encoded",
]
