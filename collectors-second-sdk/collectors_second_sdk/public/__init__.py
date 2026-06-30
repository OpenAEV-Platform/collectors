"""Public API surface for collectors-second-sdk.

All 43 symbols re-exported here. Users import from:
    from collectors_second_sdk import BaseCollector, BasicCollectorEngine
    from collectors_second_sdk.public import BaseCollector, BasicCollectorEngine
"""

# --- Config ---
from collectors_second_sdk._core.config.settings import (
    ConfigBaseSettings,
    ConfigLoaderCollector,
    ConfigLoaderCustom,
    ConfigLoaderOAEV,
)

# --- Protocols ---
from collectors_second_sdk._core.base_collector.protocols.data_fetcher import DataFetcherProtocol
from collectors_second_sdk._core.base_collector.protocols.engine import CollectorEngineProtocol
from collectors_second_sdk._core.base_collector.protocols.source_data import SourceDataProtocol
from collectors_second_sdk._core.base_collector.protocols.source_handler import SourceHandlerProtocol

# --- DaemonProtocol (from xtm-oaev-sdk) ---
from xtm_oaev_sdk import DaemonProtocol

# --- Models ---
from collectors_second_sdk._core.base_collector.models.data import OAEVData, TraceData
from collectors_second_sdk._core.base_collector.models.expectations import (
    ExpectationResult,
    ExpectationSummary,
    ExpectationTrace,
)
from collectors_second_sdk._core.base_collector.models.source import Source, SourceHandler

# --- Errors ---
from collectors_second_sdk._core.base_collector.models.exception import (
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

# --- Type aliases ---
from collectors_second_sdk._core.base_collector.types.collector import (
    CustomConfig,
    ExpectationsList,
    SignatureGroups,
)
from collectors_second_sdk._core.base_collector.types.internals import (
    BulkData,
    BulkUploadFunction,
    IndividualUploadFunction,
    PrepareBulkFunction,
    UnpackBulkFunction,
)

# --- Collector + Engine ---
from collectors_second_sdk._core.base_collector.collector import BaseCollector
from collectors_second_sdk._core.base_collector.engines.basic import BasicCollectorEngine

# --- Detection utils ---
from collectors_second_sdk._core.base_collector.utils.detection import (
    SignatureMatcher,
    _decode_value,
    _is_base64_encoded,
)


__all__ = [
    # Config
    "ConfigBaseSettings",
    "ConfigLoaderCollector",
    "ConfigLoaderCustom",
    "ConfigLoaderOAEV",
    # Protocols
    "CollectorEngineProtocol",
    "DaemonProtocol",
    "DataFetcherProtocol",
    "SourceDataProtocol",
    "SourceHandlerProtocol",
    # Models
    "ExpectationResult",
    "ExpectationSummary",
    "ExpectationTrace",
    "OAEVData",
    "Source",
    "SourceHandler",
    "TraceData",
    # Errors
    "APIError",
    "BulkPreparationError",
    "BulkUploadError",
    "CollectorConfigError",
    "CollectorEngineConfigError",
    "CollectorError",
    "CollectorProcessingError",
    "CollectorSetupError",
    "ExpectationHandlerError",
    "ExpectationProcessingError",
    "ExpectationUpdateError",
    "TraceCreationError",
    "TraceSubmissionError",
    "TracingError",
    # Type aliases
    "BulkData",
    "BulkUploadFunction",
    "CustomConfig",
    "ExpectationsList",
    "IndividualUploadFunction",
    "PrepareBulkFunction",
    "SignatureGroups",
    "UnpackBulkFunction",
    # Collector + Engine
    "BaseCollector",
    "BasicCollectorEngine",
    # Detection
    "SignatureMatcher",
    "_decode_value",
    "_is_base64_encoded",
]
