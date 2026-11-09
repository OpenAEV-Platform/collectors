"""Public API surface for collectors-sdk."""

__version__ = "0.1.0"

# --- Daemons ---
from collectors_sdk.public.daemons import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
    CollectorDaemon,
)

# --- Detection ---
from collectors_sdk.public.detection import OpenAEVDetectionHelper

# --- Expectations ---
from collectors_sdk.public.expectations import (
    DetectionExpectation,
    Expectation,
    ExpectationApiProtocol,
    ExpectationSignature,
    ExpectationTypeEnum,
    PreventionExpectation,
    expectations_models_for_source,
)

# --- Runtime ---
from collectors_sdk.public.runtime import (
    CollectorDevOptions,
    collector_dev_help,
    collector_dev_options,
)

__all__ = [
    "__version__",
    # Daemons
    "CollectorDaemon",
    "DEFAULT_PERIOD_SECONDS",
    "DEFAULT_PLATFORM_TAG_COLOR",
    # Expectations
    "DetectionExpectation",
    "Expectation",
    "ExpectationApiProtocol",
    "ExpectationSignature",
    "ExpectationTypeEnum",
    "PreventionExpectation",
    "expectations_models_for_source",
    # Detection
    "OpenAEVDetectionHelper",
    # Runtime
    "CollectorDevOptions",
    "collector_dev_help",
    "collector_dev_options",
]
