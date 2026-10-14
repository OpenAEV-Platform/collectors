"""Public API surface for collectors-sdk."""

__version__ = "0.1.0"

# --- Daemons ---
from collectors_sdk.seam.daemons import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
    CollectorDaemon,
)

# --- Detection ---
from collectors_sdk.seam.detection import OpenAEVDetectionHelper

__all__ = [
    "__version__",
    # Daemons
    "CollectorDaemon",
    "DEFAULT_PERIOD_SECONDS",
    "DEFAULT_PLATFORM_TAG_COLOR",
    # Detection
    "OpenAEVDetectionHelper",
]
