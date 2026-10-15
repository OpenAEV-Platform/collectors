"""collectors-sdk — OpenAEV Collectors SDK (DDD + Light Hex Architecture).

Built on the shared ``xtm-oaev-sdk``; never depends on the pyoaev client.

Architecture:
    _core/daemons/        Collector registration and schedule
    _core/detection/      Alert-element matching
    _core/expectations/   Expectation matching and updates
    seam/daemons/         Collector defaults and ports (closed, versioned)
    seam/detection/       Alert-matching port (closed, versioned)
    seam/expectations/    Expectation contracts and ports (closed, versioned)
    public/daemons        CollectorDaemon adapter
    public/detection      OpenAEVDetectionHelper adapter
    public/expectations   Expectation adapters
    public/               User-facing re-exports

Port/adapter layering: ``seam`` holds the contracts and imports nothing from
``_core`` nor ``public``; ``_core`` implements the seam ports and never imports
``public``; ``public`` exposes adapters that speak seam types and delegate to
``_core``, plus the seam contracts themselves — never a core object.

The OpenAEV API client is injected (``api_client=``), conforming to
``xtm_oaev_sdk.BaseClient``.
"""

__version__ = "0.1.0"

from collectors_sdk.public import *  # noqa: F401, F403
from collectors_sdk.public import __all__ as _public_all

__all__ = list(_public_all)
