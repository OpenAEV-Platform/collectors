"""collectors-sdk — OpenAEV Collectors SDK (DDD + Light Hex Architecture).

Built on the shared ``xtm-oaev-sdk``; never depends on the pyoaev client.

Architecture:
    _core/daemons/     Collector daemon implementation
    _core/detection/   Alert-element detection implementation
    seam/              Stable boundary between public/ and _core/
    public/            User-facing re-exports

The OpenAEV API client is injected (``api_client=``), conforming to
``xtm_oaev_sdk.BaseClient``.
"""

__version__ = "0.1.0"

from collectors_sdk.public import *  # noqa: F401, F403
from collectors_sdk.public import __all__ as _public_all

__all__ = list(_public_all)
