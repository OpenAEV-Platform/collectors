"""collectors-sdk — Collector SDK (DDD + Light Hex Architecture).

Architecture mirrors collectors_template/template/src/collector/:
    _core/base_collector/   engines/, internals/, models/, protocols/, types/, utils/
    _core/config/           ConfigBaseSettings
    contracts/              Stable interfaces (protocols, models, types)
    public/                 User-facing re-exports (43 symbols)
"""

__version__ = "0.1.0"

from collectors_sdk.public import *  # noqa: F401, F403
from collectors_sdk.public import __all__ as _public_all

__all__ = list(_public_all)
