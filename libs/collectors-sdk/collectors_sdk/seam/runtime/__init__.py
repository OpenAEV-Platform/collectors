"""Collector runtime seam: the contract between the public runtime and the core.

Closed: it imports nothing from ``collectors_sdk._core`` nor ``collectors_sdk.public``.
Any change to these contracts must bump :data:`SEAM_VERSION`.
"""

from collectors_sdk.seam.runtime.models import CollectorDevOptions
from collectors_sdk.seam.runtime.ports import CollectorDevRuntimePort

#: Version of the collector runtime seam. Bump on any contract change.
SEAM_VERSION = "1.0.0"

__all__ = ["SEAM_VERSION", "CollectorDevOptions", "CollectorDevRuntimePort"]
