"""Detection seam: the contract between the public detection helper and the core.

Closed: it imports nothing from ``collectors_sdk._core`` nor
``collectors_sdk.public``. Any change to these contracts must bump
:data:`SEAM_VERSION`.
"""

from collectors_sdk.seam.detection.ports import AlertMatchingPort

#: Version of the detection seam. Bump on any contract change.
SEAM_VERSION = "1.0.0"

__all__ = ["SEAM_VERSION", "AlertMatchingPort"]
