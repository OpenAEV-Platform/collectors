"""Expectations seam: the contract between the public expectations and the core.

Closed: it imports nothing from ``collectors_sdk._core`` nor
``collectors_sdk.public``. Any change to these contracts must bump
:data:`SEAM_VERSION`.
"""

from collectors_sdk.seam.expectations.models import (
    ExpectationData,
    ExpectationSignature,
    ExpectationTypeEnum,
)
from collectors_sdk.seam.expectations.ports import (
    ExpectationApiProtocol,
    ExpectationLoadingPort,
    ExpectationMatchingPort,
    ExpectationUpdatePort,
)

#: Version of the expectations seam. Bump on any contract change.
SEAM_VERSION = "1.0.0"

__all__ = [
    "SEAM_VERSION",
    "ExpectationData",
    "ExpectationSignature",
    "ExpectationTypeEnum",
    "ExpectationApiProtocol",
    "ExpectationLoadingPort",
    "ExpectationMatchingPort",
    "ExpectationUpdatePort",
]
