"""Collector daemon seam: the contract between the public daemon and the core.

Closed: it imports nothing from ``collectors_sdk._core`` nor
``collectors_sdk.public``. Any change to these contracts must bump
:data:`SEAM_VERSION`.
"""

from collectors_sdk.seam.daemons.models import (
    DEFAULT_PERIOD_SECONDS,
    DEFAULT_PLATFORM_TAG_COLOR,
)
from collectors_sdk.seam.daemons.ports import (
    CollectorRegistrationPort,
    CollectorSchedulePort,
)

#: Version of the collector daemon seam. Bump on any contract change.
SEAM_VERSION = "1.0.0"

__all__ = [
    "SEAM_VERSION",
    "DEFAULT_PERIOD_SECONDS",
    "DEFAULT_PLATFORM_TAG_COLOR",
    "CollectorRegistrationPort",
    "CollectorSchedulePort",
]
