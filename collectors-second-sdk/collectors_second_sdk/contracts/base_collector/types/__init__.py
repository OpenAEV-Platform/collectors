"""Type alias contracts for the base_collector feature."""

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

__all__ = [
    "BulkData",
    "BulkUploadFunction",
    "CustomConfig",
    "ExpectationsList",
    "IndividualUploadFunction",
    "PrepareBulkFunction",
    "SignatureGroups",
    "UnpackBulkFunction",
]
