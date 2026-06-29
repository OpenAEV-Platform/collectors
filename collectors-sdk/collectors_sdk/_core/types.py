"""Type aliases for the collectors SDK."""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping, Sequence, TypeAlias

from collectors_sdk._core.config.settings import ConfigLoaderCustom

BulkData: TypeAlias = Mapping[str, Any] | Sequence[Any]
PrepareBulkFunction: TypeAlias = Callable[[list[Any]], tuple[BulkData, int]]
BulkUploadFunction: TypeAlias = Callable[[BulkData], None]
UnpackBulkFunction: TypeAlias = Callable[[BulkData], Iterable[tuple[Any, Any]]]
IndividualUploadFunction: TypeAlias = Callable[[Any, Any], None]

CustomConfig: TypeAlias = ConfigLoaderCustom
ExpectationsList: TypeAlias = Sequence[Any]
SignatureGroups: TypeAlias = dict[str, list[dict[str, str]]]

__all__ = [
    "BulkData",
    "PrepareBulkFunction",
    "BulkUploadFunction",
    "UnpackBulkFunction",
    "IndividualUploadFunction",
    "CustomConfig",
    "ExpectationsList",
    "SignatureGroups",
]
