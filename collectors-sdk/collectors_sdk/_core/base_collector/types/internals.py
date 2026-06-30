"""Type aliases for internal upload machinery."""

from typing import Any, Callable, Iterable, Mapping, Sequence, TypeAlias

BulkData: TypeAlias = Mapping[str, Any] | Sequence[Any]
PrepareBulkFunction: TypeAlias = Callable[[list[Any]], tuple[BulkData, int]]
BulkUploadFunction: TypeAlias = Callable[[BulkData], None]
UnpackBulkFunction: TypeAlias = Callable[[BulkData], Iterable[tuple[Any, Any]]]
IndividualUploadFunction: TypeAlias = Callable[[Any, Any], None]
