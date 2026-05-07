from typing import Any, Callable, Iterable, Mapping, TypeAlias

PrepareBulkFunction: TypeAlias = Callable[[list[Any]], tuple[Iterable[Any], int]]
BulkUploadFunction: TypeAlias = Callable[[Iterable[Any]], None]
UnpackBulkFunction: TypeAlias = Callable[[Iterable[Any] | Mapping[str, Any]], Iterable[tuple[Any, Any]]]
IndividualUploadFunction: TypeAlias = Callable[[Any, Any], None]
