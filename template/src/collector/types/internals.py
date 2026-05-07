from typing import Any, Callable, Iterable, TypeAlias

PrepareBulkFunction: TypeAlias = Callable[[list[Any]], tuple[Iterable[Any], int]]
BulkUploadFunction: TypeAlias = Callable[[Iterable[Any]], None]
UnpackBulkFunction: TypeAlias = Callable[[Iterable[Any]], Iterable[tuple[Any, Any]]]
IndividualUploadFunction: TypeAlias = Callable[[Any, Any], None]
