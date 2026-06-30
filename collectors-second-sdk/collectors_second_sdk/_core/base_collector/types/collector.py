"""Type aliases for the collector domain."""

from typing import Sequence, TypeAlias

CustomConfig: TypeAlias = any
ExpectationsList: TypeAlias = Sequence[any]
SignatureGroups: TypeAlias = dict[str, list[dict[str, str]]]
