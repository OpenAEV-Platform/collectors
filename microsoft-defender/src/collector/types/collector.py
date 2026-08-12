from typing import Sequence, TypeAlias

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from src.models.settings.source_configs import _ConfigLoaderSource

SourceConfig: TypeAlias = _ConfigLoaderSource
ExpectationsList: TypeAlias = Sequence[DetectionExpectation | PreventionExpectation]
SignatureGroups: TypeAlias = dict[str, list[dict[str, str]]]
