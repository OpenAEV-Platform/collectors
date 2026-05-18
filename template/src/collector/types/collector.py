from typing import Sequence, TypeAlias

from pyoaev.apis.inject_expectation.model import (
    DetectionExpectation,
    PreventionExpectation,
)
from src.models.settings.custom_configs import _ConfigLoaderCustom

CustomConfig: TypeAlias = _ConfigLoaderCustom
ExpectationsList: TypeAlias = Sequence[DetectionExpectation | PreventionExpectation]
SignatureGroups: TypeAlias = dict[str, list[dict[str, str]]]
