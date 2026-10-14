"""Expectation data contracts: expectation types, signatures and data."""

from enum import Enum
from typing import Any, List
from uuid import UUID

from pydantic import BaseModel, Field, field_validator
from xtm_oaev_sdk import SignatureTypes

__all__ = ["ExpectationData", "ExpectationSignature", "ExpectationTypeEnum"]


class ExpectationTypeEnum(str, Enum):
    """Types of Expectations"""

    Detection = "DETECTION"
    Prevention = "PREVENTION"
    Vulnerability = "VULNERABILITY"
    Other = "other"

    @classmethod
    def _missing_(cls, value):
        return cls.Other


class ExpectationSignature(BaseModel):
    """An expectation signature describes a known marker potentially
    found in alerting data in security software. For example, an
    expectation signature can be a process image name, a command
    line, or any other relevant piece of data.
    """

    type: SignatureTypes
    value: str


class ExpectationData(BaseModel):
    """Data of an expectation: an expected outcome of a BAS run.
    For example, in the case of running an attack command line, the
    expectation may be that security software has _detected_ it, while
    another expectation may be that the attack was _prevented_.
    """

    inject_expectation_id: UUID
    inject_expectation_signatures: List[ExpectationSignature] = Field(
        default_factory=list
    )

    success_label: str = "Success"
    failure_label: str = "Failure"

    @field_validator("inject_expectation_signatures", mode="before")
    @classmethod
    def _coerce_none_signatures_to_empty(cls, value: Any) -> Any:
        # The platform serializes this field as null when an expectation has no
        # signatures yet. Without this, a single such expectation raises a
        # ValidationError that aborts the whole batch fetch (collectors#490).
        return [] if value is None else value
