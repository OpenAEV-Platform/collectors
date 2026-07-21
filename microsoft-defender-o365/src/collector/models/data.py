from datetime import UTC, datetime
from typing import Any, ClassVar

from pydantic import AnyUrl, BaseModel, Field, model_validator
from pyoaev.signatures.types import SignatureTypes  # type: ignore[import-untyped]


class OAEVData(BaseModel, extra="allow"):
    """
    Source-side version of OAEV formatted data.
    Apart from context, the allowed fields are signature types (e.g. parent_process_name)
    """

    __pydantic_extra__: dict[str, str] = Field(default_factory=dict)
    _allowed_values: ClassVar[frozenset[str]] = frozenset(
        [sig.value for sig in SignatureTypes]
    )

    @model_validator(mode="before")
    @classmethod
    def check_field_names(cls, data: Any) -> Any:
        """Check whether the fields provided through extra are actually signature types"""
        if isinstance(data, dict):
            for key in data:
                if key not in cls._allowed_values:
                    raise ValueError("Only signature types are allowed")
        return data

    def __str__(self) -> str:
        """str formatted version of the object"""
        text = ", ".join(
            f"{key}='{value}'"
            for key, value in self.model_dump().items()
            if key in self._allowed_values
        )
        text = f"OAEVData({text})"
        return text


class TraceData(BaseModel):
    """Source-side version of OAEV formatted data"""

    alert_name: str = Field(..., description="Alert name")
    alert_link: AnyUrl = Field(..., description="Alert link")
    alert_date: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Alert date"
    )

    def __str__(self) -> str:
        """str formatted version of the object"""
        return (
            f"TraceData(alert_name='{self.alert_name}', alert_link='{self.alert_link}', "
            f"alert_date='{self.alert_date}')"
        )
